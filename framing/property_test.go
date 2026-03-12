package framing

import (
	"bytes"
	"testing"
	"testing/quick"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/secrettree"
)

// TestProperty_EncryptDecrypt_Identity verifies that Encrypt followed by Decrypt
// returns the exact original plaintext.
func TestProperty_EncryptDecrypt_Identity(t *testing.T) {
	// Skip if short mode, setup takes a bit
	if testing.Short() {
		t.Skip("skipping property tests in short mode")
	}

	cs := ciphersuite.MLS128DHKEMP256

	// Fixed setup
	secretTree, _ := secrettree.NewTree(ciphersuite.NewSecret(make([]byte, 32)), 2, cs)
	senderDataSecret := ciphersuite.NewSecret(make([]byte, 32))
	sigPriv, _ := ciphersuite.GenerateSignaturePrivateKey()
	groupID := make([]byte, 16)
	groupContext := make([]byte, 32)

	property := func(appData []byte) bool {
		// Limit to 10KB to avoid excessive test times
		if len(appData) > 10240 {
			appData = appData[:10240]
		}

		content := FramedContent{
			GroupID:           groupID,
			Epoch:             0,
			Sender:            Sender{Type: SenderTypeMember, LeafIndex: 0},
			AuthenticatedData: []byte{},
			Body:              ApplicationData{Data: appData},
		}

		pm, err := Encrypt(EncryptParams{
			Content:          content,
			SenderLeafIndex:  0,
			CipherSuite:      cs,
			PaddingSize:      0,
			SenderDataSecret: senderDataSecret,
			SecretTree:       secretTree,
			SigKey:           sigPriv,
			GroupContext:     groupContext,
		})
		if err != nil {
			return false
		}

		// Decrypt needs a fresh secret tree to read the first message
		decTree, _ := secrettree.NewTree(ciphersuite.NewSecret(make([]byte, 32)), 2, cs)

		openPub := ciphersuite.NewOpenMlsSignaturePublicKey(sigPriv.PublicKey().AsSlice(), ciphersuite.ECDSA_SECP256R1_SHA256)
		decrypted, err := Decrypt(pm, DecryptParams{
			CipherSuite:      cs,
			SenderDataSecret: senderDataSecret,
			SecretTree:       decTree,
			SigPubKey:        openPub,
			GroupContext:     groupContext,
		})
		if err != nil {
			return false
		}

		if appDataObj, ok := decrypted.Content.Body.(ApplicationData); ok {
			// Quick generates nil slices sometimes, standardize to empty
			if len(appData) == 0 && len(appDataObj.Data) == 0 {
				return true
			}
			return bytes.Equal(appDataObj.Data, appData)
		}
		return false
	}

	if err := quick.Check(property, &quick.Config{MaxCount: 50}); err != nil {
		t.Error(err)
	}
}
