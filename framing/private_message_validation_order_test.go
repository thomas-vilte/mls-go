package framing_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/secrettree"
)

// decryptionOrderTestEnv is a sender and a receiver that share the epoch secrets. The forger signs with its own
// key but holds the same secrets, so its messages pass AEAD and fail the signature check.
type decryptionOrderTestEnv struct {
	cs         ciphersuite.CipherSuite
	sdSecret   []byte
	gc         []byte
	legitTree  *secrettree.Tree
	forgerTree *secrettree.Tree
	recvTree   *secrettree.Tree
	legitPriv  *ciphersuite.SignaturePrivateKey
	forgerPriv *ciphersuite.SignaturePrivateKey
	decrypt    framing.DecryptParams
}

func newDecryptionOrderTestEnv(t *testing.T) *decryptionOrderTestEnv {
	t.Helper()
	cs := ciphersuite.MLS128DHKEMP256
	root := bytes.Repeat([]byte{0x42}, 32)
	sd := bytes.Repeat([]byte{0x99}, 32)
	gc := []byte("serialized-group-context")
	legitPriv, legitPub := makeSigKeyPair(t, cs)
	forgerPriv, _ := makeSigKeyPair(t, cs)
	newTree := func() *secrettree.Tree {
		t.Helper()
		tree, err := secrettree.NewTree(ciphersuite.NewSecret(root), 2, cs)
		if err != nil {
			t.Fatalf("secrettree.NewTree: %v", err)
		}
		return tree
	}
	env := &decryptionOrderTestEnv{
		cs:         cs,
		sdSecret:   sd,
		gc:         gc,
		legitTree:  newTree(),
		forgerTree: newTree(),
		recvTree:   newTree(),
		legitPriv:  legitPriv,
		forgerPriv: forgerPriv,
	}
	env.decrypt = framing.DecryptParams{
		CipherSuite:      cs,
		SenderDataSecret: ciphersuite.NewSecret(sd),
		SecretTree:       env.recvTree,
		SigPubKey:        legitPub,
		GroupContext:     gc,
	}
	return env
}

// seal encrypts data from leaf 0 with the given tree and signing key.
func (env *decryptionOrderTestEnv) seal(t *testing.T, tree *secrettree.Tree, sig *ciphersuite.SignaturePrivateKey, data string) *framing.PrivateMessage {
	t.Helper()
	pm, err := framing.Encrypt(framing.EncryptParams{
		Content: framing.FramedContent{
			GroupID:           []byte("test-group-id"),
			Epoch:             1,
			Sender:            framing.Sender{Type: framing.SenderTypeMember, LeafIndex: 0},
			AuthenticatedData: []byte("aad"),
			Body:              framing.ApplicationData{Data: []byte(data)},
		},
		SenderLeafIndex:  0,
		CipherSuite:      env.cs,
		SenderDataSecret: ciphersuite.NewSecret(env.sdSecret),
		SecretTree:       tree,
		SigKey:           sig,
		GroupContext:     env.gc,
	})
	if err != nil {
		t.Fatalf("Encrypt(%q): %v", data, err)
	}
	return pm
}

// TestDecryptRejectsInvalidSignatureWithoutConsumingGeneration checks that a
// message with valid AEAD and an invalid signature leaves the receiver's ratchet
// unchanged and does not prevent subsequent honest messages from decrypting.
func TestDecryptRejectsInvalidSignatureWithoutConsumingGeneration(t *testing.T) {
	t.Run("same_generation", func(t *testing.T) {
		env := newDecryptionOrderTestEnv(t)
		forged := env.seal(t, env.forgerTree, env.forgerPriv, "forged")
		honest := env.seal(t, env.legitTree, env.legitPriv, "honest")

		if _, err := framing.Decrypt(forged, env.decrypt); !errors.Is(err, framing.ErrVerificationFailed) {
			t.Fatalf("forged message: err = %v, want ErrVerificationFailed", err)
		}
		if gen := env.receiverLeaf(t).CurrentGeneration(); gen != 0 {
			t.Fatalf("forged message moved the ratchet to generation %d, want 0", gen)
		}
		if _, err := framing.Decrypt(honest, env.decrypt); err != nil {
			t.Fatalf("honest generation 0 refused after a forged message with the same generation: %v", err)
		}
	})

	// A forged message that names a later generation must not move the ratchet either, so the honest
	// messages before it still decrypt in order.
	t.Run("later_generation", func(t *testing.T) {
		env := newDecryptionOrderTestEnv(t)
		var forged *framing.PrivateMessage
		for range 6 {
			forged = env.seal(t, env.forgerTree, env.forgerPriv, "forged")
		}
		honest := make([]*framing.PrivateMessage, 0, 6)
		for range 6 {
			honest = append(honest, env.seal(t, env.legitTree, env.legitPriv, "honest"))
		}

		if _, err := framing.Decrypt(forged, env.decrypt); !errors.Is(err, framing.ErrVerificationFailed) {
			t.Fatalf("forged message at generation 5: err = %v, want ErrVerificationFailed", err)
		}
		if gen := env.receiverLeaf(t).CurrentGeneration(); gen != 0 {
			t.Fatalf("forged message at generation 5 moved the ratchet to %d, want 0", gen)
		}
		for i, pm := range honest {
			if _, err := framing.Decrypt(pm, env.decrypt); err != nil {
				t.Fatalf("honest message %d after a forged message at generation 5: %v", i, err)
			}
		}
	})
}

// receiverLeaf returns the receiver's secret ratchet for leaf 0.
func (env *decryptionOrderTestEnv) receiverLeaf(t *testing.T) *secrettree.LeafSecret {
	t.Helper()
	leaf, err := env.recvTree.LeafForIndex(0)
	if err != nil {
		t.Fatalf("LeafForIndex(0): %v", err)
	}
	return leaf
}
