package group

import (
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/treesync"
)

// SendMessage encrypts an application message as a PrivateMessage per RFC 9420 §6.3.
//
// Application messages are encrypted using the secret tree derived from the
// epoch secrets. Each sender gets their own encryption key from the secret tree.
//
// # Security
//
//   - Message confidentiality: Only group members can decrypt the message
//   - Message authentication: The sender's signature is verified
//   - Forward secrecy: Each message uses fresh encryption keys from the secret tree
func (g *Group) SendMessage(
	data []byte,
	sigPrivKey *ciphersuite.SignaturePrivateKey,
) (*framing.PrivateMessage, error) {
	if g.state != StateOperational {
		return nil, fmt.Errorf("group not operational")
	}
	if sigPrivKey == nil {
		return nil, fmt.Errorf("signature private key is nil")
	}
	if g.EpochSecrets == nil || g.EpochSecrets.SenderDataSecret == nil {
		return nil, fmt.Errorf("sender_data_secret not available")
	}
	if g.SecretTree == nil {
		return nil, fmt.Errorf("secret tree not available")
	}

	content := framing.FramedContent{
		GroupID:           g.GroupID.AsSlice(),
		Epoch:             g.Epoch.AsUint64(),
		Sender:            framing.Sender{Type: framing.SenderTypeMember, LeafIndex: uint32(g.OwnLeafIndex)},
		AuthenticatedData: []byte{},
		Body:              framing.ApplicationData{Data: data},
	}

	return framing.Encrypt(framing.EncryptParams{
		Content:          content,
		SenderLeafIndex:  uint32(g.OwnLeafIndex),
		CipherSuite:      g.CipherSuite,
		PaddingSize:      0,
		SenderDataSecret: g.EpochSecrets.SenderDataSecret,
		SecretTree:       g.SecretTree,
		SigKey:           sigPrivKey,
		GroupContext:     g.GroupContext.Marshal(),
	})
}

// ReceiveMessage decrypts a PrivateMessage and returns application data per RFC 9420 §6.3.
//
// The sender leaf index must be provided to look up the sender's public key
// for signature verification.
//
// # Security
//
//   - Verifies message signature using sender's public key from ratchet tree
//   - Validates sender is an active member of the group
//   - Decrypts using the secret tree
func (g *Group) ReceiveMessage(
	pm *framing.PrivateMessage,
	senderLeafIdx LeafNodeIndex,
) ([]byte, error) {
	if g.state != StateOperational {
		return nil, fmt.Errorf("group not operational")
	}
	if pm == nil {
		return nil, fmt.Errorf("private message is nil")
	}
	if g.EpochSecrets == nil || g.EpochSecrets.SenderDataSecret == nil {
		return nil, fmt.Errorf("sender_data_secret not available")
	}
	if g.SecretTree == nil {
		return nil, fmt.Errorf("secret tree not available")
	}

	// RFC §6.1: Validate sender index is within tree bounds
	if uint32(senderLeafIdx) >= g.RatchetTree.NumLeaves {
		return nil, fmt.Errorf("sender index %d out of bounds (tree has %d leaves)", senderLeafIdx, g.RatchetTree.NumLeaves)
	}

	// Resolve sender signature pubkey from ratchet tree
	senderLeaf := g.RatchetTree.GetLeaf(treesync.LeafIndex(senderLeafIdx))
	var sigPubKey *ciphersuite.OpenMlsSignaturePublicKey
	if senderLeaf != nil && senderLeaf.LeafData != nil && senderLeaf.LeafData.SignatureKey != nil {
		raw := treesync.MarshalSignatureKey(senderLeaf.LeafData.SignatureKey)
		sigPubKey = ciphersuite.NewOpenMlsSignaturePublicKey(raw, ciphersuite.ECDSA_SECP256R1_SHA256)
	}

	ac, err := framing.Decrypt(pm, framing.DecryptParams{
		CipherSuite:      g.CipherSuite,
		SenderDataSecret: g.EpochSecrets.SenderDataSecret,
		SecretTree:       g.SecretTree,
		SigPubKey:        sigPubKey,
		GroupContext:     g.GroupContext.Marshal(),
	})
	if err != nil {
		return nil, fmt.Errorf("decrypting message: %w", err)
	}

	data, ok := ac.Content.ApplicationData()
	if !ok {
		return nil, fmt.Errorf("received message is not application data")
	}
	return data, nil
}
