package group

import (
	"fmt"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/framing"
	"github.com/openmls/go/treesync"
)

// SendMessage encrypts an application message as PrivateMessage (RFC 9420 §6.3).
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

// ReceiveMessage decrypts a PrivateMessage and returns application data (RFC 9420 §6.3).
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
	// resolve sender signature pubkey from ratchet tree
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
