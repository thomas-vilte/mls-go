package group

import (
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/secrettree"
	"github.com/thomas-vilte/mls-go/treesync"
)

// SendMessage encrypts an application message for the group.
//
// RFC 9420 §6.3
// The message is authenticated using the sender's signature key and encrypted
// using the current epoch's symmetric keys (via the Secret Tree).
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

// SendApplicationMessage encrypts an application message with caller-supplied
// authenticated data. Unlike SendMessage, the authenticated_data field is
// not hardcoded to empty — required by the MLSWG interop gRPC interface
// (ProtectRequest.authenticated_data, RFC 9420 §6.3.1).
func (g *Group) SendApplicationMessage(
	data []byte,
	authenticatedData []byte,
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
		AuthenticatedData: authenticatedData,
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

// ReceiveMessage decrypts an application message from another member.
//
// RFC 9420 §6.3
// It verifies the sender's signature, decrypts the content, and advances the
// Secret Tree ratchets. The sender leaf index must be provided (typically
// obtained from the unencrypted MLSSenderData if using PrivateMessage).
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

	// Resolve sender signature pubkey from ratchet tree.
	// Use SigKeyBytes() to handle both ECDSA (SignatureKey) and Ed25519 (SignatureKeyRaw).
	senderLeaf := g.RatchetTree.GetLeaf(treesync.LeafIndex(senderLeafIdx))
	var sigPubKey *ciphersuite.OpenMlsSignaturePublicKey
	if senderLeaf != nil && senderLeaf.LeafData != nil {
		if raw := senderLeaf.LeafData.SigKeyBytes(); len(raw) > 0 {
			sigPubKey = ciphersuite.NewOpenMlsSignaturePublicKey(raw, g.CipherSuite.SignatureScheme())
		}
	}

	ac, err := framing.Decrypt(pm, framing.DecryptParams{
		CipherSuite:      g.CipherSuite,
		SenderDataSecret: g.EpochSecrets.SenderDataSecret,
		SecretTree:       g.SecretTree,
		SigPubKey:        sigPubKey,
		GroupContext:     g.GroupContext.Marshal(),
	})
	if err != nil {
		return nil, &ErrDecryptionFailed{Reason: "message", Err: err}
	}

	data, ok := ac.Content.ApplicationData()
	if !ok {
		return nil, fmt.Errorf("received message is not application data")
	}
	return data, nil
}

// ReceiveApplicationMessage decrypts an application PrivateMessage without
// requiring the caller to supply the sender's leaf index. The leaf index is
// extracted from the encrypted SenderData (RFC 9420 §6.3.2). Signature
// verification is skipped; use ReceiveMessage when the sender is known.
//
// This is the entry point used by the MLSWG interop gRPC Unprotect RPC,
// where the ciphertext is opaque and the sender is determined at decrypt time.
//
// Messages from previous epochs are decrypted using the cached EpochHistory
// to support out-of-order delivery across epoch boundaries.
func (g *Group) ReceiveApplicationMessage(pm *framing.PrivateMessage) (plaintext, authenticatedData []byte, err error) {
	if g.state != StateOperational {
		return nil, nil, fmt.Errorf("group not operational")
	}
	if pm == nil {
		return nil, nil, fmt.Errorf("private message is nil")
	}

	var senderDataSecret *ciphersuite.Secret
	var secretTree *secrettree.Tree

	if pm.Epoch == g.Epoch.AsUint64() {
		// Current epoch — use live secrets.
		if g.EpochSecrets == nil || g.EpochSecrets.SenderDataSecret == nil {
			return nil, nil, fmt.Errorf("sender_data_secret not available")
		}
		if g.SecretTree == nil {
			return nil, nil, fmt.Errorf("secret tree not available")
		}
		senderDataSecret = g.EpochSecrets.SenderDataSecret
		secretTree = g.SecretTree
	} else {
		// Old epoch — look up cached epoch history.
		if state, ok := g.EpochHistory[pm.Epoch]; ok {
			senderDataSecret = state.SenderDataSecret
			secretTree = state.SecretTree
		} else {
			return nil, nil, fmt.Errorf("message from unknown epoch %d (current: %d)", pm.Epoch, g.Epoch.AsUint64())
		}
	}

	// Decrypt without signature verification — sender identity is not available
	// before decrypting SenderData. SigPubKey: nil skips the verify step in
	// framing.Decrypt while still advancing the SecretTree ratchet correctly.
	ac, decErr := framing.Decrypt(pm, framing.DecryptParams{
		CipherSuite:      g.CipherSuite,
		SenderDataSecret: senderDataSecret,
		SecretTree:       secretTree,
		GroupContext:     g.GroupContext.Marshal(),
	})
	if decErr != nil {
		return nil, nil, &ErrDecryptionFailed{Reason: "message", Err: decErr}
	}

	data, ok := ac.Content.ApplicationData()
	if !ok {
		return nil, nil, fmt.Errorf("received message is not application data")
	}
	return data, ac.Content.AuthenticatedData, nil
}
