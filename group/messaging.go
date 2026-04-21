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
		return nil, fmt.Errorf("send message: %w", ErrGroupNotOperational)
	}
	// RFC 9420 §12.4 requires committing observed proposals before sending
	// application data in the current epoch.
	if g.proposals != nil && len(g.proposals.Proposals) > 0 {
		return nil, fmt.Errorf("cannot send application data while proposals are pending: %w", ErrPendingProposals)
	}
	if sigPrivKey == nil {
		return nil, fmt.Errorf("send message: %w", ErrNilSignaturePrivateKey)
	}
	if g.epochSecrets == nil || g.epochSecrets.SenderDataSecret == nil {
		return nil, fmt.Errorf("send message: %w", ErrSenderDataSecretMissing)
	}
	if g.secretTree == nil {
		return nil, fmt.Errorf("send message: %w", ErrSecretTreeMissing)
	}

	content := framing.FramedContent{
		GroupID:           g.groupID.AsSlice(),
		Epoch:             g.epoch.AsUint64(),
		Sender:            framing.Sender{Type: framing.SenderTypeMember, LeafIndex: uint32(g.ownLeafIndex)},
		AuthenticatedData: []byte{},
		Body:              framing.ApplicationData{Data: data},
	}

	return framing.Encrypt(framing.EncryptParams{
		Content:          content,
		SenderLeafIndex:  uint32(g.ownLeafIndex),
		CipherSuite:      g.cipherSuite,
		PaddingSize:      g.paddingSize,
		SenderDataSecret: g.epochSecrets.SenderDataSecret,
		SecretTree:       g.secretTree,
		SigKey:           sigPrivKey,
		GroupContext:     g.groupContext.Marshal(),
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
		return nil, fmt.Errorf("send application message: %w", ErrGroupNotOperational)
	}
	// RFC 9420 §12.4 requires committing observed proposals before sending
	// application data in the current epoch.
	if g.proposals != nil && len(g.proposals.Proposals) > 0 {
		return nil, fmt.Errorf("cannot send application data while proposals are pending: %w", ErrPendingProposals)
	}
	if sigPrivKey == nil {
		return nil, fmt.Errorf("send application message: %w", ErrNilSignaturePrivateKey)
	}
	if g.epochSecrets == nil || g.epochSecrets.SenderDataSecret == nil {
		return nil, fmt.Errorf("send application message: %w", ErrSenderDataSecretMissing)
	}
	if g.secretTree == nil {
		return nil, fmt.Errorf("send application message: %w", ErrSecretTreeMissing)
	}

	content := framing.FramedContent{
		GroupID:           g.groupID.AsSlice(),
		Epoch:             g.epoch.AsUint64(),
		Sender:            framing.Sender{Type: framing.SenderTypeMember, LeafIndex: uint32(g.ownLeafIndex)},
		AuthenticatedData: authenticatedData,
		Body:              framing.ApplicationData{Data: data},
	}

	return framing.Encrypt(framing.EncryptParams{
		Content:          content,
		SenderLeafIndex:  uint32(g.ownLeafIndex),
		CipherSuite:      g.cipherSuite,
		PaddingSize:      g.paddingSize,
		SenderDataSecret: g.epochSecrets.SenderDataSecret,
		SecretTree:       g.secretTree,
		SigKey:           sigPrivKey,
		GroupContext:     g.groupContext.Marshal(),
	})
}

// SignProposalAsPublicMessage wraps a Proposal in a signed PublicMessage MLSMessage.
//
// RFC 9420 §6.2: proposals from group members MUST be sent as PublicMessage with
// a membership_tag. This is the format expected by other MLS implementations.
func (g *Group) SignProposalAsPublicMessage(
	proposal *Proposal,
	sigKey *ciphersuite.SignaturePrivateKey,
) ([]byte, error) {
	content := framing.FramedContent{
		GroupID:           g.groupID.AsSlice(),
		Epoch:             g.epoch.AsUint64(),
		Sender:            framing.Sender{Type: framing.SenderTypeMember, LeafIndex: uint32(g.ownLeafIndex)},
		AuthenticatedData: []byte{},
		Body:              framing.ProposalBody{Data: ProposalMarshal(proposal)},
	}
	pm, err := framing.NewPublicMessage(
		content,
		sigKey,
		g.groupContext.Marshal(),
		g.epochSecrets.MembershipKey,
		g.cipherSuite,
	)
	if err != nil {
		return nil, fmt.Errorf("signing proposal: %w", err)
	}

	// RFC 9420 §12.4: index the ProposalRef in the lookup map so this sender can
	// resolve the proposal when another member's commit references it by hash.
	// Without this, a competing commit that references the proposal by-ref would
	// fail with "unknown proposal reference" when processed by the original proposer.
	//
	// We update ONLY proposalByRef (not StoredProposal.Ref) so that the committer's
	// own commits continue to include locally-created proposals inline — receivers
	// may not have received the proposal message separately and cannot resolve by-ref.
	acForRef := &framing.AuthenticatedContent{
		WireFormat: framing.WireFormatPublicMessage,
		Content:    pm.Content,
		Auth:       pm.Auth,
	}
	ref := ComputeProposalRef(acForRef.Marshal(), g.cipherSuite)
	if g.proposalByRef == nil {
		g.proposalByRef = make(map[string]*Proposal)
	}
	g.proposalByRef[string(ref)] = proposal

	return framing.NewMLSMessagePublic(pm).Marshal(), nil
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
		return nil, fmt.Errorf("receive message: %w", ErrGroupNotOperational)
	}
	if pm == nil {
		return nil, fmt.Errorf("receive message: %w", ErrNilPrivateMessage)
	}
	if g.epochSecrets == nil || g.epochSecrets.SenderDataSecret == nil {
		return nil, fmt.Errorf("receive message: %w", ErrSenderDataSecretMissing)
	}
	if g.secretTree == nil {
		return nil, fmt.Errorf("receive message: %w", ErrSecretTreeMissing)
	}

	// RFC §6.1: Validate sender index is within tree bounds
	if uint32(senderLeafIdx) >= g.ratchetTree.NumLeaves {
		return nil, &ErrUnknownMember{LeafIndex: uint32(senderLeafIdx)}
	}

	// Resolve sender signature pubkey from ratchet tree.
	// Use SigKeyBytes() to handle both ECDSA (SignatureKey) and Ed25519 (SignatureKeyRaw).
	senderLeaf := g.ratchetTree.GetLeaf(treesync.LeafIndex(senderLeafIdx))
	var sigPubKey *ciphersuite.MLSSignaturePublicKey
	if senderLeaf != nil && senderLeaf.LeafData != nil {
		if raw := senderLeaf.LeafData.SigKeyBytes(); len(raw) > 0 {
			sigPubKey = ciphersuite.NewMLSSignaturePublicKey(raw, g.cipherSuite.SignatureScheme())
		}
	}

	ac, err := framing.Decrypt(pm, framing.DecryptParams{
		CipherSuite:      g.cipherSuite,
		SenderDataSecret: g.epochSecrets.SenderDataSecret,
		SecretTree:       g.secretTree,
		SigPubKey:        sigPubKey,
		GroupContext:     g.groupContext.Marshal(),
	})
	if err != nil {
		return nil, &ErrDecryptionFailed{Reason: "message", Err: err}
	}

	data, ok := ac.Content.ApplicationData()
	if !ok {
		return nil, ErrNotApplicationData
	}
	return data, nil
}

// ReceiveApplicationMessage decrypts an application PrivateMessage without
// requiring the caller to supply the sender's leaf index. The leaf index is
// extracted from the encrypted SenderData (RFC 9420 §6.3.2). After decryption,
// the sender's signature is verified using the ratchet tree for the message's epoch.
//
// This is the entry point used by the MLSWG interop gRPC Unprotect RPC,
// where the ciphertext is opaque and the sender is determined at decrypt time.
//
// Messages from previous epochs are decrypted and verified using the cached
// EpochHistory to support out-of-order delivery across epoch boundaries.
func (g *Group) ReceiveApplicationMessage(pm *framing.PrivateMessage) (plaintext, authenticatedData []byte, senderLeafIdx treesync.LeafIndex, err error) {
	if g.state != StateOperational {
		return nil, nil, 0, fmt.Errorf("receive application message: %w", ErrGroupNotOperational)
	}
	if pm == nil {
		return nil, nil, 0, fmt.Errorf("receive application message: %w", ErrNilPrivateMessage)
	}

	var senderDataSecret *ciphersuite.Secret
	var secretTree *secrettree.Tree
	var ratchetTree *treesync.RatchetTree
	var groupContextBytes []byte
	var cs ciphersuite.CipherSuite

	if pm.Epoch == g.epoch.AsUint64() {
		if g.epochSecrets == nil || g.epochSecrets.SenderDataSecret == nil {
			return nil, nil, 0, fmt.Errorf("current epoch: %w", ErrSenderDataSecretMissing)
		}
		if g.secretTree == nil {
			return nil, nil, 0, fmt.Errorf("current epoch: %w", ErrSecretTreeMissing)
		}
		if g.ratchetTree == nil {
			return nil, nil, 0, fmt.Errorf("current epoch: %w", ErrRatchetTreeMissing)
		}
		senderDataSecret = g.epochSecrets.SenderDataSecret
		secretTree = g.secretTree
		ratchetTree = g.ratchetTree
		groupContextBytes = g.groupContext.Marshal()
		cs = g.cipherSuite
	} else {
		if state, ok := g.epochHistory[pm.Epoch]; ok {
			senderDataSecret = state.SenderDataSecret
			secretTree = state.SecretTree
			ratchetTree = state.RatchetTree
			if state.GroupContext == nil {
				return nil, nil, 0, fmt.Errorf("group context not available for epoch %d: %w", pm.Epoch, ErrUnknownEpoch)
			}
			groupContextBytes = state.GroupContext.Marshal()
			cs = state.CipherSuite
		} else {
			return nil, nil, 0, fmt.Errorf("message from unknown epoch %d (current: %d): %w", pm.Epoch, g.epoch.AsUint64(), ErrUnknownEpoch)
		}
	}

	ac, decErr := framing.Decrypt(pm, framing.DecryptParams{
		CipherSuite:      cs,
		SenderDataSecret: senderDataSecret,
		SecretTree:       secretTree,
		GroupContext:     groupContextBytes,
	})
	if decErr != nil {
		return nil, nil, 0, &ErrDecryptionFailed{Reason: "message", Err: decErr}
	}

	senderLeafIdx = treesync.LeafIndex(ac.Content.Sender.LeafIndex)
	if ratchetTree == nil {
		return nil, nil, 0, fmt.Errorf("ratchet tree not available for epoch %d: %w", pm.Epoch, ErrRatchetTreeMissing)
	}

	if uint32(senderLeafIdx) >= ratchetTree.NumLeaves {
		return nil, nil, 0, &ErrUnknownMember{LeafIndex: uint32(senderLeafIdx)}
	}

	senderLeaf := ratchetTree.GetLeaf(senderLeafIdx)
	if senderLeaf == nil || senderLeaf.State != treesync.NodeStatePresent || senderLeaf.LeafData == nil {
		return nil, nil, 0, fmt.Errorf("sender %d is not an active member: %w", senderLeafIdx, ErrSenderNotActive)
	}

	rawKey := senderLeaf.LeafData.SigKeyBytes()
	if len(rawKey) == 0 {
		return nil, nil, 0, ErrMissingSenderSignature
	}

	pubKey := ciphersuite.NewMLSSignaturePublicKey(rawKey, cs.SignatureScheme())
	if err := ciphersuite.VerifyWithLabel(pubKey, "FramedContentTBS", ac.MarshalTBS(), ac.Auth.Signature); err != nil {
		return nil, nil, 0, &ErrInvalidSignature{Context: "private message", Err: err}
	}

	data, ok := ac.Content.ApplicationData()
	if !ok {
		return nil, nil, 0, ErrNotApplicationData
	}
	return data, ac.Content.AuthenticatedData, senderLeafIdx, nil
}
