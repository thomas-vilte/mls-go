package group

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/schedule"
	"github.com/thomas-vilte/mls-go/secrettree"
	"github.com/thomas-vilte/mls-go/treesync"
)

// GroupStateData represents the serialized state of an MLS group.
//
// SECURITY WARNING: This structure contains sensitive cryptographic material
// (epoch secrets, membership data, ratchet tree). It MUST be encrypted at rest
// by the application using it. Never persist this data in plaintext.
//
// Wire format: JSON with base64-encoded byte fields for compatibility and ease
// of debugging. For production use, consider a more compact binary format.
//
// Fields:
//   - GroupID: Unique group identifier (RFC 9420 §5.2)
//   - Epoch: Current epoch number
//   - CipherSuite: Cipher suite in use
//   - OwnLeafIndex: This member's leaf index in the tree
//   - RatchetTree: Serialized tree (RFC 9420 §12.4.3.3 extension format)
//   - GroupContext: Serialized GroupContext (RFC 9420 §5.2)
//   - InterimTranscriptHash: Hash of handshake messages (RFC 9420 §8.2)
//   - ConfirmationTag: Tag confirming epoch agreement (RFC 9420 §8.2)
//   - EpochSecrets: Serialized epoch secrets (sender_data, encryption, exporter, etc.)
//   - Members: Map of member state data
//   - CachedPsks: Cached pre-shared keys for future epochs
//   - MyLeafEncryptionKey: This member's current leaf encryption key
type GroupStateData struct {
	GroupID               []byte                      `json:"group_id"`
	Epoch                 uint64                      `json:"epoch"`
	CipherSuite           uint16                      `json:"cipher_suite"`
	OwnLeafIndex          uint32                      `json:"own_leaf_index"`
	RatchetTree           []byte                      `json:"ratchet_tree"` // serializado como extensión
	GroupContext          []byte                      `json:"group_context"`
	InterimTranscriptHash []byte                      `json:"interim_transcript_hash"`
	ConfirmationTag       []byte                      `json:"confirmation_tag"`
	EpochSecrets          *schedule.EpochSecretsData  `json:"epoch_secrets"`
	Members               map[uint32]*MemberStateData `json:"members"`
	StoredProposals       []*StoredProposalStateData  `json:"stored_proposals,omitempty"`
	CachedPsks            map[string][]byte           `json:"cached_psks"`
	MyLeafEncryptionKey   []byte                      `json:"my_leaf_encryption_key"`
}

// MemberStateData represents a group member in serialized state.
//
// Only the KeyPackage bytes are stored (not decoded) to minimize memory
// footprint. The KeyPackage can be decoded on-demand when needed.
type MemberStateData struct {
	LeafIndex  uint32 `json:"leaf_index"`
	KeyPackage []byte `json:"key_package"`
	Credential []byte `json:"credential,omitempty"`
	SigningKey []byte `json:"signing_key,omitempty"`
	Active     bool   `json:"active"`
}

// StoredProposalStateData represents a pending proposal persisted across reloads.
type StoredProposalStateData struct {
	Proposal []byte `json:"proposal"`
	Sender   uint32 `json:"sender"`
	Ref      []byte `json:"ref,omitempty"`
}

// MarshalState serializes the complete group state to JSON.
//
// SECURITY WARNING: The output contains sensitive cryptographic material
// (epoch secrets, ratchet tree, membership data). The caller MUST encrypt
// this data before persisting it to disk or transmitting it.
//
// Returns:
//   - JSON-encoded byte slice containing the full group state
//   - Error if the group is not in operational state or serialization fails
//
// Usage:
//
//	data, err := group.MarshalState()
//	if err != nil {
//	    return err
//	}
//	// Encrypt data before storing
//	encrypted := EncryptAtRest(data)
func (g *Group) MarshalState() ([]byte, error) {
	if g.state != StateOperational {
		return nil, fmt.Errorf("can only serialize group in operational state")
	}

	state := &GroupStateData{
		GroupID:               g.groupID.AsSlice(),
		Epoch:                 g.epoch.AsUint64(),
		CipherSuite:           uint16(g.cipherSuite),
		OwnLeafIndex:          uint32(g.ownLeafIndex),
		GroupContext:          g.groupContext.Marshal(),
		InterimTranscriptHash: g.interimTranscriptHash,
		ConfirmationTag:       g.confirmationTag,
		Members:               make(map[uint32]*MemberStateData),
		CachedPsks:            g.cachedPsks,
		MyLeafEncryptionKey:   g.myLeafEncryptionKey,
	}

	// Serialize tree
	state.RatchetTree = g.ratchetTree.MarshalTree()

	// Serialize EpochSecrets (assumes schedule will export this soon)
	state.EpochSecrets = g.epochSecrets.MarshalData()

	// Serialize members
	for idx, member := range g.members {
		if member == nil {
			continue
		}
		mState := &MemberStateData{
			LeafIndex: uint32(member.LeafIndex),
			Active:    member.Active,
		}
		if member.KeyPackage != nil {
			mState.KeyPackage = member.KeyPackage.Marshal()
		}
		if member.Credential != nil {
			mState.Credential = member.Credential.Marshal()
		}
		leaf := g.ratchetTree.GetLeaf(treesync.LeafIndex(idx))
		if leaf != nil && leaf.LeafData != nil {
			mState.SigningKey = append([]byte(nil), leaf.LeafData.SigKeyBytes()...)
		}
		state.Members[uint32(idx)] = mState
	}

	for _, stored := range g.proposals.Proposals {
		if stored.Proposal == nil {
			continue
		}
		state.StoredProposals = append(state.StoredProposals, &StoredProposalStateData{
			Proposal: ProposalMarshal(stored.Proposal),
			Sender:   uint32(stored.Sender),
			Ref:      append([]byte(nil), stored.Ref...),
		})
	}

	return json.Marshal(state)
}

// UnmarshalGroupState deserializes a previously saved group state from JSON.
//
// SECURITY WARNING: The input data contains sensitive cryptographic material.
// Ensure the data is decrypted from a trusted source before calling this function.
//
// Parameters:
//   - data: JSON-encoded byte slice from MarshalState()
//
// Returns:
//   - Restored Group instance ready for use
//   - Error if deserialization fails or tree restoration fails
//
// Usage:
//
//	// Decrypt data from storage first
//	decrypted := DecryptFromStorage(encryptedData)
//	group, err := UnmarshalGroupState(decrypted)
//	if err != nil {
//	    return err
//	}
func UnmarshalGroupState(data []byte) (*Group, error) {
	var state GroupStateData
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("unmarshaling group state: %w", err)
	}

	cs := ciphersuite.CipherSuite(state.CipherSuite)

	// Restore RatchetTree
	tree, err := treesync.UnmarshalTree(state.RatchetTree, cs)
	if err != nil {
		// Try UnmarshalTreeFromExtension for backwards compatibility
		tree, err = treesync.UnmarshalTreeFromExtension(state.RatchetTree, cs)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling ratchet tree: %w", err)
		}
	}

	// Restore GroupContext
	gc, err := UnmarshalGroupContext(state.GroupContext)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling group context: %w", err)
	}

	// Restore EpochSecrets
	var epochSecrets *schedule.EpochSecrets
	if state.EpochSecrets != nil {
		epochSecrets = &schedule.EpochSecrets{
			SenderDataSecret:     ciphersuite.NewSecret(state.EpochSecrets.SenderDataSecret),
			EncryptionSecret:     ciphersuite.NewSecret(state.EpochSecrets.EncryptionSecret),
			ExporterSecret:       ciphersuite.NewSecret(state.EpochSecrets.ExporterSecret),
			AuthenticationSecret: ciphersuite.NewSecret(state.EpochSecrets.AuthenticationSecret),
			ConfirmationKey:      ciphersuite.NewSecret(state.EpochSecrets.ConfirmationKey),
			MembershipKey:        ciphersuite.NewSecret(state.EpochSecrets.MembershipKey),
			ExternalSecret:       ciphersuite.NewSecret(state.EpochSecrets.ExternalSecret),
			ResumptionSecret:     ciphersuite.NewSecret(state.EpochSecrets.ResumptionSecret),
			InitSecret:           ciphersuite.NewSecret(state.EpochSecrets.InitSecret),
		}
	}

	// Restore SecretTree
	st, err := secrettree.NewTree(epochSecrets.EncryptionSecret, tree.NumLeaves, cs)
	if err != nil {
		return nil, fmt.Errorf("recreating secret tree: %w", err)
	}

	// Restore Group
	g := &Group{
		groupID:               NewGroupID(state.GroupID),
		epoch:                 NewGroupEpoch(state.Epoch),
		cipherSuite:           cs,
		ownLeafIndex:          LeafNodeIndex(state.OwnLeafIndex),
		ratchetTree:           tree,
		groupContext:          gc,
		interimTranscriptHash: state.InterimTranscriptHash,
		confirmationTag:       state.ConfirmationTag,
		epochSecrets:          epochSecrets,
		keySchedule:           schedule.NewKeySchedule(cs, epochSecrets.InitSecret),
		secretTree:            st,
		members:               make(map[LeafNodeIndex]*Member),
		cachedPsks:            state.CachedPsks,
		myLeafEncryptionKey:   state.MyLeafEncryptionKey,
		proposals:             NewProposalStore(),
		proposalByRef:         make(map[string]*Proposal),
		state:                 StateOperational,
	}

	// Restaurant members
	for idx, mData := range state.Members {
		var kp *keypackages.KeyPackage
		if len(mData.KeyPackage) > 0 {
			kp, err = keypackages.UnmarshalKeyPackage(mData.KeyPackage)
			if err != nil {
				return nil, fmt.Errorf("unmarshaling member %d key package: %w", idx, err)
			}
		}
		var cred *credentials.Credential
		if len(mData.Credential) > 0 {
			cred, err = credentials.UnmarshalCredential(mData.Credential)
			if err != nil {
				return nil, fmt.Errorf("unmarshaling member %d credential: %w", idx, err)
			}
		}
		g.members[LeafNodeIndex(idx)] = &Member{
			LeafIndex:  LeafNodeIndex(mData.LeafIndex),
			KeyPackage: kp,
			Credential: cred,
			Active:     mData.Active,
		}
	}

	for i, pData := range state.StoredProposals {
		if pData == nil {
			continue
		}
		proposal, err := UnmarshalProposal(pData.Proposal)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling stored proposal %d: %w", i, err)
		}
		g.proposals.AddProposalWithRef(proposal, LeafNodeIndex(pData.Sender), append([]byte(nil), pData.Ref...))
	}

	if err := g.ValidateRestoredState(); err != nil {
		return nil, err
	}

	return g, nil
}

// ValidateRestoredState verifies that a deserialized group is internally consistent
// before it is returned to callers.
func (g *Group) ValidateRestoredState() error {
	if g == nil {
		return fmt.Errorf("validating restored state: %w", ErrInvalidGroupState)
	}
	if g.groupContext == nil {
		return fmt.Errorf("validating restored state: missing group context: %w", ErrInvalidGroupState)
	}
	if g.ratchetTree == nil {
		return fmt.Errorf("validating restored state: missing ratchet tree: %w", ErrInvalidGroupState)
	}
	if g.epochSecrets == nil {
		return fmt.Errorf("validating restored state: missing epoch secrets: %w", ErrInvalidGroupState)
	}
	if g.secretTree == nil {
		return fmt.Errorf("validating restored state: missing secret tree: %w", ErrInvalidGroupState)
	}
	if g.groupContext.GroupID == nil || !bytes.Equal(g.groupID.AsSlice(), g.groupContext.GroupID.AsSlice()) {
		return fmt.Errorf("validating restored state: group ID mismatch: %w", ErrInvalidGroupState)
	}
	if g.groupContext.CipherSuite != g.cipherSuite {
		return fmt.Errorf("validating restored state: cipher suite mismatch: %w", ErrInvalidGroupState)
	}
	if g.groupContext.Epoch != g.epoch {
		return fmt.Errorf("validating restored state: epoch mismatch: %w", ErrInvalidGroupState)
	}
	if uint32(g.ownLeafIndex) >= g.ratchetTree.NumLeaves {
		return fmt.Errorf("validating restored state: own leaf index %d out of bounds for tree with %d leaves: %w", g.ownLeafIndex, g.ratchetTree.NumLeaves, ErrInvalidGroupState)
	}

	ownLeaf := g.ratchetTree.GetLeaf(treesync.LeafIndex(g.ownLeafIndex))
	if ownLeaf == nil || ownLeaf.State != treesync.NodeStatePresent || ownLeaf.LeafData == nil {
		return fmt.Errorf("validating restored state: own leaf %d is not active: %w", g.ownLeafIndex, ErrInvalidGroupState)
	}

	computedTreeHash := g.ratchetTree.TreeHash()
	if !bytes.Equal(computedTreeHash, g.groupContext.TreeHash) {
		return fmt.Errorf("validating restored state: computed tree hash %x does not match stored tree hash %x: %w", computedTreeHash, g.groupContext.TreeHash, ErrTreeHashMismatch)
	}

	if len(g.confirmationTag) > 0 {
		expectedTag := schedule.ComputeConfirmationTag(
			g.cipherSuite,
			g.epochSecrets.ConfirmationKey.AsSlice(),
			g.groupContext.ConfirmedTranscriptHash,
		)
		if !ciphersuite.EqualCT(expectedTag, g.confirmationTag) {
			return fmt.Errorf("validating restored state: stored confirmation tag %x does not match computed confirmation tag %x: %w", g.confirmationTag, expectedTag, ErrConfirmationTagMismatch)
		}
	}

	return nil
}
