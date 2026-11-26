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

// stateVersion is the StateData format that MarshalState writes. Version 1 guarantees a confirmation tag
// and an RFC 9420 §8.2 interim transcript hash for every epoch, epoch 0 included.
const stateVersion = 1

// StateData represents the serialized state of an MLS group.
//
// SECURITY WARNING: This structure contains sensitive cryptographic material
// (epoch secrets, membership data, ratchet tree). It MUST be encrypted at rest
// by the application using it. Never persist this data in plaintext.
//
// Wire format: JSON with base64-encoded byte fields for compatibility and ease
// of debugging. For production use, consider a more compact binary format.
//
// Fields:
//   - ID: Unique group identifier (RFC 9420 §5.2)
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
//   - PathNodePrivKeys: Private HPKE keys for copath ancestor nodes derived from
//     past UpdatePaths (RFC 9420 §12.4.2/§12.4.3.1), needed to decrypt path
//     secrets in future commits where one of these nodes appears in the
//     resolution. Without this, callers using CacheNone (which round-trips
//     every group through Marshal/UnmarshalGroupState) lose this material and
//     ProcessCommit can fail with ErrOwnLeafNotFound.
//   - PendingUpdatePrivKey: Private HPKE key for a self-generated Update
//     proposal (SelfUpdate) not yet committed; needed to decrypt the UpdatePath
//     of the commit that merges this proposal.
type StateData struct {
	// StateVersion is the format version (stateVersion when written by MarshalState). A state without it was
	// saved by an earlier version, and UnmarshalGroupState migrates it.
	StateVersion          int                           `json:"state_version,omitempty"`
	GroupID               []byte                        `json:"group_id"`
	Epoch                 uint64                        `json:"epoch"`
	CipherSuite           uint16                        `json:"cipher_suite"`
	OwnLeafIndex          uint32                        `json:"own_leaf_index"`
	RatchetTree           []byte                        `json:"ratchet_tree"`
	GroupContext          []byte                        `json:"group_context"`
	InterimTranscriptHash []byte                        `json:"interim_transcript_hash"`
	ConfirmationTag       []byte                        `json:"confirmation_tag"`
	EpochSecrets          *schedule.EpochSecretsData    `json:"epoch_secrets"`
	SecretTree            *secrettree.TreeState         `json:"secret_tree,omitempty"`
	Members               map[uint32]*MemberStateData   `json:"members"`
	StoredProposals       []*StoredProposalStateData    `json:"stored_proposals,omitempty"`
	CachedPsks            map[string][]byte             `json:"cached_psks"`
	MyLeafEncryptionKey   []byte                        `json:"my_leaf_encryption_key"`
	PathNodePrivKeys      map[treesync.NodeIndex][]byte `json:"path_node_priv_keys,omitempty"`
	PendingUpdatePrivKey  []byte                        `json:"pending_update_priv_key,omitempty"`
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
	LocalRef []byte `json:"local_ref,omitempty"`
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

	state := &StateData{
		StateVersion:          stateVersion,
		GroupID:               g.groupID.AsSlice(),
		Epoch:                 g.epoch.AsUint64(),
		CipherSuite:           uint16(g.cipherSuite),
		OwnLeafIndex:          uint32(g.ownLeafIndex),
		GroupContext:          g.groupContext.Marshal(),
		InterimTranscriptHash: g.interimTranscriptHash,
		ConfirmationTag:       g.confirmationTag,
		EpochSecrets:          g.epochSecrets.MarshalData(),
		SecretTree:            g.secretTree.MarshalFull(),
		Members:               make(map[uint32]*MemberStateData),
		CachedPsks:            g.cachedPsks,
		MyLeafEncryptionKey:   g.myLeafEncryptionKey,
		PathNodePrivKeys:      g.pathNodePrivKeys,
		PendingUpdatePrivKey:  g.pendingUpdatePrivKey,
	}

	// Serialize tree
	state.RatchetTree = g.ratchetTree.MarshalTree()

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
			LocalRef: append([]byte(nil), stored.LocalRef...),
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
	var state StateData
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("unmarshaling group state: %w", err)
	}

	cs := ciphersuite.CipherSuite(state.CipherSuite)
	if !cs.IsSupported() {
		return nil, fmt.Errorf("unmarshaling group state: %w: %d", ciphersuite.ErrUnsupportedSuite, cs)
	}

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

	// Restore EpochSecrets with the suite's own hash (SHA-512 for CS5). NewSecret defaults to
	// SHA-256, so a restored group would derive different exporter, sender data and ratchet values.
	var epochSecrets *schedule.EpochSecrets
	if state.EpochSecrets != nil {
		epochSecrets = &schedule.EpochSecrets{
			SenderDataSecret:     ciphersuite.NewSecretForCS(cs, state.EpochSecrets.SenderDataSecret),
			EncryptionSecret:     ciphersuite.NewSecretForCS(cs, state.EpochSecrets.EncryptionSecret),
			ExporterSecret:       ciphersuite.NewSecretForCS(cs, state.EpochSecrets.ExporterSecret),
			AuthenticationSecret: ciphersuite.NewSecretForCS(cs, state.EpochSecrets.AuthenticationSecret),
			ConfirmationKey:      ciphersuite.NewSecretForCS(cs, state.EpochSecrets.ConfirmationKey),
			MembershipKey:        ciphersuite.NewSecretForCS(cs, state.EpochSecrets.MembershipKey),
			ExternalSecret:       ciphersuite.NewSecretForCS(cs, state.EpochSecrets.ExternalSecret),
			ResumptionSecret:     ciphersuite.NewSecretForCS(cs, state.EpochSecrets.ResumptionSecret),
			InitSecret:           ciphersuite.NewSecretForCS(cs, state.EpochSecrets.InitSecret),
		}
	}

	var st *secrettree.Tree
	switch {
	case state.SecretTree != nil:
		st, err = secrettree.UnmarshalFull(state.SecretTree, cs)
		if err != nil {
			return nil, fmt.Errorf("restoring secret tree: %w", err)
		}
	case epochSecrets != nil && epochSecrets.EncryptionSecret != nil:
		st, err = secrettree.NewTree(epochSecrets.EncryptionSecret, tree.NumLeaves, cs)
		if err != nil {
			return nil, fmt.Errorf("recreating secret tree: %w", err)
		}
	default:
		return nil, fmt.Errorf("missing secret tree and encryption secret")
	}

	if epochSecrets == nil {
		return nil, fmt.Errorf("missing epoch secrets")
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
		pathNodePrivKeys:      state.PathNodePrivKeys,
		pendingUpdatePrivKey:  state.PendingUpdatePrivKey,
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
		ref := append([]byte(nil), pData.Ref...)
		// A state saved before repeated copies were ignored can hold one ProposalRef twice. That is one
		// proposal, so only its first copy is restored.
		if g.proposals.hasRef(ref) {
			continue
		}
		// A state saved before LocalRef was recorded can hold the echo of an own proposal next to the
		// proposal itself: a copy with a ProposalRef, sent by this member's leaf. The echo is the local
		// proposal, so the local entry takes the ref and the copy is not restored.
		if len(ref) > 0 && LeafNodeIndex(pData.Sender) == g.ownLeafIndex {
			if local := g.proposals.localWithoutRef(g.ownLeafIndex, pData.Proposal); local != nil {
				local.LocalRef = ref
				continue
			}
		}
		g.proposals.Proposals = append(g.proposals.Proposals, StoredProposal{
			Proposal: proposal,
			Sender:   LeafNodeIndex(pData.Sender),
			Ref:      ref,
			LocalRef: append([]byte(nil), pData.LocalRef...),
		})
		// Rebuild the by-ref index so that commits referencing proposals by hash
		// can resolve them after a state restore (UnmarshalGroupState).
		if len(ref) > 0 {
			g.proposalByRef[string(ref)] = proposal
		}
	}

	switch {
	case state.StateVersion > stateVersion:
		return nil, fmt.Errorf("unmarshaling group state: unsupported state version %d: %w", state.StateVersion, ErrInvalidGroupState)
	case state.StateVersion == 0:
		g.migrateLegacyTranscript()
	}

	if err := g.ValidateRestoredState(); err != nil {
		return nil, err
	}

	return g, nil
}

// migrateLegacyTranscript completes a state saved before stateVersion 1. Such a state can lack the
// confirmation tag (groups still at epoch 0, external joiners saved before ExternalCommit kept it) and, at
// epoch 0, hold an interim transcript hash computed from an empty tag. The tag follows from the epoch's own
// secrets. A group at epoch 0 has not used its interim hash yet, so that one is recomputed as RFC 9420 §11
// specifies. In later epochs the stored interim hash already came from the real tag and is kept.
func (g *Group) migrateLegacyTranscript() {
	if len(g.confirmationTag) > 0 || g.groupContext == nil || g.epochSecrets == nil || g.epochSecrets.ConfirmationKey == nil {
		return
	}
	cth := g.groupContext.ConfirmedTranscriptHash
	g.confirmationTag = schedule.ComputeConfirmationTag(g.cipherSuite, g.epochSecrets.ConfirmationKey.AsSlice(), cth)
	if g.epoch.AsUint64() == 0 {
		g.interimTranscriptHash = schedule.ComputeInterimTranscriptHash(g.cipherSuite, cth, g.confirmationTag)
	}
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
	// GroupID is public protocol metadata, not secret material.
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
	// TreeHash is a public integrity value from GroupContext, not secret material.
	if !bytes.Equal(computedTreeHash, g.groupContext.TreeHash) {
		return fmt.Errorf("validating restored state: computed tree hash %x does not match stored tree hash %x: %w", computedTreeHash, g.groupContext.TreeHash, ErrTreeHashMismatch)
	}

	// Every epoch has a confirmation tag (RFC 9420 §8.2, §11), and it is the integrity check of the epoch
	// secrets, so a state without it is incomplete. UnmarshalGroupState completes states saved
	// before stateVersion 1 before this check runs.
	if len(g.confirmationTag) == 0 {
		return fmt.Errorf("validating restored state: missing confirmation tag: %w", ErrInvalidGroupState)
	}
	expectedTag := schedule.ComputeConfirmationTag(
		g.cipherSuite,
		g.epochSecrets.ConfirmationKey.AsSlice(),
		g.groupContext.ConfirmedTranscriptHash,
	)
	if !ciphersuite.EqualCT(expectedTag, g.confirmationTag) {
		return fmt.Errorf("validating restored state: stored confirmation tag %x does not match computed confirmation tag %x: %w", g.confirmationTag, expectedTag, ErrConfirmationTagMismatch)
	}
	// interim_transcript_hash = Hash(confirmed_transcript_hash || VL(confirmation_tag)) (RFC 9420 §8.2).
	expectedInterim := schedule.ComputeInterimTranscriptHash(g.cipherSuite, g.groupContext.ConfirmedTranscriptHash, g.confirmationTag)
	if !bytes.Equal(expectedInterim, g.interimTranscriptHash) {
		return fmt.Errorf("validating restored state: interim transcript hash does not follow from the confirmed transcript hash and confirmation tag: %w", ErrInvalidGroupState)
	}

	return nil
}
