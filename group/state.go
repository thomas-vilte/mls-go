package group

import (
	"encoding/json"
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
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
		GroupID:               g.GroupID.AsSlice(),
		Epoch:                 g.Epoch.AsUint64(),
		CipherSuite:           uint16(g.CipherSuite),
		OwnLeafIndex:          uint32(g.OwnLeafIndex),
		GroupContext:          g.GroupContext.Marshal(),
		InterimTranscriptHash: g.InterimTranscriptHash,
		ConfirmationTag:       g.ConfirmationTag,
		Members:               make(map[uint32]*MemberStateData),
		CachedPsks:            g.CachedPsks,
		MyLeafEncryptionKey:   g.MyLeafEncryptionKey,
	}

	// Serialize tree
	state.RatchetTree = g.RatchetTree.MarshalTree()

	// Serialize EpochSecrets (assumes schedule will export this soon)
	state.EpochSecrets = g.EpochSecrets.MarshalData()

	// Serialize members
	for idx, member := range g.Members {
		if member != nil && member.KeyPackage != nil {
			state.Members[uint32(idx)] = &MemberStateData{
				LeafIndex:  uint32(member.LeafIndex),
				KeyPackage: member.KeyPackage.Marshal(),
			}
		}
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
	tree, err := treesync.UnmarshalTree(state.RatchetTree)
	if err != nil {
		// Try UnmarshalTreeFromExtension for backwards compatibility
		tree, err = treesync.UnmarshalTreeFromExtension(state.RatchetTree)
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
		GroupID:               NewGroupID(state.GroupID),
		Epoch:                 NewGroupEpoch(state.Epoch),
		CipherSuite:           cs,
		OwnLeafIndex:          LeafNodeIndex(state.OwnLeafIndex),
		RatchetTree:           tree,
		GroupContext:          gc,
		InterimTranscriptHash: state.InterimTranscriptHash,
		ConfirmationTag:       state.ConfirmationTag,
		EpochSecrets:          epochSecrets,
		KeySchedule:           schedule.NewKeySchedule(cs, epochSecrets.InitSecret),
		SecretTree:            st,
		Members:               make(map[LeafNodeIndex]*Member),
		CachedPsks:            state.CachedPsks,
		MyLeafEncryptionKey:   state.MyLeafEncryptionKey,
		Proposals:             NewProposalStore(),
		ProposalByRef:         make(map[string]*Proposal),
		state:                 StateOperational,
	}

	// Restaurant members
	for idx, mData := range state.Members {
		kp, err := keypackages.UnmarshalKeyPackage(mData.KeyPackage)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling member %d key package: %w", idx, err)
		}
		g.Members[LeafNodeIndex(idx)] = &Member{
			LeafIndex:  LeafNodeIndex(mData.LeafIndex),
			KeyPackage: kp,
		}
	}

	return g, nil
}
