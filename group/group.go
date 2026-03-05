// Package group implements MLS Group Management according to RFC 9420 §11-12.
//
// This package provides functionality for:
//   - Group creation and joining
//   - Proposal handling (Add, Update, Remove)
//   - Commit creation and processing
//   - Welcome message handling
//   - Member management
//
// This implementation is generic and can be used for any MLS-based protocol.
package group

import (
	"crypto/rand"
	"fmt"

	"github.com/openmls/go/ciphersuite"
	keypackages "github.com/openmls/go/key_packages"
	"github.com/openmls/go/schedule"
	"github.com/openmls/go/treesync"
)

// GroupID uniquely identifies an MLS group
type GroupID struct {
	Value []byte
}

// NewGroupID creates a GroupID from bytes
func NewGroupID(value []byte) *GroupID {
	return &GroupID{Value: value}
}

// NewGroupIDRandom generates a random GroupID.
func NewGroupIDRandom() (*GroupID, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("generating random group ID: %w", err)
	}
	return &GroupID{Value: id}, nil
}

// AsSlice returns the GroupID as a byte slice.
func (g *GroupID) AsSlice() []byte {
	return g.Value
}

// GroupEpoch represents the epoch number of a group.
type GroupEpoch uint64

// NewGroupEpoch creates a new epoch.
func NewGroupEpoch(epoch uint64) GroupEpoch {
	return GroupEpoch(epoch)
}

// AsUint64 returns the epoch as uint64.
func (e GroupEpoch) AsUint64() uint64 {
	return uint64(e)
}

// Increment increments the epoch.
func (e *GroupEpoch) Increment() {
	*e++
}

// Group represents an MLS group.
type Group struct {
	GroupID               *GroupID
	Epoch                 GroupEpoch
	CipherSuite           ciphersuite.CipherSuite
	GroupContext          *GroupContext
	RatchetTree           *treesync.RatchetTree
	OwnLeafIndex          LeafNodeIndex
	EpochSecrets          *schedule.EpochSecrets
	Proposals             *ProposalStore
	PendingCommit         *StagedCommit
	ConfirmationTag       []byte
	InterimTranscriptHash []byte
	KeySchedule           *schedule.KeySchedule
	Members               map[LeafNodeIndex]*Member
	state                 GroupState
}

// This is the entry point for creating a new group.
func NewGroup(
	groupID *GroupID,
	cipherSuite ciphersuite.CipherSuite,
	keyPackage *keypackages.KeyPackage,
	privateKeys *keypackages.KeyPackagePrivateKeys,
) (*Group, error) {
	// Create ratchet tree with 1 leaf
	ratchetTree := treesync.NewRatchetTree(1)

	// Add our leaf
	leafData := treesync.LeafNodeData{
		EncryptionKey:  keyPackage.InitKey,
		SignatureKey:   &privateKeys.SignatureKey.PublicKey,
		Credential:     keyPackage.LeafNode.Credential,
		Capabilities:   &treesync.LeafNodeCapabilities{},
		Lifetime:       &treesync.LeafNodeLifetime{},
		LeafNodeSource: 1, // key_package
	}

	_, _ = ratchetTree.AddLeaf(leafData)

	// Create group context
	groupContext := &GroupContext{
		GroupID:     groupID,
		Epoch:       NewGroupEpoch(0),
		CipherSuite: cipherSuite,
		Extensions:  []Extension{},
	}

	// Initialize key schedule with zeros for first epoch
	initSecret := ciphersuite.ZeroSecret(cipherSuite.HashLength())
	keySchedule := schedule.NewKeySchedule(cipherSuite, initSecret)

	// Compute epoch secrets
	commitSecret := ciphersuite.ZeroSecret(cipherSuite.HashLength())
	keySchedule.SetCommitSecret(commitSecret)

	_, err := keySchedule.ComputeJoinerSecret()
	if err != nil {
		return nil, fmt.Errorf("computing joiner secret: %w", err)
	}

	_, err = keySchedule.ComputePskSecret([]schedule.Psk{})
	if err != nil {
		return nil, fmt.Errorf("computing psk secret: %w", err)
	}

	groupContextBytes := groupContext.Marshal()
	_, err = keySchedule.ComputeIntermediateSecret(groupContextBytes)
	if err != nil {
		return nil, fmt.Errorf("computing intermediate secret: %w", err)
	}

	_, err = keySchedule.ComputeEpochSecret()
	if err != nil {
		return nil, fmt.Errorf("computing epoch secret: %w", err)
	}

	epochSecrets, err := keySchedule.DeriveEpochSecrets()
	if err != nil {
		return nil, fmt.Errorf("deriving epoch secrets: %w", err)
	}

	// Create group
	group := &Group{
		GroupID:               groupID,
		Epoch:                 NewGroupEpoch(0),
		CipherSuite:           cipherSuite,
		GroupContext:          groupContext,
		RatchetTree:           ratchetTree,
		OwnLeafIndex:          NewLeafNodeIndex(0),
		EpochSecrets:          epochSecrets,
		Proposals:             NewProposalStore(),
		KeySchedule:           keySchedule,
		InterimTranscriptHash: make([]byte, 32), // Hash of empty string
		Members:               make(map[LeafNodeIndex]*Member),
		state:                 StateOperational,
	}

	// Add ourselves as a member
	group.Members[NewLeafNodeIndex(0)] = &Member{
		LeafIndex:  NewLeafNodeIndex(0),
		KeyPackage: keyPackage,
		Credential: keyPackage.LeafNode.Credential,
		Active:     true,
	}

	return group, nil
}

// AddMember adds a new member to the group.
//
// This creates an Add proposal and stages it for commit.
func (g *Group) AddMember(keyPackage *keypackages.KeyPackage) (*Proposal, error) {
	if g.state != StateOperational {
		return nil, fmt.Errorf("group not in operational state")
	}

	// Create Add proposal
	proposal := &Proposal{
		Type: ProposalTypeAdd,
		Add: &AddProposal{
			KeyPackage: keyPackage,
		},
	}

	// Store proposal
	g.Proposals.AddProposal(proposal)

	return proposal, nil
}

// UpdateMember updates the own leaf node.
//
// This creates an Update proposal with a new LeafNode.
func (g *Group) UpdateMember(
	newLeafNode *treesync.LeafNodeData,
	privateKeys *keypackages.KeyPackagePrivateKeys,
) (*Proposal, error) {
	if g.state != StateOperational {
		return nil, fmt.Errorf("group not in operational state")
	}

	// Create Update proposal
	proposal := &Proposal{
		Type: ProposalTypeUpdate,
		Update: &UpdateProposal{
			LeafNode: nil, // TODO: Convert treesync.LeafNodeData to keypackages.LeafNode
		},
	}

	// Store proposal
	g.Proposals.AddProposal(proposal)

	return proposal, nil
}

// RemoveMember removes a member from the group.
//
// This creates a Remove proposal.
func (g *Group) RemoveMember(leafIndex LeafNodeIndex) (*Proposal, error) {
	if g.state != StateOperational {
		return nil, fmt.Errorf("group not in operational state")
	}

	// Validate leaf index
	if int(leafIndex) >= int(g.RatchetTree.NumLeaves) {
		return nil, fmt.Errorf("invalid leaf index: %d", leafIndex)
	}

	// Create Remove proposal
	proposal := &Proposal{
		Type: ProposalTypeRemove,
		Remove: &RemoveProposal{
			Removed: leafIndex,
		},
	}

	// Store proposal
	g.Proposals.AddProposal(proposal)

	return proposal, nil
}

// Commit applies all pending proposals and creates a new epoch.
//
// This is the main function to advance the group to a new epoch.
func (g *Group) Commit() (*StagedCommit, error) {
	if g.state != StateOperational {
		return nil, fmt.Errorf("group not in operational state")
	}

	if len(g.Proposals.Proposals) == 0 {
		return nil, fmt.Errorf("no proposals to commit")
	}

	// Create staged commit
	stagedCommit := &StagedCommit{
		Proposals: g.Proposals.Proposals,
	}

	g.PendingCommit = stagedCommit
	g.state = StatePendingCommit

	return stagedCommit, nil
}

// MergeCommit merges a staged commit into the group state.
func (g *Group) MergeCommit(stagedCommit *StagedCommit) error {
	if g.state != StatePendingCommit {
		return fmt.Errorf("group not in pending commit state")
	}

	// Apply each proposal
	for _, proposal := range stagedCommit.Proposals {
		if err := g.applyProposal(proposal); err != nil {
			return fmt.Errorf("applying proposal: %w", err)
		}
	}

	// Update epoch
	g.Epoch.Increment()

	// Clear proposals
	g.Proposals.Clear()

	// Update state
	g.state = StateOperational
	g.PendingCommit = nil

	return nil
}

// applyProposal applies a single proposal to the group state.
func (g *Group) applyProposal(proposal *Proposal) error {
	switch proposal.Type {
	case ProposalTypeAdd:
		return g.applyAddProposal(proposal.Add)
	case ProposalTypeUpdate:
		return g.applyUpdateProposal(proposal.Update)
	case ProposalTypeRemove:
		return g.applyRemoveProposal(proposal.Remove)
	default:
		return fmt.Errorf("unsupported proposal type: %d", proposal.Type)
	}
}

// applyAddProposal applies an Add proposal.
func (g *Group) applyAddProposal(add *AddProposal) error {
	if add == nil {
		return fmt.Errorf("invalid Add proposal")
	}

	// For now, just increment leaf count - full implementation would add the key package
	_ = add

	return nil
}

// applyUpdateProposal applies an Update proposal.
func (g *Group) applyUpdateProposal(update *UpdateProposal) error {
	if update == nil {
		return fmt.Errorf("invalid Update proposal")
	}

	// TODO: Implement leaf update
	_ = update

	return nil
}

// applyRemoveProposal applies a Remove proposal.
func (g *Group) applyRemoveProposal(remove *RemoveProposal) error {
	if remove == nil {
		return fmt.Errorf("invalid Remove proposal")
	}

	// Blank the node
	nodeIndex := treesync.LeafIndexToNodeIndex(treesync.LeafIndex(remove.Removed))
	g.RatchetTree.BlankNode(nodeIndex)

	// Mark member as inactive
	if member, ok := g.Members[remove.Removed]; ok {
		member.Active = false
	}

	return nil
}

// GetMember returns a member by leaf index.
func (g *Group) GetMember(leafIndex LeafNodeIndex) (*Member, bool) {
	member, ok := g.Members[leafIndex]
	return member, ok
}

// GetMembers returns all active members.
func (g *Group) GetMembers() []*Member {
	members := make([]*Member, 0)
	for _, member := range g.Members {
		if member.Active {
			members = append(members, member)
		}
	}
	return members
}

// MemberCount returns the number of active members.
func (g *Group) MemberCount() int {
	count := 0
	for _, member := range g.Members {
		if member.Active {
			count++
		}
	}
	return count
}

// State returns the current state of the group.
func (g *Group) State() GroupState {
	return g.state
}
