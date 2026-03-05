package group

import (
	"github.com/openmls/go/credentials"
	keypackages "github.com/openmls/go/key_packages"
)

// ProposalType identifies the type of proposal.
type ProposalType uint16

// LeafNodeIndex identifies a member's position in the ratchet tree.
type LeafNodeIndex uint32

// NewLeafNodeIndex creates a leaf node index.
func NewLeafNodeIndex(index uint32) LeafNodeIndex {
	return LeafNodeIndex(index)
}

// Extension represents an MLS extension.
type Extension struct {
	Type uint16
	Data []byte
}

// ProposalOrRef represents a proposal or a reference to a proposal.
type ProposalOrRef struct {
	Proposal    *Proposal
	ProposalRef []byte
}

// Proposal represents an MLS proposal.
type Proposal struct {
	Type                   ProposalType
	Add                    *AddProposal
	Update                 *UpdateProposal
	Remove                 *RemoveProposal
	PreSharedKey           *PreSharedKeyProposal
	ReInit                 *ReInitProposal
	ExternalInit           *ExternalInitProposal
	GroupContextExtensions *GroupContextExtensionsProposal
}

// LeafNode represents a node in the ratchet tree.
type LeafNode struct {
	Index         LeafNodeIndex
	EncryptionKey []byte
	SignatureKey  []byte
	Credential    *credentials.Credential
}

// GroupState represents the operational state of a group.
type GroupState int

const (
	StateOperational GroupState = iota
	StatePendingCommit
	StateInactive
)

// ProposalStore stores pending proposals.
type ProposalStore struct {
	Proposals []*Proposal
}

// NewProposalStore creates a new proposal store.
func NewProposalStore() *ProposalStore {
	return &ProposalStore{
		Proposals: make([]*Proposal, 0),
	}
}

// AddProposal adds a proposal to the store.
func (ps *ProposalStore) AddProposal(proposal *Proposal) {
	ps.Proposals = append(ps.Proposals, proposal)
}

// Clear clears all proposals.
func (ps *ProposalStore) Clear() {
	ps.Proposals = make([]*Proposal, 0)
}

// Member represents a group member.
type Member struct {
	LeafIndex  LeafNodeIndex
	KeyPackage *keypackages.KeyPackage
	Credential *credentials.Credential
	Active     bool
}
