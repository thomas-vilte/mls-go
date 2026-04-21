package mls

import (
	"context"

	"github.com/thomas-vilte/mls-go/group"
)

// ProposalPolicy is a hook that allows applications to review proposals
// before they are stored in the group state.
type ProposalPolicy interface {
	ReviewProposal(ctx context.Context, snapshot GroupSnapshot, proposal ReviewableProposal) error
}

// GroupSnapshot provides a read-only view of group state for policy decisions.
type GroupSnapshot interface {
	Epoch() uint64
	MemberCount() int
	MemberIdentities() [][]byte
	Extensions() []group.Extension
}

// ReviewableProposal represents a proposal being reviewed by policy hooks.
type ReviewableProposal struct {
	Type   group.ProposalType
	Sender []byte
	Add    *AddProposalInfo
	Remove *RemoveProposalInfo
}

// AddProposalInfo contains information about an Add proposal.
type AddProposalInfo struct {
	KeyPackage []byte
	Identity   []byte
}

// RemoveProposalInfo contains information about a Remove proposal.
type RemoveProposalInfo struct {
	RemovedIndex uint32
	Identity     []byte
}

// ProposalPolicyRegistry manages proposal policy hooks.
type ProposalPolicyRegistry struct {
	policies []ProposalPolicy
}

// NewProposalPolicyRegistry creates a new proposal policy registry.
func NewProposalPolicyRegistry() *ProposalPolicyRegistry {
	return &ProposalPolicyRegistry{
		policies: make([]ProposalPolicy, 0),
	}
}

// Register adds a proposal policy to the registry.
// Register adds a proposal policy to the registry.
func (r *ProposalPolicyRegistry) Register(p ProposalPolicy) {
	if r == nil || p == nil {
		return
	}
	r.policies = append(r.policies, p)
}

// ReviewProposal runs all registered policy hooks against a proposal.
func (r *ProposalPolicyRegistry) ReviewProposal(ctx context.Context, snap GroupSnapshot, prop ReviewableProposal) error {
	if r == nil {
		return nil
	}
	for _, p := range r.policies {
		if err := p.ReviewProposal(ctx, snap, prop); err != nil {
			return err
		}
	}
	return nil
}
