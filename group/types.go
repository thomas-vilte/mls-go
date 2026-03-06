package group

import (
	"github.com/openmls/go/credentials"
	"github.com/openmls/go/internal/tls"
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

// Marshal serializes the LeafNode to TLS format.
func (ln *LeafNode) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteUint32(uint32(ln.Index))
	w.WriteVLBytes(ln.EncryptionKey)
	w.WriteVLBytes(ln.SignatureKey)
	w.WriteVLBytes(ln.Credential.Marshal())
	return w.Bytes()
}

// UnmarshalLeafNode deserializes a LeafNode from TLS format.
func UnmarshalLeafNode(data []byte) (*LeafNode, error) {
	r := tls.NewReader(data)

	index, err := r.ReadUint32()
	if err != nil {
		return nil, err
	}

	encKey, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	sigKey, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	credData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	credential, err := credentials.UnmarshalCredential(credData)
	if err != nil {
		return nil, err
	}

	return &LeafNode{
		Index:         LeafNodeIndex(index),
		EncryptionKey: encKey,
		SignatureKey:  sigKey,
		Credential:    credential,
	}, nil
}

// ProposalMarshal serializes a Proposal to TLS format.
func ProposalMarshal(p *Proposal) []byte {
	w := tls.NewWriter()
	w.WriteUint16(uint16(p.Type))

	switch p.Type {
	case ProposalTypeAdd:
		if p.Add != nil {
			w.WriteVLBytes(p.Add.KeyPackage.Marshal())
		}
	case ProposalTypeUpdate:
		if p.Update != nil {
			w.WriteVLBytes(p.Update.LeafNode.Marshal())
		}
	case ProposalTypeRemove:
		if p.Remove != nil {
			w.WriteUint32(uint32(p.Remove.Removed))
		}
		// ... otros casos
	}

	return w.Bytes()
}

// UnmarshalProposal deserializes a Proposal from TLS format.
func UnmarshalProposal(data []byte) (*Proposal, error) {
	r := tls.NewReader(data)

	propType, err := r.ReadUint16()
	if err != nil {
		return nil, err
	}

	proposal := &Proposal{
		Type: ProposalType(propType),
	}

	switch proposal.Type {
	case ProposalTypeAdd:
		kpData, err := r.ReadVLBytes()
		if err != nil {
			return nil, err
		}
		kp, err := keypackages.UnmarshalKeyPackage(kpData)
		if err != nil {
			return nil, err
		}
		proposal.Add = &AddProposal{KeyPackage: kp}
	case ProposalTypeUpdate:
		lnData, err := r.ReadVLBytes()
		if err != nil {
			return nil, err
		}
		ln, err := keypackages.UnmarshalLeafNode(lnData)
		if err != nil {
			return nil, err
		}
		proposal.Update = &UpdateProposal{LeafNode: ln}
	case ProposalTypeRemove:
		removed, err := r.ReadUint32()
		if err != nil {
			return nil, err
		}
		proposal.Remove = &RemoveProposal{Removed: LeafNodeIndex(removed)}
	}

	return proposal, nil
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
