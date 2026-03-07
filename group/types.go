package group

import (
	"github.com/openmls/go/credentials"
	"github.com/openmls/go/internal/tls"
	keypackages "github.com/openmls/go/keypackages"
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
	case ProposalTypePreSharedKey:
		if p.PreSharedKey != nil {
			w.WriteUint8(p.PreSharedKey.PskType)
			w.WriteVLBytes(p.PreSharedKey.PskID.ID)
		}
	case ProposalTypeReInit:
		if p.ReInit != nil {
			w.WriteVLBytes(p.ReInit.GroupID)
			w.WriteUint16(uint16(p.ReInit.Version))
			w.WriteUint16(uint16(p.ReInit.CipherSuite))
			extBuf := tls.NewWriter()
			for _, ext := range p.ReInit.Extensions {
				extBuf.WriteUint16(ext.Type)
				extBuf.WriteVLBytes(ext.Data)
			}
			w.WriteVLBytes(extBuf.Bytes())
		}
	case ProposalTypeExternalInit:
		if p.ExternalInit != nil {
			w.WriteVLBytes(p.ExternalInit.KemOutput)
		}
	case ProposalTypeGroupContextExtensions:
		if p.GroupContextExtensions != nil {
			extBuf := tls.NewWriter()
			for _, ext := range p.GroupContextExtensions.Extensions {
				extBuf.WriteUint16(ext.Type)
				extBuf.WriteVLBytes(ext.Data)
			}
			w.WriteVLBytes(extBuf.Bytes())
		}
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
	case ProposalTypePreSharedKey:
		pskType, err := r.ReadUint8()
		if err != nil {
			return nil, err
		}
		pskID, err := r.ReadVLBytes()
		if err != nil {
			return nil, err
		}
		proposal.PreSharedKey = &PreSharedKeyProposal{
			PskType: pskType,
			PskID:   PskID{PskType: pskType, ID: pskID},
		}
	case ProposalTypeReInit:
		groupID, err := r.ReadVLBytes()
		if err != nil {
			return nil, err
		}
		version, err := r.ReadUint16()
		if err != nil {
			return nil, err
		}
		cs, err := r.ReadUint16()
		if err != nil {
			return nil, err
		}
		extData, err := r.ReadVLBytes()
		if err != nil {
			return nil, err
		}
		exts, _ := parseExtensions(extData)
		proposal.ReInit = &ReInitProposal{
			GroupID:     groupID,
			Version:     keypackages.ProtocolVersion(version),
			CipherSuite: keypackages.CipherSuite(cs),
			Extensions:  exts,
		}
	case ProposalTypeExternalInit:
		kemOutput, err := r.ReadVLBytes()
		if err != nil {
			return nil, err
		}
		proposal.ExternalInit = &ExternalInitProposal{KemOutput: kemOutput}
	case ProposalTypeGroupContextExtensions:
		extData, err := r.ReadVLBytes()
		if err != nil {
			return nil, err
		}
		exts, _ := parseExtensions(extData)
		proposal.GroupContextExtensions = &GroupContextExtensionsProposal{Extensions: exts}
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
	Proposals []StoredProposal
}

// NewProposalStore creates a new proposal store.
func NewProposalStore() *ProposalStore {
	return &ProposalStore{
		Proposals: make([]StoredProposal, 0),
	}
}

// AddProposal adds a proposal to the store.
func (ps *ProposalStore) AddProposal(proposal *Proposal, sender LeafNodeIndex) {
	ps.Proposals = append(ps.Proposals, StoredProposal{Proposal: proposal, Sender: sender})
}

// Clear clears all proposals.
func (ps *ProposalStore) Clear() {
	ps.Proposals = make([]StoredProposal, 0)
}

// Member represents a group member.
type Member struct {
	LeafIndex  LeafNodeIndex
	KeyPackage *keypackages.KeyPackage
	Credential *credentials.Credential
	Active     bool
}

// StoredProposal guarda un proposal junto con el indice de hoja de quien lo envio
type StoredProposal struct {
	Proposal *Proposal
	Sender   LeafNodeIndex
}
