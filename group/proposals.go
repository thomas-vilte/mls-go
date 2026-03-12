package group

import (
	"errors"

	"github.com/mls-go/keypackages"
)

// All proposal types according to RFC 9420 §12.1
const (
	ProposalTypeAdd                    ProposalType = 0x0001
	ProposalTypeUpdate                 ProposalType = 0x0002
	ProposalTypeRemove                 ProposalType = 0x0003
	ProposalTypePreSharedKey           ProposalType = 0x0004
	ProposalTypeReInit                 ProposalType = 0x0005
	ProposalTypeExternalInit           ProposalType = 0x0006
	ProposalTypeGroupContextExtensions ProposalType = 0x0007
)

// AddProposal - RFC 9420 §12.1.1
type AddProposal struct {
	KeyPackage *keypackages.KeyPackage
}

// UpdateProposal - RFC 9420 §12.1.2
type UpdateProposal struct {
	LeafNode *keypackages.LeafNode
}

// RemoveProposal - RFC 9420 §12.1.3
type RemoveProposal struct {
	Removed LeafNodeIndex
}

// PreSharedKeyProposal - RFC 9420 §12.1.4
type PreSharedKeyProposal struct {
	PskType uint8
	PskID   PskID
}

// PskID represents a pre-shared key identifier (RFC 9420 §8.4 PreSharedKeyID).
//
//	struct {
//	    PSKType psktype;
//	    select (PreSharedKeyID.psktype) {
//	        case external:
//	            opaque psk_id<V>;
//	        case resumption:
//	            ResumptionPSKUsage usage;
//	            opaque psk_group_id<V>;
//	            uint64 psk_epoch;
//	    };
//	    opaque psk_nonce<V>;
//	} PreSharedKeyID;
type PskID struct {
	PskType uint8
	// External PSK fields (PskType == 1)
	ID []byte
	// Resumption PSK fields (PskType == 2)
	Usage      uint8
	PskGroupID []byte
	PskEpoch   uint64
	// Common
	Nonce []byte
}

// ReInitProposal - RFC 9420 §12.1.5
type ReInitProposal struct {
	GroupID       []byte
	Version       keypackages.ProtocolVersion
	CipherSuite   keypackages.CipherSuite
	Extensions    []Extension
	Confirmations []Confirmation
}

// Confirmation for ReInit
type Confirmation struct {
	LeafIndex LeafNodeIndex
	Tag       []byte
}

// ExternalInitProposal - RFC 9420 §12.1.6
//
//	struct {
//	    opaque kem_output<V>;
//	} ExternalInit;
type ExternalInitProposal struct {
	KemOutput []byte
}

// GroupContextExtensionsProposal - RFC 9420 §12.1.7
type GroupContextExtensionsProposal struct {
	Extensions []Extension
}

// ExternalProposal - RFC 9420 §12.1.8
type ExternalProposal struct {
	Proposal     *Proposal
	Confirmation []byte
}

// Helper functions

// NewAddProposal creates a new Add proposal.
func NewAddProposal(keyPackage *keypackages.KeyPackage) *Proposal {
	return &Proposal{
		Type: ProposalTypeAdd,
		Add: &AddProposal{
			KeyPackage: keyPackage,
		},
	}
}

// NewUpdateProposal creates a new Update proposal.
func NewUpdateProposal(leafNode *keypackages.LeafNode) *Proposal {
	return &Proposal{
		Type: ProposalTypeUpdate,
		Update: &UpdateProposal{
			LeafNode: leafNode,
		},
	}
}

// NewRemoveProposal creates a new Remove proposal.
func NewRemoveProposal(leafIndex LeafNodeIndex) *Proposal {
	return &Proposal{
		Type: ProposalTypeRemove,
		Remove: &RemoveProposal{
			Removed: leafIndex,
		},
	}
}

// NewPreSharedKeyProposal creates a new PreSharedKey proposal.
func NewPreSharedKeyProposal(pskType uint8, pskID []byte) *Proposal {
	return &Proposal{
		Type: ProposalTypePreSharedKey,
		PreSharedKey: &PreSharedKeyProposal{
			PskType: pskType,
			PskID: PskID{
				PskType: pskType,
				ID:      pskID,
			},
		},
	}
}

// NewReInitProposal creates a new ReInit proposal.
func NewReInitProposal(
	groupID []byte,
	version keypackages.ProtocolVersion,
	cipherSuite keypackages.CipherSuite,
	extensions []Extension,
) *Proposal {
	return &Proposal{
		Type: ProposalTypeReInit,
		ReInit: &ReInitProposal{
			GroupID:     groupID,
			Version:     version,
			CipherSuite: cipherSuite,
			Extensions:  extensions,
		},
	}
}

// NewExternalInitProposal creates a new ExternalInit proposal.
func NewExternalInitProposal(kemOutput []byte) *Proposal {
	return &Proposal{
		Type: ProposalTypeExternalInit,
		ExternalInit: &ExternalInitProposal{
			KemOutput: kemOutput,
		},
	}
}

// NewGroupContextExtensionsProposal creates a new GroupContextExtensions proposal.
func NewGroupContextExtensionsProposal(extensions []Extension) *Proposal {
	return &Proposal{
		Type: ProposalTypeGroupContextExtensions,
		GroupContextExtensions: &GroupContextExtensionsProposal{
			Extensions: extensions,
		},
	}
}

// ValidateProposal validates a proposal according to RFC 9420 §12.2.
func ValidateProposal(proposal *Proposal, capabilities *keypackages.Capabilities) error {
	if proposal == nil {
		return ErrNilProposal
	}

	// Check if proposal type is supported
	if !isProposalTypeSupported(proposal.Type, capabilities) {
		return ErrUnsupportedProposalType
	}

	// Type-specific validation
	switch proposal.Type {
	case ProposalTypeAdd:
		return validateAddProposal(proposal.Add)
	case ProposalTypeUpdate:
		return validateUpdateProposal(proposal.Update)
	case ProposalTypeRemove:
		return validateRemoveProposal(proposal.Remove)
	case ProposalTypePreSharedKey:
		return validatePreSharedKeyProposal(proposal.PreSharedKey)
	case ProposalTypeReInit:
		return validateReInitProposal(proposal.ReInit)
	case ProposalTypeExternalInit:
		return validateExternalInitProposal(proposal.ExternalInit)
	case ProposalTypeGroupContextExtensions:
		return validateGroupContextExtensionsProposal(proposal.GroupContextExtensions)
	default:
		return ErrUnknownProposalType
	}
}

func isProposalTypeSupported(proposalType ProposalType, capabilities *keypackages.Capabilities) bool {
	if capabilities == nil {
		// Default to supporting basic proposal types if no capabilities provided
		switch proposalType {
		case ProposalTypeAdd, ProposalTypeUpdate, ProposalTypeRemove:
			return true
		}
		return false
	}

	for _, supportedType := range capabilities.Proposals {
		if uint16(proposalType) == supportedType {
			return true
		}
	}

	return false
}

func validateAddProposal(add *AddProposal) error {
	if add == nil {
		return ErrNilAddProposal
	}
	if add.KeyPackage == nil {
		return ErrNilKeyPackage
	}
	return add.KeyPackage.Validate()
}

func validateUpdateProposal(update *UpdateProposal) error {
	if update == nil {
		return ErrNilUpdateProposal
	}
	if update.LeafNode == nil {
		return ErrNilLeafNode
	}
	return update.LeafNode.Validate()
}

func validateRemoveProposal(remove *RemoveProposal) error {
	if remove == nil {
		return ErrNilRemoveProposal
	}
	// Leaf index validation would go here
	return nil
}

func validatePreSharedKeyProposal(psk *PreSharedKeyProposal) error {
	if psk == nil {
		return ErrNilPreSharedKeyProposal
	}
	// PSK validation would go here
	return nil
}

func validateReInitProposal(reinit *ReInitProposal) error {
	if reinit == nil {
		return ErrNilReInitProposal
	}
	if len(reinit.GroupID) == 0 {
		return ErrEmptyGroupID
	}
	// More validation would go here
	return nil
}

func validateExternalInitProposal(ext *ExternalInitProposal) error {
	if ext == nil {
		return ErrNilExternalInitProposal
	}
	if len(ext.KemOutput) == 0 {
		return errors.New("kem_output is empty")
	}
	return nil
}

func validateGroupContextExtensionsProposal(ext *GroupContextExtensionsProposal) error {
	if ext == nil {
		return ErrNilGroupContextExtensionsProposal
	}
	// Extension validation would go here
	return nil
}
