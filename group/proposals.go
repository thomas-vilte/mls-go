package group

import (
	"fmt"

	"github.com/thomas-vilte/mls-go/keypackages"
)

// AddProposal adds a new member to the group per RFC 9420 §12.1.1.
//
// The KeyPackage contains the new member's identity, keys, and capabilities.
// When committed, the new member is added to the ratchet tree.
type AddProposal struct {
	KeyPackage *keypackages.KeyPackage
}

// UpdateProposal updates a member's leaf node per RFC 9420 §12.1.2.
//
// The sender updates their own leaf with new encryption keys, providing
// Post-Compromise Security for that member.
type UpdateProposal struct {
	LeafNode *keypackages.LeafNode
}

// RemoveProposal removes a member from the group per RFC 9420 §12.1.3.
//
// The specified leaf index is blanked in the ratchet tree, removing
// the member's ability to participate in the group.
type RemoveProposal struct {
	Removed LeafNodeIndex
}

// PreSharedKeyProposal adds a pre-shared key to the key schedule per RFC 9420 §12.1.4.
//
// PSKs provide additional entropy to the key schedule and can be used
// for external key agreement or group resumption.
type PreSharedKeyProposal struct {
	PskType uint8
	PskID   PskID
}

// PskID represents a pre-shared key identifier per RFC 9420 §8.4.
//
// ```text
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
//
// ```
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

// ReInitProposal reinitializes the group with new parameters per RFC 9420 §12.1.5.
//
// This allows changing the group's protocol version, cipher suite, or extensions
// while preserving the group's membership through resumption secrets.
type ReInitProposal struct {
	GroupID       []byte
	Version       keypackages.ProtocolVersion
	CipherSuite   keypackages.CipherSuite
	Extensions    []Extension
	Confirmations []Confirmation
}

// Confirmation contains a member's confirmation tag for ReInit per RFC 9420 §12.1.5.
type Confirmation struct {
	LeafIndex LeafNodeIndex
	Tag       []byte
}

// ExternalInitProposal allows external joiners to enter per RFC 9420 §12.1.6.
//
// The kem_output is the result of HPKE encapsulation to the group's external_pub.
//
// ```text
//
//	struct {
//	    opaque kem_output<V>;
//	} ExternalInit;
//
// ```
type ExternalInitProposal struct {
	KemOutput []byte
}

// GroupContextExtensionsProposal updates group extensions per RFC 9420 §12.1.7.
//
// This modifies the group's extensions in the GroupContext, affecting all members.
type GroupContextExtensionsProposal struct {
	Extensions []Extension
}

// ExternalProposal represents a proposal sent by an external sender per RFC 9420 §12.1.8.
//
// External senders can send proposals without being group members, as long as
// their signature keys are listed in the ExternalSenders extension.
type ExternalProposal struct {
	Proposal     *Proposal
	Confirmation []byte
}

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
//
// Validation includes checking proposal type support and proposal-specific constraints.
func ValidateProposal(proposal *Proposal, capabilities *keypackages.Capabilities) error {
	if proposal == nil {
		return ErrNilProposal
	}

	if !isProposalTypeSupported(proposal.Type, capabilities) {
		return ErrUnsupportedProposalType
	}

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

// isProposalTypeSupported checks if the proposal type is supported by the capabilities.
//
// RFC 9420 §7.2: an empty Proposals list is equivalent to supporting all
// default proposal types (Add, Update, Remove, PreSharedKey, ReInit,
// ExternalInit, GroupContextExtensions).
func isProposalTypeSupported(proposalType ProposalType, capabilities *keypackages.Capabilities) bool {
	// nil capabilities or an empty Proposals list → all standard types supported.
	if capabilities == nil || len(capabilities.Proposals) == 0 {
		switch proposalType {
		case ProposalTypeAdd, ProposalTypeUpdate, ProposalTypeRemove,
			ProposalTypePreSharedKey, ProposalTypeReInit,
			ProposalTypeExternalInit, ProposalTypeGroupContextExtensions:
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

// validateAddProposal validates an Add proposal.
func validateAddProposal(add *AddProposal) error {
	if add == nil {
		return ErrNilAddProposal
	}
	if add.KeyPackage == nil {
		return ErrNilKeyPackage
	}
	return add.KeyPackage.Validate()
}

// validateUpdateProposal validates an Update proposal.
func validateUpdateProposal(update *UpdateProposal) error {
	if update == nil {
		return ErrNilUpdateProposal
	}
	if update.LeafNode == nil {
		return ErrNilLeafNode
	}
	return update.LeafNode.Validate()
}

// validateRemoveProposal validates a Remove proposal.
func validateRemoveProposal(remove *RemoveProposal) error {
	if remove == nil {
		return ErrNilRemoveProposal
	}
	// Leaf index validation would require tree context
	return nil
}

// validatePreSharedKeyProposal validates a PreSharedKey proposal.
func validatePreSharedKeyProposal(psk *PreSharedKeyProposal) error {
	if psk == nil {
		return ErrNilPreSharedKeyProposal
	}
	// Additional PSK validation could be added here
	return nil
}

// validateReInitProposal validates a ReInit proposal.
func validateReInitProposal(reinit *ReInitProposal) error {
	if reinit == nil {
		return ErrNilReInitProposal
	}
	if len(reinit.GroupID) == 0 {
		return ErrEmptyGroupID
	}
	return nil
}

// validateExternalInitProposal validates an ExternalInit proposal.
func validateExternalInitProposal(ext *ExternalInitProposal) error {
	if ext == nil {
		return ErrNilExternalInitProposal
	}
	if len(ext.KemOutput) == 0 {
		return fmt.Errorf("group: KEM output is empty")
	}
	return nil
}

// validateGroupContextExtensionsProposal validates a GroupContextExtensions proposal.
func validateGroupContextExtensionsProposal(ext *GroupContextExtensionsProposal) error {
	if ext == nil {
		return ErrNilGroupContextExtensionsProposal
	}
	// Extension validation could be added here
	return nil
}
