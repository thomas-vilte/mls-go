package group

import (
	"bytes"
	"fmt"

	"github.com/thomas-vilte/mls-go/credentials"
	mlsext "github.com/thomas-vilte/mls-go/extensions"
	"github.com/thomas-vilte/mls-go/internal/tls"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// ProposalType identifies the type of MLS proposal per RFC 9420 §12.1.
//
// Proposal types are registered in the IANA MLS Registry.
type ProposalType uint16

// Proposal types defined in RFC 9420 §12.1.
const (
	// ProposalTypeAdd adds a new member to the group (RFC §12.1.1).
	ProposalTypeAdd ProposalType = 0x0001

	// ProposalTypeUpdate updates a member's leaf node (RFC §12.1.2).
	ProposalTypeUpdate ProposalType = 0x0002

	// ProposalTypeRemove removes a member from the group (RFC §12.1.3).
	ProposalTypeRemove ProposalType = 0x0003

	// ProposalTypePreSharedKey adds a PSK to the key schedule (RFC §12.1.4).
	ProposalTypePreSharedKey ProposalType = 0x0004

	// ProposalTypeReInit reinitializes the group with new parameters (RFC §12.1.5).
	ProposalTypeReInit ProposalType = 0x0005

	// ProposalTypeExternalInit allows external joiners to enter (RFC §12.1.6).
	ProposalTypeExternalInit ProposalType = 0x0006

	// ProposalTypeGroupContextExtensions updates group extensions (RFC §12.1.7).
	ProposalTypeGroupContextExtensions ProposalType = 0x0007
)

// LeafNodeIndex identifies a member's position in the ratchet tree (RFC §4).
//
// Leaf indices range from 0 to NumLeaves-1.
type LeafNodeIndex uint32

// NewLeafNodeIndex creates a leaf node index.
func NewLeafNodeIndex(index uint32) LeafNodeIndex {
	return LeafNodeIndex(index)
}

// Extension re-exports the canonical MLS extension type.
type Extension = mlsext.Extension

// ProposalOrRef represents either a full proposal or a reference to one (RFC §12.4).
//
// Used in Commit messages to reference proposals either by value or by hash.
type ProposalOrRef struct {
	Proposal    *Proposal
	ProposalRef []byte
}

// Proposal represents an MLS proposal per RFC 9420 §12.1.
//
// Proposals are operations that modify the group state. They are created,
// sent, and then committed in a Commit message to take effect.
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

// ProposalMarshal serializes a Proposal to TLS format per RFC 9420 §12.1.
//
// The encoding depends on the proposal type:
//
//   - Add: VL-prefixed KeyPackage
//   - Update: VL-prefixed LeafNode
//   - Remove: uint32 leaf index
//   - PreSharedKey: PskType + PskID fields
//   - ReInit: group_id + version + cipher_suite + extensions
//   - ExternalInit: VL-prefixed kem_output
//   - GroupContextExtensions: VL-prefixed extensions vector
func ProposalMarshal(p *Proposal) []byte {
	w := tls.NewWriter()
	w.WriteUint16(uint16(p.Type))

	switch p.Type {
	case ProposalTypeAdd:
		if p.Add != nil {
			// RFC 9420 §12.1.1: struct { KeyPackage key_package; } Add — inline, no VL wrapper
			w.WriteRaw(p.Add.KeyPackage.Marshal())
		}
	case ProposalTypeUpdate:
		if p.Update != nil {
			// RFC 9420 §12.1.2: struct { LeafNode leaf_node; } Update — inline, no VL wrapper
			w.WriteRaw(p.Update.LeafNode.Marshal())
		}
	case ProposalTypeRemove:
		if p.Remove != nil {
			w.WriteUint32(uint32(p.Remove.Removed))
		}
	case ProposalTypePreSharedKey:
		if p.PreSharedKey != nil {
			w.WriteUint8(p.PreSharedKey.PskType)
			if p.PreSharedKey.PskType == 2 { // resumption
				w.WriteUint8(p.PreSharedKey.PskID.Usage)
				w.WriteVLBytes(p.PreSharedKey.PskID.PskGroupID)
				w.WriteUint64(p.PreSharedKey.PskID.PskEpoch)
			} else { // external (1) or branch (3)
				w.WriteVLBytes(p.PreSharedKey.PskID.ID)
			}
			w.WriteVLBytes(p.PreSharedKey.PskID.Nonce)
		}
	case ProposalTypeReInit:
		if p.ReInit != nil {
			w.WriteVLBytes(p.ReInit.GroupID)
			w.WriteUint16(uint16(p.ReInit.Version))
			w.WriteUint16(uint16(p.ReInit.CipherSuite))
			extBuf := tls.NewWriter()
			for _, ext := range p.ReInit.Extensions {
				extBuf.WriteUint16(uint16(ext.Type))
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
				extBuf.WriteUint16(uint16(ext.Type))
				extBuf.WriteVLBytes(ext.Data)
			}
			w.WriteVLBytes(extBuf.Bytes())
		}
	}

	return w.Bytes()
}

// UnmarshalProposal deserializes a Proposal from TLS format per RFC 9420 §12.1.
func UnmarshalProposal(data []byte) (*Proposal, error) {
	r := tls.NewReader(data)

	propType, err := r.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("reading proposal type: %w", err)
	}

	proposal := &Proposal{
		Type: ProposalType(propType),
	}

	switch proposal.Type {
	case ProposalTypeAdd:
		pos := r.Position()
		kp, err := keypackages.UnmarshalKeyPackageFromReader(r)
		if err == nil && r.Remaining() == 0 {
			proposal.Add = &AddProposal{KeyPackage: kp}
			break
		}

		r.SetPosition(pos)
		kpData, err := r.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("parsing add proposal key package: %w", err)
		}
		kp, err = keypackages.UnmarshalKeyPackage(kpData)
		if err != nil {
			return nil, fmt.Errorf("parsing add proposal key package: %w", err)
		}
		proposal.Add = &AddProposal{KeyPackage: kp}

	case ProposalTypeUpdate:
		pos := r.Position()
		ln, err := keypackages.UnmarshalLeafNodeFromReader(r)
		if err == nil && r.Remaining() == 0 {
			proposal.Update = &UpdateProposal{LeafNode: ln}
			break
		}

		r.SetPosition(pos)
		lnData, err := r.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("parsing update proposal leaf node: %w", err)
		}
		ln, err = keypackages.UnmarshalLeafNode(lnData)
		if err != nil {
			return nil, fmt.Errorf("parsing update proposal leaf node: %w", err)
		}
		proposal.Update = &UpdateProposal{LeafNode: ln}

	case ProposalTypeRemove:
		removed, err := r.ReadUint32()
		if err != nil {
			return nil, fmt.Errorf("reading remove proposal index: %w", err)
		}
		proposal.Remove = &RemoveProposal{Removed: LeafNodeIndex(removed)}

	case ProposalTypePreSharedKey:
		pskType, err := r.ReadUint8()
		if err != nil {
			return nil, fmt.Errorf("reading PSK type: %w", err)
		}
		pskID := PskID{PskType: pskType}
		if pskType == 2 { // resumption
			usage, err := r.ReadUint8()
			if err != nil {
				return nil, fmt.Errorf("reading PSK usage: %w", err)
			}
			pskGroupID, err := r.ReadVLBytes()
			if err != nil {
				return nil, fmt.Errorf("reading PSK group ID: %w", err)
			}
			pskEpoch, err := r.ReadUint64()
			if err != nil {
				return nil, fmt.Errorf("reading PSK epoch: %w", err)
			}
			pskID.Usage = usage
			pskID.PskGroupID = pskGroupID
			pskID.PskEpoch = pskEpoch
		} else { // external (1) or branch (3)
			id, err := r.ReadVLBytes()
			if err != nil {
				return nil, fmt.Errorf("reading PSK ID: %w", err)
			}
			pskID.ID = id
		}
		pskNonce, err := r.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading PSK nonce: %w", err)
		}
		pskID.Nonce = pskNonce
		proposal.PreSharedKey = &PreSharedKeyProposal{
			PskType: pskType,
			PskID:   pskID,
		}

	case ProposalTypeReInit:
		groupID, err := r.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading reinit group ID: %w", err)
		}
		version, err := r.ReadUint16()
		if err != nil {
			return nil, fmt.Errorf("reading reinit version: %w", err)
		}
		cs, err := r.ReadUint16()
		if err != nil {
			return nil, fmt.Errorf("reading reinit cipher suite: %w", err)
		}
		extData, err := r.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading reinit extensions: %w", err)
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
			return nil, fmt.Errorf("reading external init KEM output: %w", err)
		}
		proposal.ExternalInit = &ExternalInitProposal{KemOutput: kemOutput}

	case ProposalTypeGroupContextExtensions:
		extData, err := r.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading group context extensions: %w", err)
		}
		exts, _ := parseExtensions(extData)
		proposal.GroupContextExtensions = &GroupContextExtensionsProposal{Extensions: exts}
	}

	return proposal, nil
}

// unmarshalProposalFromReader reads exactly one proposal from r, advancing r's
// position past all proposal bytes. Returns an error if the proposal is malformed.
// Used by decodeProposalBodyLength (body scanner) and parseProposalOrRefsCanonical.
func unmarshalProposalFromReader(r *tls.Reader) error {
	propType, err := r.ReadUint16()
	if err != nil {
		return fmt.Errorf("reading proposal type: %w", err)
	}
	return readProposalInlineBody(r, ProposalType(propType))
}

// readProposalInlineBody reads one proposal body from r based on the given type.
// Add and Update first try VL-wrapped (our format), then fall back to inline RFC format.
// Returns nil on success with r advanced past all proposal bytes.
func readProposalInlineBody(r *tls.Reader, propType ProposalType) error {
	switch propType {
	case ProposalTypeAdd:
		pos := r.Position()
		if _, err := keypackages.UnmarshalKeyPackageFromReader(r); err == nil {
			return nil
		}
		r.SetPosition(pos)
		kpData, err := r.ReadVLBytes()
		if err != nil {
			return fmt.Errorf("parsing add proposal: %w", err)
		}
		if _, err := keypackages.UnmarshalKeyPackage(kpData); err != nil {
			return fmt.Errorf("parsing add proposal: %w", err)
		}
		return nil

	case ProposalTypeUpdate:
		pos := r.Position()
		if _, err := keypackages.UnmarshalLeafNodeFromReader(r); err == nil {
			return nil
		}
		r.SetPosition(pos)
		lnData, err := r.ReadVLBytes()
		if err != nil {
			return fmt.Errorf("parsing update proposal: %w", err)
		}
		if _, err := keypackages.UnmarshalLeafNode(lnData); err != nil {
			return fmt.Errorf("parsing update proposal: %w", err)
		}
		return nil

	case ProposalTypeRemove:
		_, err := r.ReadUint32()
		return err

	case ProposalTypePreSharedKey:
		pskType, err := r.ReadUint8()
		if err != nil {
			return err
		}
		if pskType == 2 { // resumption
			if _, err := r.ReadUint8(); err != nil { // usage
				return err
			}
			if _, err := r.ReadVLBytes(); err != nil { // psk_group_id
				return err
			}
			if _, err := r.ReadUint64(); err != nil { // psk_epoch
				return err
			}
		} else { // external (1) or branch (3)
			if _, err := r.ReadVLBytes(); err != nil { // psk_id
				return err
			}
		}
		_, err = r.ReadVLBytes() // psk_nonce
		return err

	case ProposalTypeReInit:
		if _, err := r.ReadVLBytes(); err != nil {
			return err
		}
		if _, err := r.ReadUint16(); err != nil {
			return err
		}
		if _, err := r.ReadUint16(); err != nil {
			return err
		}
		_, err := r.ReadVLBytes()
		return err

	case ProposalTypeExternalInit, ProposalTypeGroupContextExtensions:
		_, err := r.ReadVLBytes()
		return err

	default:
		return fmt.Errorf("unknown proposal type: %d", propType)
	}
}

// GroupState represents the operational state of a group.
//
// The group transitions through states as operations occur:
//
//   - StateOperational: Normal operation, proposals can be created
//   - StatePendingCommit: A commit has been staged, awaiting merge
//   - StateInactive: Group has been reinitialized or terminated
type GroupState int

const (
	// StateOperational indicates the group is ready for operations.
	StateOperational GroupState = iota

	// StatePendingCommit indicates a commit is staged and awaiting merge.
	StatePendingCommit

	// StateInactive indicates the group is no longer active (ReInit occurred).
	StateInactive
)

// ProposalStore stores pending proposals for a group.
//
// Proposals are accumulated until they are committed or cleared.
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

// AddProposalWithRef adds a network-received proposal with its ProposalRef.
func (ps *ProposalStore) AddProposalWithRef(proposal *Proposal, sender LeafNodeIndex, ref []byte) {
	ps.Proposals = append(ps.Proposals, StoredProposal{Proposal: proposal, Sender: sender, Ref: ref})
}

// Clear clears all proposals.
func (ps *ProposalStore) Clear() {
	ps.Proposals = make([]StoredProposal, 0)
}

// RemoveByRef removes the first proposal with the given ProposalRef.
// Returns true if a proposal was found and removed, false otherwise.
func (ps *ProposalStore) RemoveByRef(ref []byte) bool {
	for i, sp := range ps.Proposals {
		// ProposalRef is a public hash/reference used for lookup, not secret material.
		if bytes.Equal(sp.Ref, ref) {
			ps.Proposals = append(ps.Proposals[:i], ps.Proposals[i+1:]...)
			return true
		}
	}
	return false
}

// Member represents a group member.
//
// Each member has a position in the ratchet tree (LeafIndex),
// a KeyPackage with their public keys, and a Credential with
// their identity information.
type Member struct {
	LeafIndex  LeafNodeIndex
	KeyPackage *keypackages.KeyPackage
	Credential *credentials.Credential
	Active     bool
}

// StoredProposal stores a proposal alongside the sender's leaf index.
type StoredProposal struct {
	Proposal *Proposal
	Sender   LeafNodeIndex
	// Ref is the ProposalRef bytes if this proposal was received from the network.
	// Nil for proposals generated locally by the committer.
	Ref []byte
}

// ExternalSender represents an allowed external sender per RFC 9420 §12.1.8.1.
//
// External senders can send proposals and commits without being group members.
// Their signing keys are listed in the ExternalSenders extension.
type ExternalSender struct {
	SignatureKey []byte
	Credential   *credentials.Credential
}

// parseExternalSenders deserializes an ExternalSenders extension payload.
//
// RFC 9420 §12.1.8.1: ExternalSender external_senders<V> — the data is
// a VL-prefixed vector of ExternalSender structs, each encoded as
// VL(signature_key) || Credential (inline TLS encoding, no extra VL wrapper).
func parseExternalSenders(data []byte) ([]ExternalSender, error) {
	r := tls.NewReader(data)
	innerBytes, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading external_senders vector: %w", err)
	}
	r2 := tls.NewReader(innerBytes)
	var senders []ExternalSender
	for r2.Remaining() > 0 {
		sigKey, err := r2.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading external sender signature key: %w", err)
		}
		cred, err := credentials.UnmarshalCredentialFromReader(r2)
		if err != nil {
			return nil, fmt.Errorf("parsing external sender credential: %w", err)
		}
		senders = append(senders, ExternalSender{SignatureKey: sigKey, Credential: cred})
	}
	return senders, nil
}
