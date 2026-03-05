package group

import (
	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/internal/tls"
)

// Commit represents an MLS Commit message (RFC 9420 §12.4).
//
//	struct {
//	    ProposalOrRef proposals<V>;
//	    optional<UpdatePath> path;
//	} Commit;
type Commit struct {
	Proposals []ProposalOrRef
	Path      *UpdatePath
}

// UpdatePath represents the update path in a Commit.
//
//	struct {
//	    LeafNode leaf_node;
//	    UpdatePathNode nodes<V>;
//	} UpdatePath;
type UpdatePath struct {
	LeafNode *LeafNode
	Nodes    []UpdatePathNode
}

// UpdatePathNode represents a node in the update path.
type UpdatePathNode struct {
	EncryptionKey        []byte
	EncryptedPathSecrets []ciphersuite.HpkeCiphertext
}

// StagedCommit represents a commit that has been staged but not yet merged.
type StagedCommit struct {
	Commit    *Commit
	Proposals []*Proposal
}

// ConfirmationTag represents the confirmation tag in a commit.
type ConfirmationTag struct {
	Value []byte
}

// Marshal serializes the Commit to TLS format.
func (c *Commit) Marshal() []byte {
	w := tls.NewWriter()
	// Proposals
	propBuf := tls.NewWriter()
	for _, por := range c.Proposals {
		if por.Proposal != nil {
			// Serialize proposal (simplified)
			propBuf.WriteUint8(0x01) // Proposal present
		} else {
			propBuf.WriteVLBytes(por.ProposalRef)
		}
	}
	w.WriteVLBytes(propBuf.Bytes())
	// Path (optional)
	if c.Path != nil {
		w.WriteUint8(0x01)
		// Serialize path (simplified)
	} else {
		w.WriteUint8(0x00)
	}
	return w.Bytes()
}

// UnmarshalCommit deserializes a Commit from TLS format.
func UnmarshalCommit(data []byte) (*Commit, error) {
	r := tls.NewReader(data)

	commit := &Commit{
		Proposals: make([]ProposalOrRef, 0),
	}

	// Read proposals (variable-length vector)
	proposalsData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	if len(proposalsData) > 0 {
		propReader := tls.NewReader(proposalsData)
		for propReader.Remaining() > 0 {
			// Read proposal type/indicator
			propType, err := propReader.ReadUint8()
			if err != nil {
				break
			}

			if propType == 0x01 {
				// Proposal present (simplified - full deserialization would need Proposal type)
				// For now, skip the proposal data
			} else {
				// ProposalRef
				ref, err := propReader.ReadVLBytes()
				if err != nil {
					return nil, err
				}
				commit.Proposals = append(commit.Proposals, ProposalOrRef{
					ProposalRef: ref,
				})
			}
		}
	}

	// Read optional path
	pathPresent, err := r.ReadUint8()
	if err != nil {
		return nil, err
	}

	if pathPresent == 0x01 {
		// Path is present (simplified - would need full UpdatePath deserialization)
		commit.Path = &UpdatePath{}
	}

	return commit, nil
}
