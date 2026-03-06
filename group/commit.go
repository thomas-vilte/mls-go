package group

import (
	"fmt"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/internal/tls"
)

// ProposalOrRefType - RFC 9420 §12.4
type ProposalOrRefType uint8

const (
	ProposalOrRefTypeProposal  ProposalOrRefType = 1
	ProposalOrRefTypeReference ProposalOrRefType = 2
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

func (up *UpdatePath) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteVLBytes(up.LeafNode.Marshal())

	nodesBuf := tls.NewWriter()
	for _, node := range up.Nodes {
		nodesBuf.WriteVLBytes(node.Marshal())
	}
	w.WriteVLBytes(nodesBuf.Bytes())

	return w.Bytes()
}

func UnmarshalUpdatePath(data []byte) (*UpdatePath, error) {
	r := tls.NewReader(data)

	leafData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	leafNode, err := UnmarshalLeafNode(leafData)
	if err != nil {
		return nil, err
	}

	nodesData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	var nodes []UpdatePathNode
	nodesReader := tls.NewReader(nodesData)
	for nodesReader.Remaining() > 0 {
		nodeData, err := nodesReader.ReadVLBytes()
		if err != nil {
			break
		}
		node, err := UnmarshalUpdatePathNode(nodeData)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, *node)
	}

	return &UpdatePath{
		LeafNode: leafNode,
		Nodes:    nodes,
	}, nil
}

// UpdatePathNode represents a node in the update path.
type UpdatePathNode struct {
	EncryptionKey        []byte
	EncryptedPathSecrets []ciphersuite.HpkeCiphertext
}

func (upn *UpdatePathNode) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteVLBytes(upn.EncryptionKey)

	// Vector de HPKE ciphertexts
	secretsBuf := tls.NewWriter()
	for _, ct := range upn.EncryptedPathSecrets {
		// Manual serialization of HpkeCiphertext
		ctBuf := tls.NewWriter()
		ctBuf.WriteVLBytes(ct.KEMOutput)
		ctBuf.WriteVLBytes(ct.Ciphertext)
		secretsBuf.WriteVLBytes(ctBuf.Bytes())
	}
	w.WriteVLBytes(secretsBuf.Bytes())

	return w.Bytes()
}

func UnmarshalUpdatePathNode(data []byte) (*UpdatePathNode, error) {
	r := tls.NewReader(data)

	encKey, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	secretsData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	var secrets []ciphersuite.HpkeCiphertext
	secretsReader := tls.NewReader(secretsData)
	for secretsReader.Remaining() > 0 {
		ctData, err := secretsReader.ReadVLBytes()
		if err != nil {
			break
		}
		// Manual deserialization of HpkeCiphertext
		ctReader := tls.NewReader(ctData)
		kemOutput, err := ctReader.ReadVLBytes()
		if err != nil {
			return nil, err
		}
		ciphertext, err := ctReader.ReadVLBytes()
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, ciphersuite.HpkeCiphertext{
			KEMOutput:  kemOutput,
			Ciphertext: ciphertext,
		})
	}

	return &UpdatePathNode{
		EncryptionKey:        encKey,
		EncryptedPathSecrets: secrets,
	}, nil
}

// StagedCommit representa un commit preparado para ser mergeado
type StagedCommit struct {
	Commit             *Commit
	Proposals          []*Proposal
	WireFormat         uint16 // Necesario para transcript hash
	FramedContentBytes []byte // Serialized FramedContent
	Signature          []byte
	ConfirmationTag    []byte
	RootPathSecret     *ciphersuite.Secret // Para avanzar key schedule
}

// ConfirmationTag represents the confirmation tag in a commit.
type ConfirmationTag struct {
	Value []byte
}

// Marshal serializes the Commit to TLS format con encoding correcto de ProposalOrRef.
func (c *Commit) Marshal() []byte {
	w := tls.NewWriter()

	// Proposals vector
	propBuf := tls.NewWriter()
	for _, por := range c.Proposals {
		if por.Proposal != nil {
			// Proposal inline: type = 1
			propBuf.WriteUint8(uint8(ProposalOrRefTypeProposal))
			propBuf.WriteVLBytes(ProposalMarshal(por.Proposal))
		} else {
			// Reference: type = 2
			propBuf.WriteUint8(uint8(ProposalOrRefTypeReference))
			propBuf.WriteVLBytes(por.ProposalRef)
		}
	}
	w.WriteVLBytes(propBuf.Bytes())

	// Path (optional)
	if c.Path != nil {
		w.WriteUint8(1)
		w.WriteVLBytes(c.Path.Marshal())
	} else {
		w.WriteUint8(0)
	}

	return w.Bytes()
}

// UnmarshalCommit deserializes a Commit from TLS format con encoding correcto.
func UnmarshalCommit(data []byte) (*Commit, error) {
	r := tls.NewReader(data)

	commit := &Commit{
		Proposals: make([]ProposalOrRef, 0),
	}

	// Read proposals
	proposalsData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	if len(proposalsData) > 0 {
		propReader := tls.NewReader(proposalsData)
		for propReader.Remaining() > 0 {
			porType, err := propReader.ReadUint8()
			if err != nil {
				break
			}

			switch ProposalOrRefType(porType) {
			case ProposalOrRefTypeProposal:
				propData, err := propReader.ReadVLBytes()
				if err != nil {
					return nil, err
				}
				proposal, err := UnmarshalProposal(propData)
				if err != nil {
					return nil, err
				}
				commit.Proposals = append(commit.Proposals, ProposalOrRef{
					Proposal: proposal,
				})

			case ProposalOrRefTypeReference:
				ref, err := propReader.ReadVLBytes()
				if err != nil {
					return nil, err
				}
				commit.Proposals = append(commit.Proposals, ProposalOrRef{
					ProposalRef: ref,
				})

			default:
				return nil, fmt.Errorf("unknown ProposalOrRefType: %d", porType)
			}
		}
	}

	// Read optional path
	pathPresent, err := r.ReadUint8()
	if err != nil {
		return nil, err
	}

	if pathPresent == 1 {
		pathData, err := r.ReadVLBytes()
		if err != nil {
			return nil, err
		}
		path, err := UnmarshalUpdatePath(pathData)
		if err != nil {
			return nil, err
		}
		commit.Path = path
	}

	return commit, nil
}
