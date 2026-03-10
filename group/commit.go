package group

import (
	"fmt"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/framing"
	"github.com/openmls/go/internal/tls"
	"github.com/openmls/go/schedule"
	"github.com/openmls/go/treesync"
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
	LeafNode *treesync.LeafNodeData
	Nodes    []UpdatePathNode
}

func (up *UpdatePath) Marshal() []byte {
	w := tls.NewWriter()
	// leaf_node is inline per RFC 9420 §12.4.1 (NOT VL-prefixed)
	w.WriteRaw(up.LeafNode.Marshal())

	nodesBuf := tls.NewWriter()
	for _, node := range up.Nodes {
		nodesBuf.WriteRaw(node.Marshal())
	}
	w.WriteVLBytes(nodesBuf.Bytes())

	return w.Bytes()
}

// unmarshalUpdatePathFromReader parses an UpdatePath inline from a TLS reader.
// leaf_node is inline (not VL-prefixed), nodes<V> is VL-prefixed (RFC 9420 §12.4.1).
func unmarshalUpdatePathFromReader(r *tls.Reader) (*UpdatePath, error) {
	leafNode, err := treesync.UnmarshalLeafNodeDataFromReader(r)
	if err != nil {
		return nil, fmt.Errorf("reading leaf_node: %w", err)
	}

	nodesData, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading nodes: %w", err)
	}

	nodes, err := unmarshalUpdatePathNodes(nodesData)
	if err != nil {
		return nil, fmt.Errorf("parsing nodes: %w", err)
	}

	return &UpdatePath{LeafNode: leafNode, Nodes: nodes}, nil
}

func UnmarshalUpdatePath(data []byte) (*UpdatePath, error) {
	r := tls.NewReader(data)
	up, err := unmarshalUpdatePathFromReader(r)
	if err != nil {
		return nil, err
	}
	if r.Remaining() != 0 {
		return nil, fmt.Errorf("trailing bytes in UpdatePath: %d", r.Remaining())
	}
	return up, nil
}

// ComputeProposalRef computes ProposalRef = RefHash("MLS 1.0 Proposal Reference", Marshal(AuthenticatedContent))
// per RFC 9420 §12.4. acBytes must be the serialized AuthenticatedContent of the proposal message.
func ComputeProposalRef(acBytes []byte) []byte {
	return ciphersuite.MakeProposalRef(acBytes).AsSlice()
}

// UpdatePathNode represents a node in the update path.
type UpdatePathNode struct {
	EncryptionKey        []byte
	EncryptedPathSecrets []ciphersuite.HpkeCiphertext
}

func (upn *UpdatePathNode) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteVLBytes(upn.EncryptionKey)

	// Vector de HPKECiphertext inline (RFC 9420 §12.4.1).
	secretsBuf := tls.NewWriter()
	for _, ct := range upn.EncryptedPathSecrets {
		secretsBuf.WriteVLBytes(ct.KEMOutput)
		secretsBuf.WriteVLBytes(ct.Ciphertext)
	}
	w.WriteVLBytes(secretsBuf.Bytes())

	return w.Bytes()
}

func UnmarshalUpdatePathNode(data []byte) (*UpdatePathNode, error) {
	r := tls.NewReader(data)
	node, err := unmarshalUpdatePathNodeFromReader(r)
	if err != nil {
		return nil, err
	}
	if r.Remaining() != 0 {
		return nil, fmt.Errorf("trailing bytes in UpdatePathNode")
	}
	return node, nil
}

func unmarshalUpdatePathNodeFromReader(r *tls.Reader) (*UpdatePathNode, error) {
	encKey, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	secretsData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	secrets, err := unmarshalEncryptedPathSecrets(secretsData)
	if err != nil {
		return nil, err
	}

	return &UpdatePathNode{
		EncryptionKey:        encKey,
		EncryptedPathSecrets: secrets,
	}, nil
}

func unmarshalEncryptedPathSecrets(data []byte) ([]ciphersuite.HpkeCiphertext, error) {
	// Canonical RFC format: concatenated HPKECiphertext structs.
	if secrets, err := unmarshalEncryptedPathSecretsInline(data); err == nil {
		return secrets, nil
	}

	// Interop fallback: each HPKECiphertext wrapped in an extra VL vector.
	return unmarshalEncryptedPathSecretsWrapped(data)
}

func unmarshalEncryptedPathSecretsInline(data []byte) ([]ciphersuite.HpkeCiphertext, error) {
	secretsReader := tls.NewReader(data)
	secrets := make([]ciphersuite.HpkeCiphertext, 0)
	for secretsReader.Remaining() > 0 {
		kemOutput, err := secretsReader.ReadVLBytes()
		if err != nil {
			return nil, err
		}
		ciphertext, err := secretsReader.ReadVLBytes()
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, ciphersuite.HpkeCiphertext{KEMOutput: kemOutput, Ciphertext: ciphertext})
	}
	return secrets, nil
}

func unmarshalEncryptedPathSecretsWrapped(data []byte) ([]ciphersuite.HpkeCiphertext, error) {
	secretsReader := tls.NewReader(data)
	secrets := make([]ciphersuite.HpkeCiphertext, 0)
	for secretsReader.Remaining() > 0 {
		ctData, err := secretsReader.ReadVLBytes()
		if err != nil {
			return nil, err
		}
		ctReader := tls.NewReader(ctData)
		kemOutput, err := ctReader.ReadVLBytes()
		if err != nil {
			return nil, err
		}
		ciphertext, err := ctReader.ReadVLBytes()
		if err != nil {
			return nil, err
		}
		if ctReader.Remaining() != 0 {
			return nil, fmt.Errorf("trailing bytes in wrapped HPKECiphertext")
		}
		secrets = append(secrets, ciphersuite.HpkeCiphertext{KEMOutput: kemOutput, Ciphertext: ciphertext})
	}
	return secrets, nil
}

func unmarshalUpdatePathNodes(data []byte) ([]UpdatePathNode, error) {
	if nodes, err := unmarshalUpdatePathNodesInline(data); err == nil {
		return nodes, nil
	}
	return unmarshalUpdatePathNodesWrapped(data)
}

func unmarshalUpdatePathNodesInline(data []byte) ([]UpdatePathNode, error) {
	nodesReader := tls.NewReader(data)
	nodes := make([]UpdatePathNode, 0)
	for nodesReader.Remaining() > 0 {
		node, err := unmarshalUpdatePathNodeFromReader(nodesReader)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, *node)
	}
	return nodes, nil
}

func unmarshalUpdatePathNodesWrapped(data []byte) ([]UpdatePathNode, error) {
	nodesReader := tls.NewReader(data)
	nodes := make([]UpdatePathNode, 0)
	for nodesReader.Remaining() > 0 {
		nodeData, err := nodesReader.ReadVLBytes()
		if err != nil {
			return nil, err
		}
		node, err := UnmarshalUpdatePathNode(nodeData)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, *node)
	}
	return nodes, nil
}

// StagedCommit representa un commit preparado para ser mergeado
type StagedCommit struct {
	Commit               *Commit
	Proposals            []*Proposal
	ProposalSenders      []LeafNodeIndex // per-proposal sender indices (parallel to Proposals)
	AuthenticatedContent *framing.AuthenticatedContent
	RootPathSecret       *ciphersuite.Secret // Para avanzar key schedule
	// Precalculado por el committer en Commit() — nil para receptores
	PrecomputedEpochSecrets *schedule.EpochSecrets
	PrecomputedGroupContext *GroupContext
	PrecomputedInterimHash  []byte
}

// ConfirmationTag represents the confirmation tag in a commit.
type ConfirmationTag struct {
	Value []byte
}

// Marshal serializes the Commit to TLS format con encoding correcto de ProposalOrRef.
func (c *Commit) Marshal() []byte {
	w := tls.NewWriter()

	// Proposals vector — RFC 9420 §12.4: ProposalOrRef entries are inline (not VL-wrapped)
	propBuf := tls.NewWriter()
	for _, por := range c.Proposals {
		if por.Proposal != nil {
			// Proposal inline: type(1) + Proposal (raw, no VL wrapper)
			propBuf.WriteUint8(uint8(ProposalOrRefTypeProposal))
			propBuf.WriteRaw(ProposalMarshal(por.Proposal))
		} else {
			// Reference: type(1) + ProposalRef<V>
			propBuf.WriteUint8(uint8(ProposalOrRefTypeReference))
			propBuf.WriteVLBytes(por.ProposalRef)
		}
	}
	w.WriteVLBytes(propBuf.Bytes())

	// Path (optional<UpdatePath>): presence byte + inline content per RFC §12.4
	if c.Path != nil {
		w.WriteUint8(1)
		w.WriteRaw(c.Path.Marshal())
	} else {
		w.WriteUint8(0)
	}

	return w.Bytes()
}

// UnmarshalCommit deserializes a Commit from TLS-encoded bytes.
// The UpdatePath is inline per RFC 9420 §12.4.1 (leaf_node not VL-prefixed).
func UnmarshalCommit(data []byte) (*Commit, error) {
	r := tls.NewReader(data)
	commit, err := unmarshalCommitFromReader(r)
	if err != nil {
		return nil, err
	}
	if r.Remaining() != 0 {
		return nil, fmt.Errorf("trailing bytes after Commit body: %d", r.Remaining())
	}
	return commit, nil
}

// unmarshalCommitFromReader parses a Commit from the reader, stopping exactly
// at the end of the commit body (proposals + optional UpdatePath).
// The reader position after this call is immediately after the commit body,
// ready to read the auth tail (signature, confirmation_tag, membership_tag).
func unmarshalCommitFromReader(r *tls.Reader) (*Commit, error) {
	commit := &Commit{
		Proposals: make([]ProposalOrRef, 0),
	}

	proposalsData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	parsedProposals, err := parseProposalOrRefs(proposalsData)
	if err != nil {
		return nil, err
	}
	commit.Proposals = parsedProposals

	pathPresent, err := r.ReadUint8()
	if err != nil {
		return nil, err
	}

	if pathPresent == 1 {
		path, err := unmarshalUpdatePathFromReader(r)
		if err != nil {
			return nil, fmt.Errorf("reading UpdatePath: %w", err)
		}
		commit.Path = path
	} else if pathPresent != 0 {
		return nil, fmt.Errorf("invalid path_present byte: %d", pathPresent)
	}

	return commit, nil
}

func parseProposalOrRefs(proposalsData []byte) ([]ProposalOrRef, error) {
	if len(proposalsData) == 0 {
		return nil, nil
	}

	// Canonical encoding: concatenated ProposalOrRef entries.
	if proposals, err := parseProposalOrRefsCanonical(proposalsData); err == nil {
		return proposals, nil
	}

	// Interop fallback: each ProposalOrRef wrapped as VL entry.
	if proposals, err := parseProposalOrRefsWrapped(proposalsData); err == nil {
		return proposals, nil
	}

	return nil, fmt.Errorf("invalid proposal_or_ref vector")
}

func parseProposalOrRefsCanonical(data []byte) ([]ProposalOrRef, error) {
	propReader := tls.NewReader(data)
	proposals := make([]ProposalOrRef, 0)
	for propReader.Remaining() > 0 {
		porType, err := propReader.ReadUint8()
		if err != nil {
			return nil, err
		}

		switch ProposalOrRefType(porType) {
		case ProposalOrRefTypeProposal:
			// RFC 9420 §12.4: Proposal is inline (not VL-prefixed) inside ProposalOrRef.
			// Record position, advance reader, then extract the bytes consumed.
			startPos := propReader.Position()
			if err := unmarshalProposalFromReader(propReader); err != nil {
				return nil, err
			}
			endPos := propReader.Position()
			propReader.SetPosition(startPos)
			propData, _ := propReader.ReadBytes(endPos - startPos)
			proposal, err := UnmarshalProposal(propData)
			if err != nil {
				return nil, err
			}
			proposals = append(proposals, ProposalOrRef{Proposal: proposal})
		case ProposalOrRefTypeReference:
			ref, err := propReader.ReadVLBytes()
			if err != nil {
				return nil, err
			}
			proposals = append(proposals, ProposalOrRef{ProposalRef: ref})
		default:
			return nil, fmt.Errorf("unknown ProposalOrRefType: %d", porType)
		}
	}
	return proposals, nil
}

func parseProposalOrRefsWrapped(data []byte) ([]ProposalOrRef, error) {
	propReader := tls.NewReader(data)
	proposals := make([]ProposalOrRef, 0)
	for propReader.Remaining() > 0 {
		entry, err := propReader.ReadVLBytes()
		if err != nil {
			return nil, err
		}
		er := tls.NewReader(entry)
		porType, err := er.ReadUint8()
		if err != nil {
			return nil, err
		}

		switch ProposalOrRefType(porType) {
		case ProposalOrRefTypeProposal:
			if propData, err := er.ReadVLBytes(); err == nil && er.Remaining() == 0 {
				proposal, parseErr := UnmarshalProposal(propData)
				if parseErr != nil {
					return nil, parseErr
				}
				proposals = append(proposals, ProposalOrRef{Proposal: proposal})
				continue
			}

			propData := er.BytesAfterPosition()
			proposal, err := UnmarshalProposal(propData)
			if err != nil {
				return nil, err
			}
			proposals = append(proposals, ProposalOrRef{Proposal: proposal})
		case ProposalOrRefTypeReference:
			if ref, err := er.ReadVLBytes(); err == nil && er.Remaining() == 0 {
				proposals = append(proposals, ProposalOrRef{ProposalRef: ref})
				continue
			}

			ref := er.BytesAfterPosition()
			proposals = append(proposals, ProposalOrRef{ProposalRef: append([]byte(nil), ref...)})
		default:
			return nil, fmt.Errorf("unknown ProposalOrRefType: %d", porType)
		}
	}
	return proposals, nil
}
