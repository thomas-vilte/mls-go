package group

import (
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/internal/tls"
	"github.com/thomas-vilte/mls-go/schedule"
	"github.com/thomas-vilte/mls-go/treesync"
)

// ProposalOrRefType indicates whether a ProposalOrRef contains a proposal or reference.
//
// Per RFC 9420 §12.4:
//   - ProposalOrRefTypeProposal (1): Inline proposal
//   - ProposalOrRefTypeReference (2): Reference by hash
type ProposalOrRefType uint8

const (
	// ProposalOrRefTypeProposal indicates an inline proposal.
	ProposalOrRefTypeProposal ProposalOrRefType = 1

	// ProposalOrRefTypeReference indicates a proposal reference (hash).
	ProposalOrRefTypeReference ProposalOrRefType = 2
)

// Commit represents an MLS Commit message per RFC 9420 §12.4.
//
// A Commit applies pending proposals and advances the group to a new epoch.
// It contains an optional UpdatePath for Post-Compromise Security.
//
// ```text
//
//	struct {
//	    ProposalOrRef proposals<V>;
//	    optional<UpdatePath> path;
//	} Commit;
//
// ```
type Commit struct {
	Proposals []ProposalOrRef
	Path      *UpdatePath
}

// UpdatePath represents the update path in a Commit per RFC 9420 §12.4.1.
//
// The update path contains new encryption keys for the committer's direct path
// in the ratchet tree, providing Post-Compromise Security.
//
// ```text
//
//	struct {
//	    LeafNode leaf_node;
//	    UpdatePathNode nodes<V>;
//	} UpdatePath;
//
// ```
type UpdatePath struct {
	LeafNode *treesync.LeafNodeData
	Nodes    []UpdatePathNode
}

// Marshal serializes the UpdatePath to TLS format per RFC 9420 §12.4.1.
//
// LeafNode is inline (not VL-prefixed), nodes are VL-prefixed.
func (up *UpdatePath) Marshal() []byte {
	w := tls.NewWriter()
	// LeafNode is inline per RFC 9420 §12.4.1 (NOT VL-prefixed)
	w.WriteRaw(up.LeafNode.Marshal())

	nodesBuf := tls.NewWriter()
	for _, node := range up.Nodes {
		nodesBuf.WriteRaw(node.Marshal())
	}
	w.WriteVLBytes(nodesBuf.Bytes())

	return w.Bytes()
}

// unmarshalUpdatePathFromReader parses an UpdatePath inline from a TLS reader.
//
// LeafNode is inline (not VL-prefixed), nodes<V> is VL-prefixed per RFC 9420 §12.4.1.
func unmarshalUpdatePathFromReader(r *tls.Reader) (*UpdatePath, error) {
	leafNode, err := treesync.UnmarshalLeafNodeDataFromReader(r)
	if err != nil {
		return nil, fmt.Errorf("reading leaf node: %w", err)
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

// ComputeProposalRef computes ProposalRef = RefHash("MLS 1.0 Proposal Reference", Marshal(AuthenticatedContent))
// per RFC 9420 §12.4.
//
// acBytes must be the serialized AuthenticatedContent of the proposal message.
func ComputeProposalRef(acBytes []byte, cs ciphersuite.CipherSuite) []byte {
	return ciphersuite.MakeProposalRef(acBytes, cs.HashFunction()).AsSlice()
}

// UpdatePathNode represents a node in the update path per RFC 9420 §12.4.1.
//
// Each node contains a public encryption key and encrypted path secrets for
// the resolution of the corresponding copath node.
type UpdatePathNode struct {
	EncryptionKey        []byte
	EncryptedPathSecrets []ciphersuite.HpkeCiphertext
}

// Marshal serializes the UpdatePathNode to TLS format.
func (upn *UpdatePathNode) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteVLBytes(upn.EncryptionKey)

	// Vector of HPKECiphertext inline per RFC 9420 §12.4.1
	secretsBuf := tls.NewWriter()
	for _, ct := range upn.EncryptedPathSecrets {
		secretsBuf.WriteVLBytes(ct.KEMOutput)
		secretsBuf.WriteVLBytes(ct.Ciphertext)
	}
	w.WriteVLBytes(secretsBuf.Bytes())

	return w.Bytes()
}

// UnmarshalUpdatePathNode deserializes an UpdatePathNode from TLS-encoded bytes.
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

// unmarshalUpdatePathNodeFromReader parses an UpdatePathNode from a TLS reader.
func unmarshalUpdatePathNodeFromReader(r *tls.Reader) (*UpdatePathNode, error) {
	encKey, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading encryption key: %w", err)
	}

	secretsData, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading encrypted secrets: %w", err)
	}

	secrets, err := unmarshalEncryptedPathSecrets(secretsData)
	if err != nil {
		return nil, fmt.Errorf("parsing encrypted secrets: %w", err)
	}

	return &UpdatePathNode{
		EncryptionKey:        encKey,
		EncryptedPathSecrets: secrets,
	}, nil
}

// unmarshalEncryptedPathSecrets parses encrypted path secrets with fallback.
//
// First tries inline format per RFC, then falls back to wrapped format for interop.
func unmarshalEncryptedPathSecrets(data []byte) ([]ciphersuite.HpkeCiphertext, error) {
	if secrets, err := unmarshalEncryptedPathSecretsInline(data); err == nil {
		return secrets, nil
	}

	return unmarshalEncryptedPathSecretsWrapped(data)
}

// unmarshalEncryptedPathSecretsInline parses inline HPKE ciphertexts per RFC 9420 §12.4.1.
func unmarshalEncryptedPathSecretsInline(data []byte) ([]ciphersuite.HpkeCiphertext, error) {
	secretsReader := tls.NewReader(data)
	secrets := make([]ciphersuite.HpkeCiphertext, 0)
	for secretsReader.Remaining() > 0 {
		kemOutput, err := secretsReader.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading KEM output: %w", err)
		}
		ciphertext, err := secretsReader.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading ciphertext: %w", err)
		}
		secrets = append(secrets, ciphersuite.HpkeCiphertext{KEMOutput: kemOutput, Ciphertext: ciphertext})
	}
	return secrets, nil
}

// unmarshalEncryptedPathSecretsWrapped parses wrapped HPKE ciphertexts for interop.
func unmarshalEncryptedPathSecretsWrapped(data []byte) ([]ciphersuite.HpkeCiphertext, error) {
	secretsReader := tls.NewReader(data)
	secrets := make([]ciphersuite.HpkeCiphertext, 0)
	for secretsReader.Remaining() > 0 {
		ctData, err := secretsReader.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading wrapped ciphertext: %w", err)
		}
		ctReader := tls.NewReader(ctData)
		kemOutput, err := ctReader.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading KEM output from wrapped: %w", err)
		}
		ciphertext, err := ctReader.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading ciphertext from wrapped: %w", err)
		}
		if ctReader.Remaining() != 0 {
			return nil, fmt.Errorf("trailing bytes in wrapped HPKECiphertext")
		}
		secrets = append(secrets, ciphersuite.HpkeCiphertext{KEMOutput: kemOutput, Ciphertext: ciphertext})
	}
	return secrets, nil
}

// unmarshalUpdatePathNodes parses update path nodes with fallback.
func unmarshalUpdatePathNodes(data []byte) ([]UpdatePathNode, error) {
	if nodes, err := unmarshalUpdatePathNodesInline(data); err == nil {
		return nodes, nil
	}
	return unmarshalUpdatePathNodesWrapped(data)
}

// unmarshalUpdatePathNodesInline parses inline UpdatePathNodes per RFC 9420 §12.4.1.
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

// unmarshalUpdatePathNodesWrapped parses wrapped UpdatePathNodes for interop.
func unmarshalUpdatePathNodesWrapped(data []byte) ([]UpdatePathNode, error) {
	nodesReader := tls.NewReader(data)
	nodes := make([]UpdatePathNode, 0)
	for nodesReader.Remaining() > 0 {
		nodeData, err := nodesReader.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading wrapped node: %w", err)
		}
		node, err := UnmarshalUpdatePathNode(nodeData)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, *node)
	}
	return nodes, nil
}

// StagedCommit represents a commit prepared for merging per RFC 9420 §12.4.
//
// Staging allows the committer to prepare all values before applying them,
// enabling atomic application of the commit.
type StagedCommit struct {
	commit               *Commit
	proposals            []*Proposal
	proposalSenders      []LeafNodeIndex // Per-proposal sender indices (parallel to proposals)
	authenticatedContent *framing.AuthenticatedContent
	rootPathSecret       *ciphersuite.Secret // commit_secret; zeroed by key schedule during Commit()
	// Precomputed by committer in Commit() — nil for receivers
	precomputedEpochSecrets *schedule.EpochSecrets
	precomputedGroupContext *GroupContext
	precomputedInterimHash  []byte
	// JoinerSecret is the actual joiner_secret = ExpandWithLabel(intermediate,"joiner",GC,Nh).
	// Cloned before ComputePskSecret zeroes it; used by the caller for CreateWelcome.
	// Nil for receiver-side StagedCommits.
	joinerSecret *ciphersuite.Secret
	// PskIDs contains the PreSharedKeyID entries for all PSK proposals in this commit.
	// Used by CreateWelcome to populate GroupSecrets.psks for joiners.
	pskIDs []PskID
	// RawPskSecret is the psk_secret computed from all PSKs (0^Nh if none).
	// Used by CreateWelcome to derive welcome_secret with the correct PSK secret.
	rawPskSecret *ciphersuite.Secret
	// PathSecrets holds all N+1 path secrets from createUpdatePath (indexed 0..N).
	// pathSecrets[0] = leaf secret, pathSecrets[N] = commit_secret.
	// Used by CreateWelcome to compute per-joiner path_secret values.
	pathSecrets []*ciphersuite.Secret
	// CommitterFilteredLevels and CommitterDirectPath are used by CreateWelcome
	// to locate each new joiner's position in the committer's copath.
	committerFilteredLevels []int
	committerDirectPath     []treesync.NodeIndex
	committerCopath         []treesync.NodeIndex
	// TreeAfterProposals is the ratchet tree with all proposals applied (including
	// Add proposals that add new joiners), before MergeCommit updates the group state.
	// Used by CreateWelcome to find per-joiner path_secret for newly added members
	// whose LCA with the committer is below the filtered direct path.
	treeAfterProposals *treesync.RatchetTree
	// MembershipTag is the MAC(membership_key, AuthenticatedContentTBM) for PublicMessage
	// commits (RFC §6.2). Nil for PrivateMessage commits or when membership_key is unavailable.
	membershipTag []byte
}

// Commit returns the staged commit payload.
func (sc *StagedCommit) Commit() *Commit {
	if sc == nil {
		return nil
	}
	return sc.commit
}

// Proposals returns the staged proposals.
func (sc *StagedCommit) Proposals() []*Proposal {
	if sc == nil {
		return nil
	}
	out := make([]*Proposal, len(sc.proposals))
	copy(out, sc.proposals)
	return out
}

// ProposalSenders returns the sender index for each staged proposal.
func (sc *StagedCommit) ProposalSenders() []LeafNodeIndex {
	if sc == nil {
		return nil
	}
	out := make([]LeafNodeIndex, len(sc.proposalSenders))
	copy(out, sc.proposalSenders)
	return out
}

// AuthenticatedContent returns the authenticated commit content.
func (sc *StagedCommit) AuthenticatedContent() *framing.AuthenticatedContent {
	if sc == nil {
		return nil
	}
	return sc.authenticatedContent
}

// JoinerSecret returns a copy of the joiner secret.
func (sc *StagedCommit) JoinerSecret() *ciphersuite.Secret {
	if sc == nil || sc.joinerSecret == nil {
		return nil
	}
	return sc.joinerSecret.Clone()
}

// RootPathSecret returns a copy of the commit secret.
func (sc *StagedCommit) RootPathSecret() *ciphersuite.Secret {
	if sc == nil || sc.rootPathSecret == nil {
		return nil
	}
	return sc.rootPathSecret.Clone()
}

// PskIDs returns the PSK identifiers used by the staged commit.
func (sc *StagedCommit) PskIDs() []PskID {
	if sc == nil {
		return nil
	}
	out := make([]PskID, len(sc.pskIDs))
	copy(out, sc.pskIDs)
	return out
}

// RawPskSecret returns a copy of the computed psk_secret.
func (sc *StagedCommit) RawPskSecret() *ciphersuite.Secret {
	if sc == nil || sc.rawPskSecret == nil {
		return nil
	}
	return sc.rawPskSecret.Clone()
}

// MembershipTag returns a copy of the public message membership tag.
func (sc *StagedCommit) MembershipTag() []byte {
	if sc == nil {
		return nil
	}
	return append([]byte(nil), sc.membershipTag...)
}

// ConfirmationTag represents the confirmation tag in a commit per RFC 9420 §8.2.
//
// The confirmation_tag is a MAC over the confirmed_transcript_hash using
// the confirmation_key from the epoch secrets.
type ConfirmationTag struct {
	Value []byte
}

// Marshal serializes the Commit to TLS format per RFC 9420 §12.4.
//
// ProposalOrRef entries are inline (not VL-wrapped) per the RFC.
func (c *Commit) Marshal() []byte {
	w := tls.NewWriter()

	// Proposals vector — RFC 9420 §12.4: ProposalOrRef entries are inline
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

// UnmarshalCommit deserializes a Commit from TLS-encoded bytes per RFC 9420 §12.4.
//
// The UpdatePath is inline per RFC 9420 §12.4.1 (LeafNode not VL-prefixed).
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

// unmarshalCommitFromReader parses a Commit from the reader.
//
// The reader position after this call is immediately after the commit body,
// ready to read the auth tail (signature, confirmation_tag, membership_tag).
func unmarshalCommitFromReader(r *tls.Reader) (*Commit, error) {
	commit := &Commit{
		Proposals: make([]ProposalOrRef, 0),
	}

	proposalsData, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading proposals: %w", err)
	}
	parsedProposals, err := parseProposalOrRefs(proposalsData)
	if err != nil {
		return nil, fmt.Errorf("parsing proposals: %w", err)
	}
	commit.Proposals = parsedProposals

	pathPresent, err := r.ReadUint8()
	if err != nil {
		return nil, fmt.Errorf("reading path presence: %w", err)
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

// parseProposalOrRefs parses a vector of ProposalOrRef with fallback.
func parseProposalOrRefs(proposalsData []byte) ([]ProposalOrRef, error) {
	if len(proposalsData) == 0 {
		return nil, nil
	}

	// Canonical encoding: concatenated ProposalOrRef entries
	if proposals, err := parseProposalOrRefsCanonical(proposalsData); err == nil {
		return proposals, nil
	}

	// Interop fallback: each ProposalOrRef wrapped as VL entry
	if proposals, err := parseProposalOrRefsWrapped(proposalsData); err == nil {
		return proposals, nil
	}

	return nil, fmt.Errorf("invalid proposal_or_ref vector")
}

// parseProposalOrRefsCanonical parses ProposalOrRefs in RFC 9420 canonical format.
func parseProposalOrRefsCanonical(data []byte) ([]ProposalOrRef, error) {
	propReader := tls.NewReader(data)
	proposals := make([]ProposalOrRef, 0)
	for propReader.Remaining() > 0 {
		porType, err := propReader.ReadUint8()
		if err != nil {
			return nil, fmt.Errorf("reading ProposalOrRef type: %w", err)
		}

		switch ProposalOrRefType(porType) {
		case ProposalOrRefTypeProposal:
			// RFC 9420 §12.4: Proposal is inline (not VL-prefixed) inside ProposalOrRef.
			// Record position, advance reader, then extract the bytes consumed.
			startPos := propReader.Position()
			if err := unmarshalProposalFromReader(propReader); err != nil {
				return nil, fmt.Errorf("parsing inline proposal: %w", err)
			}
			endPos := propReader.Position()
			propReader.SetPosition(startPos)
			propData, _ := propReader.ReadBytes(endPos - startPos)
			proposal, err := UnmarshalProposal(propData)
			if err != nil {
				return nil, fmt.Errorf("unmarshaling proposal: %w", err)
			}
			proposals = append(proposals, ProposalOrRef{Proposal: proposal})

		case ProposalOrRefTypeReference:
			ref, err := propReader.ReadVLBytes()
			if err != nil {
				return nil, fmt.Errorf("reading proposal reference: %w", err)
			}
			proposals = append(proposals, ProposalOrRef{ProposalRef: ref})

		default:
			return nil, fmt.Errorf("unknown ProposalOrRefType: %d", porType)
		}
	}
	return proposals, nil
}

// parseProposalOrRefsWrapped parses ProposalOrRefs in wrapped format for interop.
func parseProposalOrRefsWrapped(data []byte) ([]ProposalOrRef, error) {
	propReader := tls.NewReader(data)
	proposals := make([]ProposalOrRef, 0)
	for propReader.Remaining() > 0 {
		entry, err := propReader.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading wrapped entry: %w", err)
		}
		er := tls.NewReader(entry)
		porType, err := er.ReadUint8()
		if err != nil {
			return nil, fmt.Errorf("reading wrapped ProposalOrRef type: %w", err)
		}

		switch ProposalOrRefType(porType) {
		case ProposalOrRefTypeProposal:
			if propData, err := er.ReadVLBytes(); err == nil && er.Remaining() == 0 {
				proposal, parseErr := UnmarshalProposal(propData)
				if parseErr != nil {
					return nil, fmt.Errorf("unmarshaling wrapped proposal: %w", parseErr)
				}
				proposals = append(proposals, ProposalOrRef{Proposal: proposal})
				continue
			}

			propData := er.BytesAfterPosition()
			proposal, err := UnmarshalProposal(propData)
			if err != nil {
				return nil, fmt.Errorf("unmarshaling proposal from wrapped: %w", err)
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
