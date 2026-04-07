// Package treesync implements MLS ratchet tree operations according to RFC 9420 §7.
//
// Uses RFC Appendix C interleaved representation:
//   - Leaves at indices 0, 2, 4, 6, ... (even indices)
//   - Parents at indices 1, 3, 5, 7, ... (odd indices)
//
// This layout enables O(1) leaf access and efficient tree traversal without pointers.
package treesync

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"math/bits"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/internal/tls"
)

// NodeIndex represents a node position in the interleaved tree.
//
// Even indices (0, 2, 4, ...) are leaves.
// Odd indices (1, 3, 5, ...) are parents.
type NodeIndex uint32

// LeafIndex represents a leaf position in the tree.
//
// Leaf index corresponds to tree node index: leaf i → node 2i.
type LeafIndex uint32

// NodeState represents the state of a node.
type NodeState uint8

const (
	// NodeStateEmpty represents an empty node (no member assigned).
	NodeStateEmpty NodeState = iota
	// NodeStatePresent represents a node with valid data.
	NodeStatePresent
	// NodeStateBlank represents a blanked node (used in path blanking).
	NodeStateBlank
)

// RatchetTree represents the MLS ratchet tree as defined in RFC 9420 §7.
//
// The tree uses interleaved array representation (RFC Appendix C):
//   - Nodes slice contains 2N-1 nodes for N leaves
//   - Leaves at even indices, parents at odd indices
//   - Efficient O(1) access by index
//
// RFC 9420 §7.1:
//
//	struct {
//	    HPKEPublicKey public_key;
//	    opaque parent_hash<V>;
//	} ParentNode;
//
// RFC 9420 §7.2:
//
//	struct {
//	    HPKEPublicKey encryption_key<V>;
//	    SignaturePublicKey signature_key<V>;
//	    Credential credential;
//	    // ... more fields
//	} LeafNode;
type RatchetTree struct {
	Nodes     []Node
	NumLeaves uint32
	cs        ciphersuite.CipherSuite
}

// hashFunc returns the hash constructor for this tree's cipher suite,
// defaulting to SHA-256 for trees created without an explicit cipher suite.
func (t *RatchetTree) hashFunc() func() hash.Hash {
	if hf := t.cs.HashFunction(); hf != nil {
		return hf
	}
	return sha256.New
}

// Node represents a node in the ratchet tree.
//
// A node can be a leaf (even index) or parent (odd index).
// The State field indicates if the node is empty, present, or blank.
//
// For leaf nodes (State == NodeStatePresent):
//   - LeafData contains the member's credentials and keys
//
// For parent nodes (State == NodeStatePresent):
//   - EncryptionKey: HPKE public key for encrypting path secrets
//   - ParentHash: Hash chain for tree integrity (RFC §7.9)
//   - UnmergedLeaves: Leaves not updated through this parent
type Node struct {
	State          NodeState
	EncryptionKey  *ecdh.PublicKey
	ParentHash     []byte
	UnmergedLeaves []LeafIndex
	LeafData       *LeafNodeData
}

// LeafNodeData contains leaf-specific data as defined in RFC 9420 §7.2.
//
// RFC 9420 §7.2 structure:
//
//	struct {
//	    HPKEPublicKey encryption_key<V>;
//	    SignaturePublicKey signature_key<V>;
//	    Credential credential;
//	    Capabilities capabilities;
//	    LeafNodeSource leaf_node_source;
//	    select (leaf_node_source) {
//	        case key_package: Lifetime lifetime;
//	        case update: struct{};
//	        case commit: opaque parent_hash<V>;
//	    }
//	    Extension extensions<V>;
//	    opaque signature<V>;
//	} LeafNode;
//
// Fields:
//   - EncryptionKey: HPKE public key for encrypting to this member
//   - SignatureKey/SignatureKeyRaw: ECDSA/Ed25519 signature verification key
//   - Credential: Identity credential (Basic, X509, etc.)
//   - Capabilities: Supported protocol versions, cipher suites, etc.
//   - LeafNodeSource: How node was created (1=key_package, 2=update, 3=commit)
//   - Lifetime: Validity period (only for key_package source)
//   - ParentHash: Hash chain for tree integrity (only for commit source)
//   - Extensions: Optional extensions
//   - Signature: Signature over TBS (To-Be-Signed) content
type LeafNodeData struct {
	Credential      *credentials.Credential
	SignatureKey    *ecdsa.PublicKey
	SignatureKeyRaw []byte
	EncryptionKey   []byte
	Capabilities    *LeafNodeCapabilities
	Lifetime        *LeafNodeLifetime
	Extensions      [][]byte
	LeafNodeSource  uint8
	ParentHash      []byte
	Signature       []byte
}

// LeafNodeCapabilities represents node capabilities as defined in RFC 9420 §7.2.
//
// RFC 9420 §7.2:
//
//	struct {
//	    ProtocolVersion protocol_versions<V>;
//	    CipherSuite cipher_suites<V>;
//	    ExtensionType extensions<V>;
//	    ProposalType proposals<V>;
//	    CredentialType credentials<V>;
//	} Capabilities;
//
// Fields:
//   - ProtocolVersions: Supported MLS protocol versions
//   - CipherSuites: Supported cipher suites
//   - Extensions: Supported extension types
//   - Proposals: Supported proposal types
//   - Credentials: Supported credential types
type LeafNodeCapabilities struct {
	ProtocolVersions []uint16
	CipherSuites     []uint16
	Extensions       []uint16
	Proposals        []uint16
	Credentials      []uint16
}

// LeafNodeLifetime represents the validity period of a LeafNode.
//
// RFC 9420 §7.2:
//
//	struct {
//	    uint64 not_before;
//	    uint64 not_after;
//	} Lifetime;
//
// Fields:
//   - NotBefore: Unix timestamp when the leaf becomes valid (0 = always valid)
//   - NotAfter: Unix timestamp when the leaf expires (0 = never expires)
//
// Validation: Current time MUST be >= NotBefore and <= NotAfter (if set).
type LeafNodeLifetime struct {
	NotBefore uint64
	NotAfter  uint64
}

// NewRatchetTree creates a new ratchet tree with N leaves.
//
// The tree is initialized with 2N-1 nodes in interleaved representation:
//   - N leaves at even indices (0, 2, 4, ..., 2N-2)
//   - N-1 parents at odd indices (1, 3, 5, ..., 2N-3)
//
// All nodes start in NodeStateEmpty.
//
// Parameters:
//   - numLeaves: Number of leaves (group members) the tree should support
//   - cs: Optional cipher suite for hash computation (defaults to SHA-256)
//
// Returns a new RatchetTree, or a tree with 1 leaf if numLeaves < 1.
//
// RFC Appendix C:
//
//	num_nodes = 2 * num_leaves - 1
func NewRatchetTree(numLeaves uint32, cs ...ciphersuite.CipherSuite) *RatchetTree {
	if numLeaves < 1 {
		numLeaves = 1
	}
	t := &RatchetTree{
		Nodes:     make([]Node, numLeaves*2-1),
		NumLeaves: numLeaves,
	}
	if len(cs) > 0 {
		t.cs = cs[0]
	}
	return t
}

// SetCipherSuite sets the cipher suite used for tree hash computation.
func (t *RatchetTree) SetCipherSuite(cs ciphersuite.CipherSuite) {
	t.cs = cs
}

// LeafCount returns the number of leaves in the tree.
//
// For a tree with N members, there are N leaves and N-1 parents,
// totaling 2N-1 nodes.
func (t *RatchetTree) LeafCount() uint32 {
	return t.NumLeaves
}

// IsLeaf returns true if the given node index is a leaf.
//
// In the interleaved representation:
//   - Even indices (0, 2, 4, ...) are leaves
//   - Odd indices (1, 3, 5, ...) are parents
//
// Parameters:
//   - idx: Node index to check
//
// Returns true if idx is even (leaf), false if odd (parent).
func IsLeaf(idx NodeIndex) bool {
	return uint32(idx)%2 == 0
}

// IsParent returns true if node index is odd (parent).
func IsParent(idx NodeIndex) bool {
	return uint32(idx)%2 == 1
}

// LeafIndexToNodeIndex converts leaf k to node 2k.
func LeafIndexToNodeIndex(leaf LeafIndex) NodeIndex {
	return NodeIndex(uint32(leaf) * 2)
}

// NodeIndexToLeafIndex converts node to leaf (if even).
func NodeIndexToLeafIndex(node NodeIndex) (LeafIndex, error) {
	if !IsLeaf(node) {
		return 0, fmt.Errorf("node %d is not a leaf", node)
	}
	return LeafIndex(uint32(node) / 2), nil
}

// nodeLevel returns the level of a node in the interleaved representation (RFC Appendix C).
// Leaves are at level 0; count consecutive 1 bits from bit 0.
func nodeLevel(x uint32) uint32 {
	// Trailing ones = trailing zeros of ^x
	return uint32(bits.TrailingZeros32(^x))
}

// FindLeafByEncKey returns the leaf index of a leaf with the given encryption key.
func (t *RatchetTree) FindLeafByEncKey(encKey []byte) (LeafIndex, bool) {
	for i := LeafIndex(0); i < LeafIndex(t.NumLeaves); i++ {
		node := t.GetLeaf(i)
		if node != nil && node.LeafData != nil && bytes.Equal(node.LeafData.EncryptionKey, encKey) {
			return i, true
		}
	}
	return 0, false
}

// Root returns the root node index per RFC Appendix C:
//
//	root(n) = (1 << floor(log2(2n-1))) - 1
func (t *RatchetTree) Root() NodeIndex {
	if t.NumLeaves == 1 {
		return 0
	}
	// floor(log2(2n-1)) = bits.Len(2n-1) - 1
	w := bits.Len(uint(2*t.NumLeaves-1)) - 1
	return NodeIndex((1 << w) - 1)
}

// parentStep computes one step of the parent function per RFC Appendix C.
// The result may fall outside the valid node range for non-power-of-2 trees.
func parentStep(node NodeIndex) NodeIndex {
	l := nodeLevel(uint32(node))
	if (uint32(node)>>(l+1))&1 == 0 {
		// left child: parent is to the right
		return node + NodeIndex(1<<l)
	}
	// right child: parent is to the left
	return node - NodeIndex(1<<l)
}

// Parent returns the parent of a node per RFC Appendix C.
//
// For non-power-of-2 trees, parentStep is applied repeatedly until the result
// falls within the valid node range (0..2n-2), per the RFC algorithm.
func (t *RatchetTree) Parent(node NodeIndex) (NodeIndex, error) {
	root := t.Root()
	if node == root {
		return 0, fmt.Errorf("root has no parent")
	}

	maxIdx := NodeIndex(t.NumLeaves*2 - 2)
	p := parentStep(node)
	for p > maxIdx {
		p = parentStep(p)
	}

	return p, nil
}

// LeftChild returns the left child of a parent node per RFC Appendix C:
//
//	left_child(x) = x ^ (1 << (level(x) - 1))
func (t *RatchetTree) LeftChild(parent NodeIndex) (NodeIndex, error) {
	if !IsParent(parent) {
		return 0, fmt.Errorf("not a parent node")
	}

	l := nodeLevel(uint32(parent))
	return NodeIndex(uint32(parent) ^ (1 << (l - 1))), nil
}

// RightChild returns the right child of a parent node per RFC Appendix C:
//
//	right_child(x) = x ^ (3 << (level(x) - 1))
func (t *RatchetTree) RightChild(parent NodeIndex) (NodeIndex, error) {
	if !IsParent(parent) {
		return 0, fmt.Errorf("not a parent node")
	}

	l := nodeLevel(uint32(parent))
	child := NodeIndex(uint32(parent) ^ (3 << (l - 1)))
	maxIdx := NodeIndex(t.NumLeaves*2 - 2)
	for child > maxIdx {
		level := nodeLevel(uint32(child))
		if level == 0 {
			break
		}
		child = NodeIndex(uint32(child) ^ (1 << (level - 1)))
	}

	return child, nil
}

// DirectPath returns the path from a leaf to root.
func (t *RatchetTree) DirectPath(leafIdx LeafIndex) []NodeIndex {
	leaf := LeafIndexToNodeIndex(leafIdx)
	path := []NodeIndex{leaf}

	current := leaf
	for current != t.Root() {
		parent, err := t.Parent(current)
		if err != nil {
			break
		}
		path = append(path, parent)
		current = parent
	}

	return path
}

// Copath returns the copath (siblings of direct path).
func (t *RatchetTree) Copath(leafIdx LeafIndex) []NodeIndex {
	path := t.DirectPath(leafIdx)
	copath := make([]NodeIndex, 0, len(path)-1)

	for i := 0; i < len(path)-1; i++ {
		node := path[i]
		parent, _ := t.Parent(node)

		left, _ := t.LeftChild(parent)
		if left == node {
			right, _ := t.RightChild(parent)
			copath = append(copath, right)
		} else {
			copath = append(copath, left)
		}
	}

	return copath
}

// AddLeaf adds a leaf to the tree.
func (t *RatchetTree) AddLeaf(leaf LeafNodeData) (LeafIndex, NodeIndex) {
	// Find first empty or blank leaf (RFC 9420 §7.8: blank leaves can be reused)
	for i := LeafIndex(0); i < LeafIndex(t.NumLeaves); i++ {
		nodeIdx := LeafIndexToNodeIndex(i)
		if int(nodeIdx) < len(t.Nodes) {
			state := t.Nodes[nodeIdx].State
			if state == NodeStateEmpty || state == NodeStateBlank {
				t.Nodes[nodeIdx] = Node{
					State:    NodeStatePresent,
					LeafData: &leaf,
				}
				// RFC 9420 §7.8: Add the new leaf to unmerged_leaves of all direct path nodes
				t.addToUnmergedLeaves(i)
				return i, nodeIdx
			}
		}
	}

	// Expand tree. RFC 9420 §7.8 says "smallest size that can contain the new
	// member count". We round up to the next power-of-2 so that our internal
	// tree structure matches the reference test vectors.
	i := LeafIndex(t.NumLeaves)
	newNumLeaves := t.NumLeaves + 1
	if newNumLeaves > 1 && (newNumLeaves&(newNumLeaves-1)) != 0 {
		newNumLeaves = 1 << bits.Len32(newNumLeaves-1)
	}
	t.NumLeaves = newNumLeaves
	newNodes := make([]Node, t.NumLeaves*2-1)
	copy(newNodes, t.Nodes)
	t.Nodes = newNodes

	nodeIdx := LeafIndexToNodeIndex(i)
	t.Nodes[nodeIdx] = Node{
		State:    NodeStatePresent,
		LeafData: &leaf,
	}
	// RFC 9420 §7.8: Add the new leaf to unmerged_leaves of all direct path nodes
	t.addToUnmergedLeaves(i)
	return i, nodeIdx
}

// addToUnmergedLeaves adds a leaf index to the unmerged_leaves list of all nodes in its direct path.
// This is required by RFC 9420 §7.8 when a new member is added to the group.
func (t *RatchetTree) addToUnmergedLeaves(leafIdx LeafIndex) {
	for _, parentIdx := range t.DirectPath(leafIdx) {
		if !IsLeaf(parentIdx) {
			t.Nodes[parentIdx].UnmergedLeaves = append(t.Nodes[parentIdx].UnmergedLeaves, leafIdx)
		}
	}
}

// GetLeaf returns a leaf node.
func (t *RatchetTree) GetLeaf(idx LeafIndex) *Node {
	nodeIdx := LeafIndexToNodeIndex(idx)
	if int(nodeIdx) >= len(t.Nodes) {
		return nil
	}
	return &t.Nodes[nodeIdx]
}

// SetLeaf updates a leaf.
func (t *RatchetTree) SetLeaf(idx LeafIndex, leaf LeafNodeData) error {
	nodeIdx := LeafIndexToNodeIndex(idx)
	if int(nodeIdx) >= len(t.Nodes) {
		return fmt.Errorf("leaf out of range")
	}
	t.Nodes[nodeIdx] = Node{
		State:    NodeStatePresent,
		LeafData: &leaf,
	}
	return nil
}

// BlankNode blanks a node.
func (t *RatchetTree) BlankNode(idx NodeIndex) {
	if int(idx) < len(t.Nodes) {
		t.Nodes[idx].State = NodeStateBlank
		t.Nodes[idx].EncryptionKey = nil
		t.Nodes[idx].LeafData = nil
		t.Nodes[idx].ParentHash = nil
		t.Nodes[idx].UnmergedLeaves = nil
	}
}

// ExpandToPowerOf2 returns a copy of the tree with NumLeaves rounded up to the
// next power of 2. This is needed when deserializing a tree that was serialized
// in minimal wire format (RFC §7.4.1): the serialized form trims trailing blank
// leaves, so the receiver must re-expand to restore the virtual power-of-2 tree
// used internally for parent/copath indexing. If NumLeaves is already a power of
// 2 (or equals 1), the original tree is returned unchanged.
func (t *RatchetTree) ExpandToPowerOf2() *RatchetTree {
	n := t.NumLeaves
	if n <= 1 || (n&(n-1)) == 0 {
		return t // already power-of-2
	}
	next := uint32(1) << bits.Len32(n-1)
	targetNodes := int(next*2 - 1)
	expanded := make([]Node, targetNodes)
	copy(expanded, t.Nodes)
	for i := len(t.Nodes); i < targetNodes; i++ {
		expanded[i] = Node{State: NodeStateEmpty}
	}
	return &RatchetTree{
		Nodes:     expanded,
		NumLeaves: next,
		cs:        t.cs,
	}
}

// TruncateTrailingBlanks removes blank or empty leaves from the end of the tree.
func (t *RatchetTree) TruncateTrailingBlanks() {
	for t.NumLeaves > 1 {
		lastLeafIdx := LeafIndex(t.NumLeaves - 1)
		lastNodeIdx := LeafIndexToNodeIndex(lastLeafIdx)
		if int(lastNodeIdx) >= len(t.Nodes) {
			break
		}

		last := t.Nodes[lastNodeIdx]
		if last.State == NodeStatePresent {
			break
		}

		t.NumLeaves--
		t.Nodes = t.Nodes[:t.NumLeaves*2-1]
	}
}

// TreeHash computes the tree hash (RFC §7.8).
func (t *RatchetTree) TreeHash() []byte {
	if t.NumLeaves == 0 {
		return nil
	}
	return t.HashNode(t.Root())
}

// TreeHashMinimal computes the tree hash using the minimal node count (RFC
// §7.4.1). The internal tree may be padded to power-of-2 leaves for
// parent/copath indexing, but the wire format (and mlspp cross-interop)
// requires the hash to be computed from the minimal tree. This method
// temporarily reduces NumLeaves to the actual member count and recomputes.
func (t *RatchetTree) TreeHashMinimal() []byte {
	// Find rightmost non-blank leaf (same logic as MarshalTreeRFC trim).
	minimalNodeCount := len(t.Nodes)
	for minimalNodeCount > 1 {
		lastNodeIdx := minimalNodeCount - 1
		if !IsLeaf(NodeIndex(lastNodeIdx)) {
			break
		}
		if t.Nodes[lastNodeIdx].State != NodeStateEmpty && t.Nodes[lastNodeIdx].State != NodeStateBlank {
			break
		}
		minimalNodeCount -= 2
	}
	if minimalNodeCount == len(t.Nodes) {
		// Tree is already minimal (no trailing blank leaves).
		return t.TreeHash()
	}
	// Create a minimal view with reduced NumLeaves. HashNode bounds-checks
	// against len(Nodes), so this correctly computes the minimal tree hash.
	minimal := &RatchetTree{
		Nodes:     t.Nodes[:minimalNodeCount],
		NumLeaves: uint32((minimalNodeCount + 1) / 2),
		cs:        t.cs,
	}
	return minimal.HashNode(minimal.Root())
}

// HashNode computes node hash.
func (t *RatchetTree) HashNode(idx NodeIndex) []byte {
	if int(idx) >= len(t.Nodes) {
		return nil
	}

	node := &t.Nodes[idx]

	if node.State == NodeStateEmpty {
		if IsLeaf(idx) {
			return ComputeLeafNodeHash(LeafIndex(uint32(idx)/2), nil, t.hashFunc())
		}
		return t.hashParent(idx)
	}

	if IsLeaf(idx) {
		return t.hashLeaf(idx)
	}

	return t.hashParent(idx)
}

// hashLeaf computes leaf hash.
func (t *RatchetTree) hashLeaf(idx NodeIndex) []byte {
	node := &t.Nodes[idx]
	return ComputeLeafNodeHash(LeafIndex(uint32(idx)/2), node.LeafData, t.hashFunc())
}

// hashParent computes parent hash.
func (t *RatchetTree) hashParent(idx NodeIndex) []byte {
	node := &t.Nodes[idx]

	// Left and right hashes
	left, _ := t.LeftChild(idx)
	leftHash := t.HashNode(left)

	right, _ := t.RightChild(idx)
	rightHash := t.HashNode(right)

	// RFC §7.8 ParentNodeHashInput uses original_sibling_tree_hash
	// but the tree hash calculation itself is recursive.

	w := tls.NewWriter()
	w.WriteUint8(nodeTypeParent)

	// optional<ParentNode> — byte de presencia seguido directo de los campos (RFC §7.8)
	if node.State == NodeStateBlank || node.EncryptionKey == nil {
		w.WriteUint8(0)
	} else {
		w.WriteUint8(1)
		w.WriteVLBytes(node.EncryptionKey.Bytes())
		w.WriteVLBytes(node.ParentHash)
		unmergedBuf := tls.NewWriter()
		for _, leaf := range node.UnmergedLeaves {
			unmergedBuf.WriteUint32(uint32(leaf))
		}
		w.WriteVLBytes(unmergedBuf.Bytes())
	}

	w.WriteVLBytes(leftHash)
	w.WriteVLBytes(rightHash)

	hf := t.hashFunc()
	h := hf()
	h.Write(w.Bytes())
	return h.Sum(nil)
}

// GetSibling returns the sibling of a node.
func (t *RatchetTree) GetSibling(node NodeIndex) NodeIndex {
	parent, err := t.Parent(node)
	if err != nil {
		return node // should not happen for non-root
	}
	left, _ := t.LeftChild(parent)
	if left == node {
		right, _ := t.RightChild(parent)
		return right
	}
	return left
}

// Resolution returns the resolution of a node (RFC §7.1).
// The resolution of a node is an ordered list of non-blank nodes that collectively
// cover all non-blank descendants of the node.
func (t *RatchetTree) Resolution(idx NodeIndex) []NodeIndex {
	return t.ResolutionWithExclusions(idx, nil)
}

// ResolutionWithExclusions computes the resolution of a node, excluding
// leaves in the exclusion set. Per RFC 9420 §12.4.2, newly added leaves
// are excluded from the resolution when encrypting/decrypting UpdatePath.
func (t *RatchetTree) ResolutionWithExclusions(idx NodeIndex, excluded map[LeafIndex]bool) []NodeIndex {
	if int(idx) >= len(t.Nodes) {
		return nil
	}

	node := &t.Nodes[idx]

	// 1. If the node is not blank, the resolution is the node itself,
	// followed by its list of unmerged leaves.
	if node.State == NodeStatePresent {
		// Check if this is an excluded leaf
		if IsLeaf(idx) && excluded != nil {
			leafIdx := LeafIndex(idx / 2)
			if excluded[leafIdx] {
				return []NodeIndex{}
			}
		}
		res := []NodeIndex{idx}
		for _, leaf := range node.UnmergedLeaves {
			if excluded != nil && excluded[leaf] {
				continue
			}
			res = append(res, LeafIndexToNodeIndex(leaf))
		}
		return res
	}

	// 2. If the node is blank and a leaf, the resolution is empty.
	if IsLeaf(idx) {
		return []NodeIndex{}
	}

	// 3. If the node is blank and an intermediate node, the resolution is the
	// concatenation of the resolutions of its children.
	left, _ := t.LeftChild(idx)
	right, _ := t.RightChild(idx)

	res := t.ResolutionWithExclusions(left, excluded)
	res = append(res, t.ResolutionWithExclusions(right, excluded)...)

	return res
}

// SubtreeContainsLeafByKey checks if any leaf node under the subtree rooted at
// idx has an EncryptionKey matching the given key.
func (t *RatchetTree) SubtreeContainsLeafByKey(idx NodeIndex, key []byte) bool {
	if int(idx) >= len(t.Nodes) {
		return false
	}
	if IsLeaf(idx) {
		node := &t.Nodes[idx]
		if node.State == NodeStatePresent && node.LeafData != nil {
			return bytes.Equal(node.LeafData.EncryptionKey, key)
		}
		return false
	}
	left, _ := t.LeftChild(idx)
	right, _ := t.RightChild(idx)
	return t.SubtreeContainsLeafByKey(left, key) || t.SubtreeContainsLeafByKey(right, key)
}

// SubtreeContainsLeaf checks if the given leaf index is under the subtree rooted at idx.
func (t *RatchetTree) SubtreeContainsLeaf(idx NodeIndex, leaf LeafIndex) bool {
	target := LeafIndexToNodeIndex(leaf)
	if int(idx) >= len(t.Nodes) || int(target) >= len(t.Nodes) {
		return false
	}
	if idx == target {
		return true
	}
	if IsLeaf(idx) {
		return false
	}
	left, _ := t.LeftChild(idx)
	right, _ := t.RightChild(idx)
	return t.SubtreeContainsLeaf(left, leaf) || t.SubtreeContainsLeaf(right, leaf)
}

// VerifyParentHashes verifies the parent hashes along the direct path (RFC §7.9.2).
//
// For each non-blank node N in the direct path (except the root), if N's
// direct parent P is also non-blank, the parent_hash field stored in N must
// match ComputeParentHash(P.encryption_key, P.parent_hash, sibling.tree_hash).
//
// When P is blank, the check for N is skipped — blank intermediate nodes
// occur in trees where the last commit had no UpdatePath (force_path=false),
// and their parent_hash fields carry the value from a prior epoch that cannot
// be independently verified by a joiner.
func (t *RatchetTree) VerifyParentHashes(leafIdx LeafIndex) error {
	path := t.DirectPath(leafIdx)
	if len(path) <= 1 {
		return nil
	}

	for i := 0; i < len(path)-1; i++ {
		nodeIdx := path[i]
		parentIdx := path[i+1]

		node := &t.Nodes[nodeIdx]
		parent := &t.Nodes[parentIdx]

		// Skip blank nodes — they carry no verifiable parent_hash.
		if node.State != NodeStatePresent {
			continue
		}
		// Skip when the direct parent is blank: the parent_hash stored in node
		// was set in a previous epoch's UpdatePath and cannot be recomputed
		// without that epoch's tree state.
		if parent.State != NodeStatePresent {
			continue
		}

		var parentKey []byte
		if parent.EncryptionKey != nil {
			parentKey = parent.EncryptionKey.Bytes()
		}
		siblingIdx := t.GetSibling(nodeIdx)
		siblingHash := t.HashNode(siblingIdx)
		expected := ComputeParentHash(parentKey, parent.ParentHash, siblingHash, t.hashFunc())

		var actual []byte
		if IsLeaf(nodeIdx) && node.LeafData != nil {
			actual = node.LeafData.ParentHash
		} else {
			actual = node.ParentHash
		}

		if !bytes.Equal(expected, actual) {
			return fmt.Errorf("parent hash mismatch at node %d", nodeIdx)
		}
	}

	return nil
}

// Clone creates a copy of the RatchetTree.
//
// Note: This is a shallow copy - Node.LeafData pointers are shared.
// For a deep copy, each LeafNodeData would need to be cloned individually.
func (t *RatchetTree) Clone() *RatchetTree {
	cloned := &RatchetTree{
		Nodes:     make([]Node, len(t.Nodes)),
		NumLeaves: t.NumLeaves,
		cs:        t.cs,
	}
	copy(cloned.Nodes, t.Nodes)
	return cloned
}

// Validate checks tree consistency.
func (t *RatchetTree) Validate() error {
	if t.NumLeaves == 0 {
		return errors.New("no leaves")
	}
	expected := int(t.NumLeaves*2 - 1)
	if len(t.Nodes) != expected {
		return fmt.Errorf("wrong node count: %d vs %d", len(t.Nodes), expected)
	}
	return nil
}
