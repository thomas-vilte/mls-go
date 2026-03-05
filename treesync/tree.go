// Package treesync implements MLS ratchet tree operations according to RFC 9420 §7.
//
// The ratchet tree is the core data structure that enables efficient group key
// agreement. It's a binary tree where each leaf represents a group member.
package treesync

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"

	"github.com/openmls/go/credentials"
	"github.com/openmls/go/internal/tls"
)

// NodeIndex represents the index of a node in the tree.
type NodeIndex uint32

// LeafIndex represents the index of a leaf (member) in the tree.
type LeafIndex uint32

// NodeState represents the state of a tree node.
type NodeState uint8

const (
	NodeStateEmpty NodeState = iota
	NodeStatePresent
	NodeStateBlank
)

// RatchetTree is the main tree structure for MLS group key agreement.
type RatchetTree struct {
	Nodes      []Node
	NumLeaves  uint32
	cachedHash []byte
	hashDirty  bool
}

// Node represents a node in the ratchet tree.
type Node struct {
	State          NodeState
	EncryptionKey  *ecdh.PublicKey
	ParentHash     []byte
	UnmergedLeaves []LeafIndex
	LeafData       *LeafNodeData
}

// LeafNodeData contains the data specific to leaf nodes.
type LeafNodeData struct {
	Credential     *credentials.Credential
	SignatureKey   *ecdsa.PublicKey
	EncryptionKey  []byte
	Capabilities   *LeafNodeCapabilities
	Lifetime       *LeafNodeLifetime
	Extensions     [][]byte // Raw extension data to avoid import cycle
	LeafNodeSource uint8
	ParentHash     []byte
	Signature      []byte
}

// LeafNodeCapabilities mirrors the KeyPackage capabilities.
type LeafNodeCapabilities struct {
	ProtocolVersions []uint16
	CipherSuites     []uint16
	Extensions       []uint16
	Proposals        []uint16
	Credentials      []uint16
}

// LeafNodeLifetime indicates the validity period of a leaf node.
type LeafNodeLifetime struct {
	NotBefore uint64
	NotAfter  uint64
}

// NewRatchetTree creates a new ratchet tree with the specified capacity.
func NewRatchetTree(numLeaves uint32) *RatchetTree {
	totalNodes := int(numLeaves)*2 - 1
	if totalNodes < 1 {
		totalNodes = 1
	}

	return &RatchetTree{
		Nodes:     make([]Node, totalNodes),
		NumLeaves: numLeaves,
		hashDirty: true,
	}
}

// AddLeaf adds a new leaf to the tree.
//
// In the standard heap representation, leaves occupy the last N positions.
// This function finds the first empty leaf slot and places the new leaf there.
func (t *RatchetTree) AddLeaf(leaf LeafNodeData) (LeafIndex, NodeIndex) {
	// Find first empty leaf slot
	// Leaves are at indices [numLeaves-1, numLeaves*2-2]
	var leafIdx LeafIndex
	var found bool
	
	startIdx := NodeIndex(t.NumLeaves - 1)
	endIdx := NodeIndex(t.NumLeaves*2 - 2)
	
	for nodeIdx := startIdx; nodeIdx <= endIdx; nodeIdx++ {
		if t.Nodes[nodeIdx].State == NodeStateEmpty {
			leafIdx = LeafIndex(nodeIdx - startIdx)
			found = true
			break
		}
	}

	// If no empty leaf found, expand the tree
	if !found {
		leafIdx = LeafIndex(t.NumLeaves)
		t.expandTree(t.NumLeaves + 1)
	}

	nodeIdx := NodeIndex(t.NumLeaves - 1 + uint32(leafIdx))

	t.Nodes[nodeIdx] = Node{
		State:    NodeStatePresent,
		LeafData: &leaf,
	}

	t.hashDirty = true
	return leafIdx, nodeIdx
}

// GetLeaf returns the leaf at the given index.
func (t *RatchetTree) GetLeaf(index LeafIndex) *Node {
	if t.NumLeaves == 0 {
		return nil
	}
	nodeIdx := NodeIndex(t.NumLeaves - 1 + uint32(index))
	if int(nodeIdx) >= len(t.Nodes) {
		return nil
	}
	return &t.Nodes[nodeIdx]
}

// SetLeaf sets the leaf at the given index.
func (t *RatchetTree) SetLeaf(index LeafIndex, leaf LeafNodeData) error {
	if t.NumLeaves == 0 {
		return errors.New("tree has no leaves")
	}
	nodeIdx := NodeIndex(t.NumLeaves - 1 + uint32(index))
	if int(nodeIdx) >= len(t.Nodes) {
		return errors.New("leaf index out of bounds")
	}

	t.Nodes[nodeIdx] = Node{
		State:    NodeStatePresent,
		LeafData: &leaf,
	}

	t.hashDirty = true
	return nil
}

// BlankNode marks a node as blank (removed).
func (t *RatchetTree) BlankNode(index NodeIndex) {
	if int(index) >= len(t.Nodes) {
		return
	}

	t.Nodes[index].State = NodeStateBlank
	t.Nodes[index].EncryptionKey = nil
	t.Nodes[index].LeafData = nil
	t.Nodes[index].ParentHash = []byte{}
	t.hashDirty = true
}

// TreeHash computes the hash of the entire tree (RFC 9420 §7.8).
func (t *RatchetTree) TreeHash() []byte {
	if len(t.Nodes) == 0 {
		hash := sha256.Sum256([]byte{})
		return hash[:]
	}

	// Root is always at index 0 in array-based tree representation
	return t.hashNode(0)
}

// hashNode computes the hash of a single node according to RFC 9420 §7.8.
//
// Tree representation (array-based, RFC 9420 Appendix C):
//   - Root is at index 0
//   - For node i: left child = 2i+1, right child = 2i+2
//   - Leaves are at indices [numLeaves-1, numLeaves*2-2]
//   - Parents are at indices [0, numLeaves-2]
func (t *RatchetTree) hashNode(index NodeIndex) []byte {
	if int(index) >= len(t.Nodes) {
		hash := sha256.Sum256([]byte{})
		return hash[:]
	}

	node := &t.Nodes[index]
	buf := tls.NewWriter()

	// Check if this is a leaf node
	// Leaves are at indices >= numLeaves-1
	isLeaf := index >= NodeIndex(t.NumLeaves-1)

	if isLeaf {
		// Leaf node hash: Hash(0x01 || leaf_index || LeafNode)
		buf.WriteUint8(1)
		
		// Convert node index to leaf index
		leafIndex := index - NodeIndex(t.NumLeaves-1)
		buf.WriteUint32(uint32(leafIndex))

		if node.State == NodeStatePresent && node.LeafData != nil {
			buf.WriteUint8(1)
			buf.WriteRaw(node.LeafData.Marshal())
		} else if node.State == NodeStateBlank {
			buf.WriteUint8(1)
			// Blank leaf - write minimal LeafNodeData
			emptyLeaf := &LeafNodeData{
				EncryptionKey: []byte{},
				Signature:     []byte{},
			}
			buf.WriteRaw(emptyLeaf.Marshal())
		} else {
			// NodeStateEmpty
			buf.WriteUint8(0)
		}
	} else {
		// Parent node hash: Hash(0x02 || left_hash || right_hash || ParentNode)
		buf.WriteUint8(2)

		leftChild := index*2 + 1
		rightChild := index*2 + 2

		var leftHash, rightHash []byte
		if leftChild < NodeIndex(len(t.Nodes)) {
			leftHash = t.hashNode(leftChild)
		} else {
			hash := sha256.Sum256([]byte{})
			leftHash = hash[:]
		}

		if rightChild < NodeIndex(len(t.Nodes)) {
			rightHash = t.hashNode(rightChild)
		} else {
			hash := sha256.Sum256([]byte{})
			rightHash = hash[:]
		}

		buf.WriteVLBytes(leftHash)
		buf.WriteVLBytes(rightHash)

		if node.State == NodeStatePresent && node.EncryptionKey != nil {
			buf.WriteUint8(1)
			buf.WriteVLBytes(node.EncryptionKey.Bytes())
			buf.WriteVLBytes(node.ParentHash)

			unmergedBuf := tls.NewWriter()
			for _, leaf := range node.UnmergedLeaves {
				unmergedBuf.WriteUint32(uint32(leaf))
			}
			buf.WriteVLBytes(unmergedBuf.Bytes())
		} else if node.State == NodeStateBlank {
			buf.WriteUint8(1)
			buf.WriteVLBytes([]byte{})
			buf.WriteVLBytes([]byte{})
			buf.WriteVLBytes([]byte{})
		} else {
			// NodeStateEmpty
			buf.WriteUint8(0)
		}
	}

	hash := sha256.Sum256(buf.Bytes())
	return hash[:]
}

// expandTree expands the tree to accommodate more leaves.
func (t *RatchetTree) expandTree(newNumLeaves uint32) {
	if newNumLeaves <= t.NumLeaves {
		return
	}

	oldNumLeaves := t.NumLeaves
	t.NumLeaves = newNumLeaves

	// Calculate new total nodes: for N leaves, we need 2N-1 nodes
	newTotalNodes := int(newNumLeaves)*2 - 1
	newNodes := make([]Node, newTotalNodes)

	// Copy old nodes to their new positions
	// In array representation, structure changes when we add leaves
	copy(newNodes, t.Nodes)

	// Initialize new leaf nodes as empty
	for i := oldNumLeaves; i < newNumLeaves; i++ {
		nodeIdx := int(newNumLeaves - 1 + i)
		if nodeIdx < len(newNodes) {
			newNodes[nodeIdx] = Node{
				State: NodeStateEmpty,
			}
		}
	}

	t.Nodes = newNodes
	t.hashDirty = true
}

// Clone creates a deep copy of the tree.
func (t *RatchetTree) Clone() *RatchetTree {
	result := &RatchetTree{
		Nodes:     make([]Node, len(t.Nodes)),
		NumLeaves: t.NumLeaves,
		hashDirty: t.hashDirty,
	}

	if t.cachedHash != nil {
		result.cachedHash = append([]byte(nil), t.cachedHash...)
	}

	for i := range t.Nodes {
		result.Nodes[i] = t.Nodes[i].clone()
	}

	return result
}

// Validate validates the tree structure.
func (t *RatchetTree) Validate() error {
	if t.NumLeaves == 0 {
		return errors.New("tree must have at least one leaf")
	}

	expectedNodes := int(t.NumLeaves)*2 - 1
	if len(t.Nodes) != expectedNodes {
		return fmt.Errorf("wrong number of nodes: got %d, want %d", len(t.Nodes), expectedNodes)
	}

	for i, node := range t.Nodes {
		if err := node.Validate(NodeIndex(i), t.NumLeaves); err != nil {
			return fmt.Errorf("node %d invalid: %w", i, err)
		}
	}

	return nil
}

// Helper functions for tree navigation

// LeftChild returns the left child of a node.
func LeftChild(index NodeIndex, numLeaves uint32) NodeIndex {
	if index >= NodeIndex(numLeaves*2-1) {
		return index
	}
	child := index*2 + 1
	if child >= NodeIndex(numLeaves*2-1) {
		return index
	}
	return child
}

// RightChild returns the right child of a node.
func RightChild(index NodeIndex, numLeaves uint32) NodeIndex {
	if index >= NodeIndex(numLeaves*2-1) {
		return index
	}
	child := index*2 + 2
	if child >= NodeIndex(numLeaves*2-1) {
		return index
	}
	return child
}

// Parent returns the parent of a node.
//
// For a binary tree stored in array form:
//   - Parent of node i is (i-1)/2 for i > 0
//   - Root (node 0) has no parent, returns 0
func Parent(index NodeIndex) NodeIndex {
	if index == 0 {
		return 0 // Root has no parent
	}
	return (index - 1) / 2
}

// Sibling returns the sibling of a node.
func Sibling(index NodeIndex) NodeIndex {
	if index == 0 {
		return 0
	}
	if index%2 == 0 {
		return index - 1
	}
	return index + 1
}

// DirectPath returns the direct path from a leaf to the root.
//
// The direct path consists of all parent nodes from the leaf's parent up to (but not including) the root.
// For a tree with N leaves, the direct path has length ceil(log2(N)).
func DirectPath(leaf LeafIndex, numLeaves uint32) []NodeIndex {
	if numLeaves == 0 {
		return []NodeIndex{}
	}
	
	var path []NodeIndex
	
	// Start from the leaf's node index
	// In our representation, leaf i is at node index (numLeaves - 1) + i
	// This is the standard heap representation where leaves are the last N nodes
	leafNodeIdx := NodeIndex(numLeaves - 1 + uint32(leaf))
	
	// Root is at index 0
	rootIdx := NodeIndex(0)
	
	// Walk up from leaf's parent to root's children
	nodeIdx := leafNodeIdx
	for nodeIdx > rootIdx {
		parentIdx := Parent(nodeIdx)
		if parentIdx == rootIdx {
			// Don't include the root in the direct path
			break
		}
		path = append(path, parentIdx)
		nodeIdx = parentIdx
	}

	return path
}

// Copath returns the copath (siblings) for a direct path.
func Copath(leaf LeafIndex, numLeaves uint32) []NodeIndex {
	directPath := DirectPath(leaf, numLeaves)
	copath := make([]NodeIndex, len(directPath))

	for i, nodeIdx := range directPath {
		copath[i] = Sibling(nodeIdx)
	}

	return copath
}

// Depth returns the depth of the tree.
func (t *RatchetTree) Depth() uint32 {
	if t.NumLeaves == 0 {
		return 0
	}
	return uint32(bits.Len32(t.NumLeaves - 1))
}

// LeafIndexToNodeIndex converts a leaf index to a node index.
//
// In the standard heap representation, leaves are the last N nodes in the array.
// For a tree with numLeaves leaves, leaf i is at node index (numLeaves - 1) + i.
// Note: This function requires knowing numLeaves, so it's deprecated.
// Use DirectPath() which handles this correctly.
func LeafIndexToNodeIndex(leafIdx LeafIndex) NodeIndex {
	// This is a simplified version that assumes leaf 0 is at node 0
	// For accurate conversion, use the formula: nodeIdx = (numLeaves - 1) + leafIdx
	return NodeIndex(leafIdx)
}

// NodeIndexToLeafIndex converts a node index to a leaf index.
// Only valid for leaf nodes (nodes >= numLeaves - 1).
func NodeIndexToLeafIndex(nodeIdx NodeIndex, numLeaves uint32) LeafIndex {
	if nodeIdx < NodeIndex(numLeaves-1) {
		return LeafIndex(0) // Not a leaf
	}
	return LeafIndex(nodeIdx - NodeIndex(numLeaves-1))
}

// SerializeRatchetTreeExtension serializes a ratchet tree for the GroupInfo extension.
// TODO: Implement full serialization according to RFC 9420 §12.4.3.3
func SerializeRatchetTreeExtension(tree *RatchetTree) ([]byte, error) {
	if tree == nil {
		return []byte{}, nil
	}
	// Stub implementation - returns empty for now
	return []byte{}, nil
}

// DeserializeRatchetTreeExtension deserializes a ratchet tree from the GroupInfo extension.
// TODO: Implement full deserialization according to RFC 9420 §12.4.3.3
func DeserializeRatchetTreeExtension(data []byte) (*RatchetTree, error) {
	// Stub implementation - returns nil tree
	return nil, nil
}
