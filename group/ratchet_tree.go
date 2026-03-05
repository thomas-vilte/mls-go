package group

import (
	"crypto/sha256"

	"github.com/openmls/go/ciphersuite"
	keypackages "github.com/openmls/go/key_packages"
)

// RatchetTree represents the ratchet tree for a group.
type RatchetTree struct {
	CipherSuite ciphersuite.CipherSuite
	Leaves      []*TreeLeaf
	Nodes       []*TreeNode
}

// TreeLeaf represents a leaf in the ratchet tree.
type TreeLeaf struct {
	Index    LeafNodeIndex
	Node     *keypackages.LeafNode
	Unmerged []LeafNodeIndex
}

// TreeNode represents an intermediate node in the ratchet tree.
type TreeNode struct {
	PublicKey  []byte
	Unmerged   []LeafNodeIndex
	ParentHash []byte
}

// NewRatchetTree creates a new empty ratchet tree.
func NewRatchetTree(cs ciphersuite.CipherSuite) (*RatchetTree, error) {
	return &RatchetTree{
		CipherSuite: cs,
		Leaves:      make([]*TreeLeaf, 0),
		Nodes:       make([]*TreeNode, 0),
	}, nil
}

// AddLeaf adds a new leaf node to the tree.
func (rt *RatchetTree) AddLeaf(leafNode *keypackages.LeafNode) (LeafNodeIndex, error) {
	index := LeafNodeIndex(len(rt.Leaves))
	rt.Leaves = append(rt.Leaves, &TreeLeaf{
		Index: index,
		Node:  leafNode,
	})
	return index, nil
}

// RemoveLeaf removes a leaf from the tree.
func (rt *RatchetTree) RemoveLeaf(index LeafNodeIndex) {
	if int(index) < len(rt.Leaves) {
		rt.Leaves[index] = nil
	}
}

// TreeHash computes the hash of the tree.
func (rt *RatchetTree) TreeHash() []byte {
	// Simplified implementation
	hash := sha256.New()
	for _, leaf := range rt.Leaves {
		if leaf != nil && leaf.Node != nil {
			hash.Write(leaf.Node.EncryptionKey)
		}
	}
	return hash.Sum(nil)
}

// Export exports the tree for serialization.
func (rt *RatchetTree) Export() *RatchetTree {
	return rt
}

// BuildRatchetTree builds a ratchet tree from exported data.
func BuildRatchetTree(exported *RatchetTree, cs ciphersuite.CipherSuite) (*RatchetTree, error) {
	return exported, nil
}
