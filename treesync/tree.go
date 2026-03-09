// Package treesync implements MLS ratchet tree operations according to RFC 9420 §7.
//
// Uses RFC Appendix C interleaved representation:
// - Leaves at indices 0, 2, 4, 6, ... (even)
// - Parents at indices 1, 3, 5, 7, ... (odd)
package treesync

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"

	"github.com/openmls/go/credentials"
	"github.com/openmls/go/internal/tls"
)

// NodeIndex represents a node in the tree (interleaved representation).
type NodeIndex uint32

// LeafIndex represents a leaf position.
type LeafIndex uint32

// NodeState represents the state of a node.
type NodeState uint8

const (
	NodeStateEmpty NodeState = iota
	NodeStatePresent
	NodeStateBlank
)

// RatchetTree represents the MLS ratchet tree.
type RatchetTree struct {
	Nodes     []Node
	NumLeaves uint32
}

// Node represents a node in the tree.
type Node struct {
	State          NodeState
	EncryptionKey  *ecdh.PublicKey
	ParentHash     []byte
	UnmergedLeaves []LeafIndex
	LeafData       *LeafNodeData
}

// LeafNodeData contains leaf-specific data.
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

// LeafNodeCapabilities represents node capabilities.
type LeafNodeCapabilities struct {
	ProtocolVersions []uint16
	CipherSuites     []uint16
	Extensions       []uint16
	Proposals        []uint16
	Credentials      []uint16
}

// LeafNodeLifetime represents validity period.
type LeafNodeLifetime struct {
	NotBefore uint64
	NotAfter  uint64
}

// NewRatchetTree creates a tree with N leaves.
func NewRatchetTree(numLeaves uint32) *RatchetTree {
	if numLeaves < 1 {
		numLeaves = 1
	}
	return &RatchetTree{
		Nodes:     make([]Node, numLeaves*2-1),
		NumLeaves: numLeaves,
	}
}

// LeafCount returns the number of leaves.
func (t *RatchetTree) LeafCount() uint32 {
	return t.NumLeaves
}

// IsLeaf returns true if node index is even (leaf).
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

// nodeLevel retorna el nivel de un nodo en la representación intercalada (RFC Apéndice C).
// Las hojas están en nivel 0; se cuenta cuántos bits 1 consecutivos tiene x desde el bit 0.
func nodeLevel(x uint32) uint32 {
	// Trailing ones = trailing zeros of ^x
	return uint32(bits.TrailingZeros32(^x))
}

// Root retorna el índice del nodo raíz según RFC Apéndice C:
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

// Parent retorna el padre de un nodo según RFC Apéndice C.
//
// Si el bit (l+1) del nodo es 0, es hijo izquierdo → padre = x + 2^l.
// Si el bit (l+1) del nodo es 1, es hijo derecho → padre = x - 2^l.
// En árboles no potencia-de-2 el resultado puede exceder la raíz; se acota.
func (t *RatchetTree) Parent(node NodeIndex) (NodeIndex, error) {
	root := t.Root()
	if node == root {
		return 0, fmt.Errorf("root has no parent")
	}

	l := nodeLevel(uint32(node))
	var p NodeIndex
	if (uint32(node)>>(l+1))&1 == 0 {
		// hijo izquierdo: padre está a la derecha
		p = node + NodeIndex(1<<l)
	} else {
		// hijo derecho: padre está a la izquierda
		p = node - NodeIndex(1<<l)
	}

	// Para árboles no potencia-de-2, el padre "natural" puede caer fuera
	// del rango válido (0..2n-2); en ese caso se usa la raíz.
	maxIdx := NodeIndex(t.NumLeaves*2 - 2)
	if p > maxIdx {
		p = root
	}

	return p, nil
}

// LeftChild retorna el hijo izquierdo de un nodo padre (RFC Apéndice C):
//
//	left_child(x) = x ^ (1 << (level(x) - 1))
func (t *RatchetTree) LeftChild(parent NodeIndex) (NodeIndex, error) {
	if !IsParent(parent) {
		return 0, fmt.Errorf("not a parent node")
	}

	l := nodeLevel(uint32(parent))
	return NodeIndex(uint32(parent) ^ (1 << (l - 1))), nil
}

// RightChild retorna el hijo derecho de un nodo padre (RFC Apéndice C):
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
	// Find first empty leaf
	for i := LeafIndex(0); i < LeafIndex(t.NumLeaves); i++ {
		nodeIdx := LeafIndexToNodeIndex(i)
		if int(nodeIdx) < len(t.Nodes) && t.Nodes[nodeIdx].State == NodeStateEmpty {
			t.Nodes[nodeIdx] = Node{
				State:    NodeStatePresent,
				LeafData: &leaf,
			}
			return i, nodeIdx
		}
	}

	// Expand tree if needed
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
	return i, nodeIdx
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

// HashNode computes node hash.
func (t *RatchetTree) HashNode(idx NodeIndex) []byte {
	if int(idx) >= len(t.Nodes) {
		return nil
	}

	node := &t.Nodes[idx]

	if node.State == NodeStateEmpty {
		if IsLeaf(idx) {
			return ComputeLeafNodeHash(LeafIndex(uint32(idx)/2), nil)
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
	return ComputeLeafNodeHash(LeafIndex(uint32(idx)/2), node.LeafData)
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

	hash := sha256.Sum256(w.Bytes())
	return hash[:]
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
	if int(idx) >= len(t.Nodes) {
		return nil
	}

	node := &t.Nodes[idx]

	// 1. If the node is not blank, the resolution is the node itself,
	// followed by its list of unmerged leaves.
	if node.State == NodeStatePresent {
		res := []NodeIndex{idx}
		for _, leaf := range node.UnmergedLeaves {
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

	res := t.Resolution(left)
	res = append(res, t.Resolution(right)...)

	return res
}

// VerifyParentHashes verifica los parent hashes a lo largo del direct path (RFC §7.9).
//
// Para cada nodo del camino (excepto la raíz), el parent_hash almacenado en ese nodo
// debe coincidir con ComputeParentHash(padre.EncryptionKey, padre.ParentHash, hermano.TreeHash).
func (t *RatchetTree) VerifyParentHashes(leafIdx LeafIndex) error {
	path := t.DirectPath(leafIdx)
	if len(path) <= 1 {
		return nil
	}

	for i := 0; i < len(path)-1; i++ {
		nodeIdx := path[i]
		parentIdx, _ := t.Parent(nodeIdx)

		node := &t.Nodes[nodeIdx]
		parent := &t.Nodes[parentIdx]

		if node.State != NodeStatePresent {
			continue
		}

		siblingIdx := t.GetSibling(nodeIdx)
		siblingHash := t.HashNode(siblingIdx)

		var parentKey []byte
		if parent.EncryptionKey != nil {
			parentKey = parent.EncryptionKey.Bytes()
		}

		expected := ComputeParentHash(parentKey, parent.ParentHash, siblingHash)

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

func (t *RatchetTree) Clone() *RatchetTree {
	cloned := &RatchetTree{
		Nodes:     make([]Node, len(t.Nodes)),
		NumLeaves: t.NumLeaves,
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
