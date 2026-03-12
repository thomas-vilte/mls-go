// Package treesync - Tests exhaustivos para Ratchet Tree según RFC 9420 §7
package treesync

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/mls-go/credentials"
)

func createTestLeaf(t *testing.T, id string) LeafNodeData {
	t.Helper()
	cred := credentials.NewBasicCredential([]byte(id))
	encPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	return LeafNodeData{
		Credential:     cred,
		EncryptionKey:  encPriv.PublicKey().Bytes(),
		LeafNodeSource: 1,
	}
}

func TestNewRatchetTree(t *testing.T) {
	tests := []struct {
		name        string
		numLeaves   uint32
		expectNodes int
	}{
		{"zero_leaves", 0, 1},
		{"one_leaf", 1, 1},
		{"two_leaves", 2, 3},
		{"three_leaves", 3, 5}, // No expande a 4, usa 5 nodos
		{"four_leaves", 4, 7},
		{"five_leaves", 5, 9}, // No expande a 8, usa 9 nodos
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := NewRatchetTree(tt.numLeaves)
			if len(tree.Nodes) != tt.expectNodes {
				t.Errorf("NewRatchetTree(%d) has %d nodes, want %d", tt.numLeaves, len(tree.Nodes), tt.expectNodes)
			}
		})
	}
}

func TestLeafCount(t *testing.T) {
	tree := NewRatchetTree(5)
	if tree.LeafCount() != 5 {
		t.Errorf("LeafCount() = %d, want 5", tree.LeafCount())
	}
}

func TestIsLeaf_IsParent(t *testing.T) {
	tests := []struct {
		idx        NodeIndex
		wantLeaf   bool
		wantParent bool
	}{
		{0, true, false},
		{1, false, true},
		{2, true, false},
		{3, false, true},
	}

	for _, tt := range tests {
		t.Run(fmtUint32(uint32(tt.idx)), func(t *testing.T) {
			if got := IsLeaf(tt.idx); got != tt.wantLeaf {
				t.Errorf("IsLeaf(%d) = %v, want %v", tt.idx, got, tt.wantLeaf)
			}
			if got := IsParent(tt.idx); got != tt.wantParent {
				t.Errorf("IsParent(%d) = %v, want %v", tt.idx, got, tt.wantParent)
			}
		})
	}
}

func TestParent(t *testing.T) {
	tree := NewRatchetTree(4)
	tests := []struct {
		idx     NodeIndex
		want    NodeIndex
		wantErr bool
	}{
		{0, 1, false},
		{2, 1, false},
		{1, 3, false},
		{3, 0, true}, // Root
	}

	for _, tt := range tests {
		t.Run(fmtUint32(uint32(tt.idx)), func(t *testing.T) {
			got, err := tree.Parent(tt.idx)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Parent(%d) err = %v", tt.idx, err)
			}
			if got != tt.want {
				t.Errorf("Parent(%d) = %d, want %d", tt.idx, got, tt.want)
			}
		})
	}
}

func TestLeftChild_RightChild(t *testing.T) {
	tree := NewRatchetTree(4)
	tests := []struct {
		idx       NodeIndex
		wantLeft  NodeIndex
		wantRight NodeIndex
		wantErr   bool
	}{
		{3, 1, 5, false},
		{1, 0, 2, false},
		{5, 4, 6, false},
		{0, 0, 0, true}, // Leaf
	}

	for _, tt := range tests {
		t.Run(fmtUint32(uint32(tt.idx)), func(t *testing.T) {
			left, lerr := tree.LeftChild(tt.idx)
			right, rerr := tree.RightChild(tt.idx)
			if (lerr != nil) != tt.wantErr {
				t.Fatalf("LeftChild(%d) err = %v", tt.idx, lerr)
			}
			if (rerr != nil) != tt.wantErr {
				t.Fatalf("RightChild(%d) err = %v", tt.idx, rerr)
			}
			if left != tt.wantLeft {
				t.Errorf("LeftChild(%d) = %d, want %d", tt.idx, left, tt.wantLeft)
			}
			if right != tt.wantRight {
				t.Errorf("RightChild(%d) = %d, want %d", tt.idx, right, tt.wantRight)
			}
		})
	}
}

func TestGetSibling(t *testing.T) {
	tree := NewRatchetTree(4)
	tests := []struct {
		idx  NodeIndex
		want NodeIndex
	}{
		{0, 2},
		{2, 0},
		{4, 6},
		{6, 4},
		{1, 5},
		{5, 1},
	}

	for _, tt := range tests {
		t.Run(fmtUint32(uint32(tt.idx)), func(t *testing.T) {
			got := tree.GetSibling(tt.idx)
			if got != tt.want {
				t.Errorf("GetSibling(%d) = %d, want %d", tt.idx, got, tt.want)
			}
		})
	}
}

func TestRoot(t *testing.T) {
	tests := []struct {
		name      string
		numLeaves uint32
		wantRoot  NodeIndex
	}{
		{"1_leaf", 1, 0},
		{"2_leaves", 2, 1},
		{"3_leaves", 3, 3},
		{"4_leaves", 4, 3},
		{"5_leaves", 5, 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := NewRatchetTree(tt.numLeaves)
			got := tree.Root()
			if got != tt.wantRoot {
				t.Errorf("Root() = %d, want %d", got, tt.wantRoot)
			}
		})
	}
}

func TestDirectPath_Copath(t *testing.T) {
	tree := NewRatchetTree(4)

	// Direct path from leaf 0: [0, 1, 3]
	direct := tree.DirectPath(0)
	wantDirect := []NodeIndex{0, 1, 3}
	if !nodeIndexSliceEqual(direct, wantDirect) {
		t.Errorf("DirectPath(0) = %v, want %v", direct, wantDirect)
	}

	// Copath from leaf 0: [2, 5]
	copath := tree.Copath(0)
	wantCopath := []NodeIndex{2, 5}
	if !nodeIndexSliceEqual(copath, wantCopath) {
		t.Errorf("Copath(0) = %v, want %v", copath, wantCopath)
	}
}

func TestResolution(t *testing.T) {
	tree := NewRatchetTree(4)

	// Add some leaves
	for i := 0; i < 4; i++ {
		leaf := createTestLeaf(t, string(rune('A'+i)))
		tree.AddLeaf(leaf)
	}

	// Resolution of present node
	res := tree.Resolution(1)
	if len(res) == 0 {
		t.Error("Resolution of present node should not be empty")
	}

	// Resolution of excluded leaf
	excluded := map[LeafIndex]bool{0: true}
	res = tree.ResolutionWithExclusions(0, excluded)
	if len(res) != 0 {
		t.Errorf("Resolution of excluded leaf = %v, want empty", res)
	}
}

func TestTreeHash(t *testing.T) {
	tree := NewRatchetTree(4)
	hash := tree.TreeHash()
	if len(hash) == 0 {
		t.Error("TreeHash() returned empty hash")
	}

	// Deterministic
	hash2 := tree.TreeHash()
	if !bytes.Equal(hash, hash2) {
		t.Error("TreeHash() is not deterministic")
	}
}

func TestHashNode(t *testing.T) {
	tree := NewRatchetTree(4)
	leafHash := tree.HashNode(0)
	parentHash := tree.HashNode(1)

	if len(leafHash) == 0 {
		t.Error("HashNode(leaf) returned empty hash")
	}
	if len(parentHash) == 0 {
		t.Error("HashNode(parent) returned empty hash")
	}
	if bytes.Equal(leafHash, parentHash) {
		t.Error("Leaf and parent hashes should be different")
	}
}

func TestAddLeaf(t *testing.T) {
	tree := NewRatchetTree(2)
	leaf := createTestLeaf(t, "Test")
	leafIdx, _ := tree.AddLeaf(leaf)

	if leafIdx != 0 {
		t.Errorf("AddLeaf() leafIdx = %d, want 0", leafIdx)
	}

	node := tree.GetLeaf(leafIdx)
	if node == nil {
		t.Fatal("GetLeaf() returned nil")
	}
	if node.State != NodeStatePresent {
		t.Errorf("Leaf state = %v, want NodeStatePresent", node.State)
	}
}

func TestClone(t *testing.T) {
	tree := NewRatchetTree(4)
	clone := tree.Clone()

	if clone == tree {
		t.Fatal("Clone() should return different instance")
	}
	if !bytes.Equal(clone.TreeHash(), tree.TreeHash()) {
		t.Error("Clone() tree hash differs")
	}

	clone.NumLeaves = 999
	if tree.NumLeaves == 999 {
		t.Error("Modifying clone affected original")
	}
}

func nodeIndexSliceEqual(a, b []NodeIndex) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func fmtUint32(v uint32) string {
	if v < 100 {
		return string(rune('0' + v%10))
	}
	return "large"
}
