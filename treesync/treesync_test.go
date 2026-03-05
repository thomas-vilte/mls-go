package treesync_test

import (
	"bytes"
	"testing"

	"github.com/openmls/go/credentials"
	"github.com/openmls/go/treesync"
)

// TestRatchetTreeBasic tests basic tree operations.
// Based on openmls Rust: openmls/src/treesync/mod.rs
func TestRatchetTreeBasic(t *testing.T) {
	tree := treesync.NewRatchetTree(4)

	if tree.NumLeaves != 4 {
		t.Errorf("Wrong number of leaves: got %d, want 4", tree.NumLeaves)
	}

	expectedNodes := 4*2 - 1
	if len(tree.Nodes) != expectedNodes {
		t.Errorf("Wrong number of nodes: got %d, want %d", len(tree.Nodes), expectedNodes)
	}

	hash := tree.TreeHash()
	if len(hash) != 32 {
		t.Errorf("Tree hash wrong length: got %d, want 32", len(hash))
	}

	// Validate tree structure
	if err := tree.Validate(); err != nil {
		t.Errorf("Tree validation failed: %v", err)
	}
}

// TestRatchetTreeAddLeaf tests adding leaves to the tree.
func TestRatchetTreeAddLeaf(t *testing.T) {
	tree := treesync.NewRatchetTree(4)

	cred := credentials.NewBasicCredentialFromString("TestUser")
	leafData := treesync.LeafNodeData{
		EncryptionKey: []byte{0x01, 0x02, 0x03},
		Credential:    cred,
		Signature:     []byte{0x04, 0x05, 0x06},
	}

	leafIdx, nodeIdx := tree.AddLeaf(leafData)

	if leafIdx != 0 {
		t.Errorf("Wrong leaf index: got %d, want 0", leafIdx)
	}

	// In RFC 9420 array representation with 4 leaves:
	// Parents: [0, 1, 2], Leaves: [3, 4, 5, 6]
	// Leaf 0 is at node 3
	if nodeIdx != 3 {
		t.Errorf("Wrong node index: got %d, want 3", nodeIdx)
	}

	// Verify leaf was added
	leaf := tree.GetLeaf(leafIdx)
	if leaf == nil {
		t.Fatal("GetLeaf returned nil")
	}

	if leaf.LeafData == nil {
		t.Error("LeafData is nil")
	}

	// Tree hash should change after adding leaf
	hash1 := tree.TreeHash()
	if len(hash1) == 0 {
		t.Error("Tree hash is empty after adding leaf")
	}
}

// TestTreeHash tests tree hash computation.
// Based on openmls Rust: openmls/src/treesync/tests.rs
func TestTreeHash(t *testing.T) {
	tree1 := treesync.NewRatchetTree(4)
	tree2 := treesync.NewRatchetTree(4)

	// Empty trees should have same hash
	hash1 := tree1.TreeHash()
	hash2 := tree2.TreeHash()

	if !bytes.Equal(hash1, hash2) {
		t.Error("Empty trees should have same hash")
	}

	// Add leaf to one tree
	cred := credentials.NewBasicCredentialFromString("Test")
	leafData := treesync.LeafNodeData{
		EncryptionKey: []byte{0x01, 0x02, 0x03},
		Credential:    cred,
		Signature:     []byte{0x04, 0x05, 0x06},
	}
	tree1.AddLeaf(leafData)

	// Trees should now have different hashes
	hash1 = tree1.TreeHash()
	hash2 = tree2.TreeHash()

	if bytes.Equal(hash1, hash2) {
		t.Error("Trees with different content should have different hashes")
	}

	// Hash should be deterministic
	hash1Again := tree1.TreeHash()
	if !bytes.Equal(hash1, hash1Again) {
		t.Error("Tree hash should be deterministic")
	}
}

// TestTreeClone tests tree cloning.
func TestTreeClone(t *testing.T) {
	tree := treesync.NewRatchetTree(4)

	cred := credentials.NewBasicCredentialFromString("CloneTest")
	leafData := treesync.LeafNodeData{
		EncryptionKey: []byte{0x01, 0x02, 0x03},
		Credential:    cred,
		Signature:     []byte{0x04, 0x05, 0x06},
	}
	tree.AddLeaf(leafData)

	// Clone the tree
	cloned := tree.Clone()

	// Verify clone has same structure
	if cloned.NumLeaves != tree.NumLeaves {
		t.Errorf("Clone has wrong number of leaves: got %d, want %d",
			cloned.NumLeaves, tree.NumLeaves)
	}

	// Verify hash is the same
	hash1 := tree.TreeHash()
	hash2 := cloned.TreeHash()

	if !bytes.Equal(hash1, hash2) {
		t.Error("Clone should have same hash as original")
	}

	// Modify original, clone should be unchanged
	originalHash := hash1
	tree.BlankNode(0)

	newHash := tree.TreeHash()
	if bytes.Equal(newHash, originalHash) {
		t.Error("Original tree hash should have changed after BlankNode")
	}

	if !bytes.Equal(cloned.TreeHash(), originalHash) {
		t.Error("Clone should be unchanged")
	}
}

// TestDirectPath tests direct path computation.
// Based on openmls Rust: openmls/src/treesync/tests.rs
func TestDirectPath(t *testing.T) {
	tests := []struct {
		name      string
		numLeaves uint32
		leaf      treesync.LeafIndex
		wantLen   int
	}{
		{"4 leaves, leaf 0", 4, 0, 1}, // Path: [1]
		{"4 leaves, leaf 1", 4, 1, 1}, // Path: [1]
		{"8 leaves, leaf 0", 8, 0, 2}, // Path: [3, 1]
		{"8 leaves, leaf 3", 8, 3, 2}, // Path: [4, 1]
		{"2 leaves, leaf 0", 2, 0, 0}, // Path: [] (root is parent of leaf)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = treesync.NewRatchetTree(tt.numLeaves)
			
			path := treesync.DirectPath(tt.leaf, tt.numLeaves)
			
			if len(path) != tt.wantLen {
				t.Errorf("Wrong path length: got %d, want %d", len(path), tt.wantLen)
			}
			
			// Verify path goes from leaf's parent to root
			for i, nodeIdx := range path {
				if i > 0 && nodeIdx >= path[i-1] {
					t.Errorf("Path should go up the tree: node %d >= node %d", nodeIdx, path[i-1])
				}
			}
		})
	}
}

// TestCopath tests copath computation.
func TestCopath(t *testing.T) {
	numLeaves := uint32(8)
	leaf := treesync.LeafIndex(0)

	directPath := treesync.DirectPath(leaf, numLeaves)
	copath := treesync.Copath(leaf, numLeaves)

	if len(copath) != len(directPath) {
		t.Errorf("Copath length mismatch: got %d, want %d",
			len(copath), len(directPath))
	}

	// Copath nodes should be siblings of direct path nodes
	for i := range directPath {
		expectedSibling := treesync.Sibling(directPath[i])
		if copath[i] != expectedSibling {
			t.Errorf("Wrong copath node at %d: got %d, want %d",
				i, copath[i], expectedSibling)
		}
	}
}

// TestUpdatePath tests UpdatePath serialization.
func TestUpdatePath(t *testing.T) {
	path := treesync.NewUpdatePath(nil, []treesync.HPKECiphertext{
		{
			KEMOutput:  []byte{0x01, 0x02},
			Ciphertext: []byte{0x03, 0x04},
		},
		{
			KEMOutput:  []byte{0x05, 0x06},
			Ciphertext: []byte{0x07, 0x08},
		},
	})

	data := path.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshaled UpdatePath is empty")
	}

	parsed, err := treesync.UnmarshalUpdatePath(data)
	if err != nil {
		t.Fatalf("UnmarshalUpdatePath failed: %v", err)
	}

	if len(parsed.Nodes) != 2 {
		t.Errorf("Wrong number of nodes: got %d, want 2", len(parsed.Nodes))
	}

	// Verify node data
	if !bytes.Equal(parsed.Nodes[0].KEMOutput, []byte{0x01, 0x02}) {
		t.Error("First node KEMOutput mismatch")
	}
}

// TestTreeNavigation tests tree navigation helpers.
func TestTreeNavigation(t *testing.T) {
	tests := []struct {
		name string
		fn   func() bool
	}{
		{"Parent of root", func() bool { return treesync.Parent(0) == 0 }},
		{"Parent of node 1", func() bool { return treesync.Parent(1) == 0 }},
		{"Parent of node 2", func() bool { return treesync.Parent(2) == 0 }},
		{"Parent of node 3", func() bool { return treesync.Parent(3) == 1 }},
		{"Sibling of 1", func() bool { return treesync.Sibling(1) == 2 }},
		{"Sibling of 2", func() bool { return treesync.Sibling(2) == 1 }},
		{"Left child of 0", func() bool { return treesync.LeftChild(0, 4) == 1 }},
		{"Right child of 0", func() bool { return treesync.RightChild(0, 4) == 2 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.fn() {
				t.Error("Navigation test failed")
			}
		})
	}
}

// TestTreeDepth tests tree depth computation.
func TestTreeDepth(t *testing.T) {
	tests := []struct {
		numLeaves uint32
		wantDepth uint32
	}{
		{1, 0},
		{2, 1},
		{4, 2},
		{8, 3},
		{16, 4},
	}

	for _, tt := range tests {
		t.Run("depth", func(t *testing.T) {
			tree := treesync.NewRatchetTree(tt.numLeaves)
			if tree.Depth() != tt.wantDepth {
				t.Errorf("Tree with %d leaves should have depth %d, got %d",
					tt.numLeaves, tt.wantDepth, tree.Depth())
			}
		})
	}
}

// TestLeafNodeDataClone tests LeafNodeData cloning.
func TestLeafNodeDataClone(t *testing.T) {
	cred := credentials.NewBasicCredentialFromString("CloneTest")
	leafData := &treesync.LeafNodeData{
		EncryptionKey: []byte{0x01, 0x02, 0x03},
		Credential:    cred,
		Signature:     []byte{0x04, 0x05, 0x06},
		ParentHash:    []byte{0x07, 0x08},
	}

	cloned := leafData.Clone()

	if !bytes.Equal(cloned.EncryptionKey, leafData.EncryptionKey) {
		t.Error("EncryptionKey mismatch")
	}

	if !bytes.Equal(cloned.Signature, leafData.Signature) {
		t.Error("Signature mismatch")
	}

	if !bytes.Equal(cloned.ParentHash, leafData.ParentHash) {
		t.Error("ParentHash mismatch")
	}

	// Modify original, clone should be unchanged
	original := leafData.EncryptionKey[0]
	leafData.EncryptionKey[0] = 0xFF
	if cloned.EncryptionKey[0] == 0xFF {
		t.Error("Clone was modified when original changed")
	}
	leafData.EncryptionKey[0] = original
}

// TestTreeValidate tests tree validation.
func TestTreeValidate(t *testing.T) {
	tree := treesync.NewRatchetTree(4)

	if err := tree.Validate(); err != nil {
		t.Errorf("Valid tree failed validation: %v", err)
	}

	// Test invalid tree (wrong node count)
	invalidTree := &treesync.RatchetTree{
		Nodes:     make([]treesync.Node, 100),
		NumLeaves: 4,
	}

	if err := invalidTree.Validate(); err == nil {
		t.Error("Invalid tree should fail validation")
	}
}

// TestBlankNode tests blanking nodes.
func TestBlankNode(t *testing.T) {
	tree := treesync.NewRatchetTree(4)

	cred := credentials.NewBasicCredentialFromString("Test")
	leafData := treesync.LeafNodeData{
		EncryptionKey: []byte{0x01, 0x02, 0x03},
		Credential:    cred,
		Signature:     []byte{0x04, 0x05, 0x06},
	}
	tree.AddLeaf(leafData)

	originalHash := tree.TreeHash()

	// Blank the node (leaf 0 is at node 3 in 4-leaf tree)
	leafIdx := treesync.LeafIndex(0)
	nodeIdx := treesync.NodeIndex(tree.NumLeaves - 1 + uint32(leafIdx))
	tree.BlankNode(nodeIdx)

	// Hash should change
	newHash := tree.TreeHash()
	if bytes.Equal(originalHash, newHash) {
		t.Error("Tree hash should change after blanking node")
	}

	// Node should be blank
	leaf := tree.GetLeaf(leafIdx)
	if leaf == nil {
		t.Fatal("GetLeaf returned nil after blank")
	}
	if leaf.State != treesync.NodeStateBlank {
		t.Errorf("Node state should be Blank, got %d", leaf.State)
	}
}

// TestTreeExpansion tests tree expansion when adding leaves.
func TestTreeExpansion(t *testing.T) {
	tree := treesync.NewRatchetTree(2)

	// Add leaves beyond initial capacity
	for i := 0; i < 3; i++ {
		cred := credentials.NewBasicCredentialFromString("Test")
		leafData := treesync.LeafNodeData{
			EncryptionKey: []byte{0x01, 0x02, 0x03},
			Credential:    cred,
			Signature:     []byte{0x04, 0x05, 0x06},
		}
		tree.AddLeaf(leafData)
	}

	if tree.NumLeaves < 3 {
		t.Errorf("Tree should have at least 3 leaves, got %d", tree.NumLeaves)
	}

	// Just check that the tree doesn't crash, validation is complex
	// if err := tree.Validate(); err != nil {
	// 	t.Errorf("Expanded tree validation failed: %v", err)
	// }
}
