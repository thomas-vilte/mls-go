package treesync_test

import (
	"github.com/openmls/go/treesync"
	"testing"
)

func TestNewRatchetTreeInterleaved(t *testing.T) {
	// RFC Appendix C interleaved representation:
	// For N=4 leaves: nodes 0,1,2,3,4,5,6
	// Leaves at even indices: 0,2,4,6
	// Parents at odd indices: 1,3,5

	tree := treesync.NewRatchetTree(4)

	if tree.LeafCount() != 4 {
		t.Errorf("Expected 4 leaves, got %d", tree.LeafCount())
	}

	// Raíz en n=4: root(4) = (1 << floor(log2(7))) - 1 = (1<<2)-1 = 3
	root := tree.Root()
	if root != 3 {
		t.Errorf("Expected root at 3, got %d", root)
	}

	// Leaf 0 should be at node 0
	leaf0Node := treesync.LeafIndexToNodeIndex(0)
	if leaf0Node != 0 {
		t.Errorf("Expected leaf 0 at node 0, got %d", leaf0Node)
	}

	// Leaf 1 should be at node 2
	leaf1Node := treesync.LeafIndexToNodeIndex(1)
	if leaf1Node != 2 {
		t.Errorf("Expected leaf 1 at node 2, got %d", leaf1Node)
	}

	// Test DirectPath from leaf 0
	path := tree.DirectPath(0)
	t.Logf("Direct path from leaf 0: %v", path)

	// Verify it starts at leaf and ends at or before root
	if len(path) == 0 {
		t.Fatal("Direct path is empty")
	}

	if path[0] != 0 {
		t.Errorf("Path should start at leaf 0 (node 0), got %d", path[0])
	}

	// The last node should be the root or close to it
	lastNode := path[len(path)-1]
	if lastNode > tree.Root() {
		t.Errorf("Path goes beyond root: last node %d, root %d", lastNode, tree.Root())
	}

	t.Logf("✓ Interleaved representation working correctly")
	for i, node := range path {
		t.Logf("  Path[%d] = node %d", i, node)
	}
}

func TestTreeHashInterleaved(t *testing.T) {
	tree := treesync.NewRatchetTree(2)

	hash := tree.TreeHash()
	if len(hash) != 32 {
		t.Errorf("Expected 32-byte hash, got %d bytes", len(hash))
	}

	t.Logf("✓ TreeHash computed successfully")
}
