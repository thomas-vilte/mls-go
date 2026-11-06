package treesync

import (
	"fmt"
	"testing"
	"time"
)

// failIfSlow runs f and fails the test if f does not return within a few seconds, so a
// query that never ends shows up as a failure instead of hanging the test binary.
func failIfSlow(t *testing.T, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not return within 5s", what)
	}
}

// TestPathAndSubtreeQueriesRejectLeavesOutsideTree checks that DirectPath, Copath, SubtreeContainsLeaf and
// VerifyParentHashes refuse a leaf outside the tree. They convert the leaf with LeafIndexToNodeIndex, which
// wraps for leaf indices >= 2^31, so a leaf of 0x80000000 on a 2-leaf tree used to be treated as node 0 (leaf 0).
// Leaves past the end of the tree never returned, because Parent looped on a node outside the tree. The range
// check comes before the conversion, and Parent rejects nodes outside the tree.
func TestPathAndSubtreeQueriesRejectLeavesOutsideTree(t *testing.T) {
	t.Parallel()
	tree := NewRatchetTree(2)

	// Control: leaf 0 of the 2-leaf tree has a direct path that ends at the root.
	if path := tree.DirectPath(0); len(path) != 2 {
		t.Fatalf("DirectPath(0) = %v, want a path of two nodes", path)
	}

	// The wrapping indices come first: they alias existing nodes but return. Indices past the end
	// of the tree come after them, because their queries used to never return.
	for _, idx := range []LeafIndex{1 << 31, 1<<31 + 1, 2, 0xFFFFFFFF} {
		var (
			path, copath []NodeIndex
			contains     bool
			hashErr      error
		)
		failIfSlow(t, fmt.Sprintf("DirectPath(%#x)", idx), func() { path = tree.DirectPath(idx) })
		failIfSlow(t, fmt.Sprintf("Copath(%#x)", idx), func() { copath = tree.Copath(idx) })
		failIfSlow(t, fmt.Sprintf("SubtreeContainsLeaf(0, %#x)", idx), func() { contains = tree.SubtreeContainsLeaf(0, idx) })
		failIfSlow(t, fmt.Sprintf("VerifyParentHashes(%#x)", idx), func() { hashErr = tree.VerifyParentHashes(idx) })

		if len(path) != 0 {
			t.Errorf("DirectPath(%#x) = %v; want no path for a leaf outside the tree", idx, path)
		}
		if len(copath) != 0 {
			t.Errorf("Copath(%#x) = %v; want no copath for a leaf outside the tree", idx, copath)
		}
		if contains {
			t.Errorf("SubtreeContainsLeaf(0, %#x) = true; the index must not alias leaf 0", idx)
		}
		if hashErr == nil {
			t.Errorf("VerifyParentHashes(%#x) = nil; want an out-of-range error", idx)
		}
	}

	// Parent of node 4, which is outside a 2-leaf tree (valid nodes are 0..2), must fail.
	var parentErr error
	failIfSlow(t, "Parent(4) on a 2-leaf tree", func() { _, parentErr = tree.Parent(4) })
	if parentErr == nil {
		t.Errorf("Parent(4) on a 2-leaf tree returned no error; want one for a node outside the tree")
	}

	// Control: in-range leaves are still under the root.
	if !tree.SubtreeContainsLeaf(1, 0) || !tree.SubtreeContainsLeaf(1, 1) {
		t.Errorf("SubtreeContainsLeaf(root, in-range leaf) = false")
	}
}
