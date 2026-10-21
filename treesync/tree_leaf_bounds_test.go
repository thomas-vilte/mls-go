package treesync

import "testing"

// TestRatchetTreeLeafIndexBounds checks that out-of-range leaf indices cannot
// read or overwrite existing nodes through integer wraparound.
func TestRatchetTreeLeafIndexBounds(t *testing.T) {
	t.Parallel()
	tree := NewRatchetTree(2)

	// Control: the two leaves of the tree are reachable.
	for _, idx := range []LeafIndex{0, 1} {
		if tree.GetLeaf(idx) == nil {
			t.Fatalf("GetLeaf(%d) = nil on a 2-leaf tree", idx)
		}
	}

	for _, idx := range []LeafIndex{2, 1 << 31, 1<<31 + 1, 0xFFFFFFFF} {
		if got := tree.GetLeaf(idx); got != nil {
			t.Errorf("GetLeaf(%#x) = non-nil; want nil (not a leaf of a 2-leaf tree, and it must not alias node %d)",
				idx, LeafIndexToNodeIndex(idx))
		}
	}

	// SetLeaf must not write through a wrapped index into node 0.
	before := tree.Nodes[0]
	for _, idx := range []LeafIndex{2, 1 << 31} {
		if err := tree.SetLeaf(idx, LeafNodeData{}); err == nil {
			t.Errorf("SetLeaf(%#x) succeeded; want an out-of-range error", idx)
		}
	}
	if tree.Nodes[0].State != before.State || tree.Nodes[0].LeafData != before.LeafData {
		t.Errorf("SetLeaf(0x80000000) modified node 0 through the wrapped index")
	}
}
