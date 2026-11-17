package treesync

import (
	"fmt"
	"math/bits"
	"testing"
)

// parentStepFormula is the RFC 9420 Appendix C parent_step written with its formula: k is the level of x
// (the number of trailing ones) and b is bit k+1 of x.
func parentStepFormula(x uint32) uint32 {
	k := uint32(bits.TrailingZeros32(^x))
	b := (x >> (k + 1)) & 1
	return (x | (1 << k)) ^ (b << (k + 1))
}

// rfcParent is the RFC parent of node in a tree of n leaves, computed with parentStepFormula. It gives up
// after 64 steps, so a wrong expectation cannot hang the test.
func rfcParent(n, node, root uint32) (uint32, bool) {
	if node == root {
		return 0, false
	}
	maxIdx := 2*n - 2
	p := parentStepFormula(node)
	for steps := 0; p > maxIdx; steps++ {
		if steps >= 64 {
			return 0, false
		}
		p = parentStepFormula(p)
	}
	return p, true
}

// TestDirectPathCheckedRejectsLeafOutsideTree checks that DirectPathChecked returns an error for every leaf
// from NumLeaves to 2*NumLeaves+1 and for the wrapping indices 2^31, 2^31+1 and 0xFFFFFFFF, while DirectPath
// and Copath return nil for them.
func TestDirectPathCheckedRejectsLeafOutsideTree(t *testing.T) {
	t.Parallel()
	for n := uint32(1); n <= 8; n++ {
		tree := NewRatchetTree(n)
		leaves := []LeafIndex{1 << 31, 1<<31 + 1, 0xFFFFFFFF}
		for leaf := n; leaf <= 2*n+1; leaf++ {
			leaves = append(leaves, LeafIndex(leaf))
		}
		for _, leaf := range leaves {
			failIfSlow(t, fmt.Sprintf("direct path of leaf %#x on a %d-leaf tree", leaf, n), func() {
				if _, err := tree.DirectPathChecked(leaf); err == nil {
					t.Errorf("DirectPathChecked(%#x) on a %d-leaf tree returned no error", leaf, n)
				}
				if path := tree.DirectPath(leaf); path != nil {
					t.Errorf("DirectPath(%#x) on a %d-leaf tree = %v, want nil", leaf, n, path)
				}
				if copath := tree.Copath(leaf); copath != nil {
					t.Errorf("Copath(%#x) on a %d-leaf tree = %v, want nil", leaf, n, copath)
				}
			})
		}
	}
}

// TestParentRejectsNodeOutsideTree checks that Parent returns an error for a node past 2*NumLeaves-2,
// including 0xFFFFFFFF, which is its own parent.
func TestParentRejectsNodeOutsideTree(t *testing.T) {
	t.Parallel()
	for n := uint32(1); n <= 8; n++ {
		tree := NewRatchetTree(n)
		maxIdx := 2*n - 2
		for _, node := range []NodeIndex{NodeIndex(maxIdx + 1), NodeIndex(maxIdx + 2), 0xFFFFFFFE, 0xFFFFFFFF} {
			failIfSlow(t, fmt.Sprintf("Parent(%#x) on a %d-leaf tree", node, n), func() {
				if parent, err := tree.Parent(node); err == nil {
					t.Errorf("Parent(%#x) on a %d-leaf tree = %d, want an error", node, n, parent)
				}
			})
		}
	}
}

// TestParentMatchesRFC checks that for every node of the trees with 1 to 300 leaves, Parent returns the RFC
// parent and the root has none.
func TestParentMatchesRFC(t *testing.T) {
	t.Parallel()
	failIfSlow(t, "Parent sweep", func() {
		for n := uint32(1); n <= 300; n++ {
			tree := NewRatchetTree(n)
			root := uint32(tree.Root())
			for node := uint32(0); node <= 2*n-2; node++ {
				got, err := tree.Parent(NodeIndex(node))
				if node == root {
					if err == nil {
						t.Fatalf("Parent(root %d) on a %d-leaf tree returned no error", node, n)
					}
					continue
				}
				want, ok := rfcParent(n, node, root)
				if !ok {
					t.Fatalf("RFC reference found no parent for node %d on a %d-leaf tree", node, n)
				}
				if err != nil || uint32(got) != want {
					t.Fatalf("Parent(%d) on a %d-leaf tree = %d, %v; want %d", node, n, got, err, want)
				}
			}
		}
	})
}

// TestDirectPathCheckedMatchesRFC checks that leaves inside the tree keep their direct path: for the trees
// with 1 to 64 leaves, DirectPathChecked and DirectPath return the RFC walk from the leaf up to the root.
func TestDirectPathCheckedMatchesRFC(t *testing.T) {
	t.Parallel()
	failIfSlow(t, "direct path sweep", func() {
		for n := uint32(1); n <= 64; n++ {
			tree := NewRatchetTree(n)
			root := uint32(tree.Root())
			for leaf := uint32(0); leaf < n; leaf++ {
				want := []uint32{2 * leaf}
				node := 2 * leaf
				for node != root {
					parent, ok := rfcParent(n, node, root)
					if !ok {
						t.Fatalf("RFC reference found no parent for node %d on a %d-leaf tree", node, n)
					}
					want = append(want, parent)
					node = parent
				}

				got, err := tree.DirectPathChecked(LeafIndex(leaf))
				if err != nil {
					t.Fatalf("DirectPathChecked(%d) on a %d-leaf tree: %v", leaf, n, err)
				}
				direct := tree.DirectPath(LeafIndex(leaf))
				if len(got) != len(want) || len(direct) != len(want) {
					t.Fatalf("direct path of leaf %d on a %d-leaf tree = %v (DirectPath %v), want %v", leaf, n, got, direct, want)
				}
				for i := range want {
					if uint32(got[i]) != want[i] || direct[i] != got[i] {
						t.Fatalf("direct path of leaf %d on a %d-leaf tree = %v (DirectPath %v), want %v", leaf, n, got, direct, want)
					}
				}
			}
		}
	})
}
