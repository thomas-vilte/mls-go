package treesync

import (
	"encoding/json"
	"os"
	"testing"
)

// tree-math.json vector structure (RFC 9420 Appendix C)
type treeMathVector struct {
	NLeaves uint32    `json:"n_leaves"`
	NNodes  uint32    `json:"n_nodes"`
	Root    uint32    `json:"root"`
	Left    []*uint32 `json:"left"`
	Right   []*uint32 `json:"right"`
	Parent  []*uint32 `json:"parent"`
	Sibling []*uint32 `json:"sibling"`
}

func TestTreeMathVectors(t *testing.T) {
	data, err := os.ReadFile("../testdata/mls-interop-testvectors/test-vectors/tree-math.json")
	if err != nil {
		t.Skipf("tree-math.json not found: %v", err)
	}

	var vectors []treeMathVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse tree-math.json: %v", err)
	}

	for _, v := range vectors {
		t.Run("", func(t *testing.T) {
			tree := NewRatchetTree(v.NLeaves)

			// Verify n_nodes = 2*n_leaves - 1
			if uint32(len(tree.Nodes)) != v.NNodes {
				t.Errorf("n_nodes: got %d want %d", len(tree.Nodes), v.NNodes)
			}

			// Verify root
			if uint32(tree.Root()) != v.Root {
				t.Errorf("root: got %d want %d", tree.Root(), v.Root)
			}

			// Verify parent, left, right, sibling for each node index
			for i := uint32(0); i < v.NNodes; i++ {
				idx := NodeIndex(i)

				// parent
				if i < uint32(len(v.Parent)) {
					parentIdx, err := tree.Parent(idx)
					if v.Parent[i] == nil {
						// root has no parent
						if err == nil {
							t.Errorf("node %d parent: expected error (root), got %d", i, parentIdx)
						}
					} else {
						if err != nil {
							t.Errorf("node %d parent: unexpected error: %v", i, err)
						} else if uint32(parentIdx) != *v.Parent[i] {
							t.Errorf("node %d parent: got %d want %d", i, parentIdx, *v.Parent[i])
						}
					}
				}

				// left child (only for parent nodes)
				if i < uint32(len(v.Left)) {
					leftIdx, err := tree.LeftChild(idx)
					if v.Left[i] == nil {
						if err == nil {
							t.Errorf("node %d left: expected error (leaf), got %d", i, leftIdx)
						}
					} else {
						if err != nil {
							t.Errorf("node %d left: unexpected error: %v", i, err)
						} else if uint32(leftIdx) != *v.Left[i] {
							t.Errorf("node %d left: got %d want %d", i, leftIdx, *v.Left[i])
						}
					}
				}

				// right child
				if i < uint32(len(v.Right)) {
					rightIdx, err := tree.RightChild(idx)
					if v.Right[i] == nil {
						if err == nil {
							t.Errorf("node %d right: expected error (leaf), got %d", i, rightIdx)
						}
					} else {
						if err != nil {
							t.Errorf("node %d right: unexpected error: %v", i, err)
						} else if uint32(rightIdx) != *v.Right[i] {
							t.Errorf("node %d right: got %d want %d", i, rightIdx, *v.Right[i])
						}
					}
				}

				// sibling
				if i < uint32(len(v.Sibling)) {
					sibIdx := tree.GetSibling(idx)
					if v.Sibling[i] == nil {
						// root has no sibling — GetSibling returns node itself
						if uint32(sibIdx) != i {
							t.Errorf("node %d sibling: expected self (root), got %d", i, sibIdx)
						}
					} else {
						if uint32(sibIdx) != *v.Sibling[i] {
							t.Errorf("node %d sibling: got %d want %d", i, sibIdx, *v.Sibling[i])
						}
					}
				}
			}
		})
	}
}
