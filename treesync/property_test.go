package treesync

import (
	"reflect"
	"testing"
	"testing/quick"
)

// TestProperty_TreeHash_Deterministic verifies that calculating TreeHash twice
// on the same tree yields the exact same result.
func TestProperty_TreeHash_Deterministic(t *testing.T) {
	property := func(numLeaves uint32) bool {
		numLeaves = (numLeaves % 100) + 1
		tree := NewRatchetTree(numLeaves)

		hash1 := tree.TreeHash()
		hash2 := tree.TreeHash()

		return reflect.DeepEqual(hash1, hash2)
	}

	if err := quick.Check(property, &quick.Config{MaxCount: 100}); err != nil {
		t.Error(err)
	}
}

// TestProperty_RootIndex_Correct verifies that the root node calculation
// produces a valid index within the tree bounds.
func TestProperty_RootIndex_Correct(t *testing.T) {
	property := func(numLeaves uint32) bool {
		numLeaves = (numLeaves % 1024) + 1
		tree := NewRatchetTree(numLeaves)

		rootIdx := tree.Root()
		return int(rootIdx) < len(tree.Nodes)
	}

	if err := quick.Check(property, &quick.Config{MaxCount: 100}); err != nil {
		t.Error(err)
	}
}
