package secrettree

import (
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// TestTreeSequenceNumber checks that SequenceNumber reports the sequence number that the next message of a leaf
// uses: 0 for a nil tree and for a leaf whose ratchet is not loaded, and the number of messages sent for a
// leaf that has encrypted.
func TestTreeSequenceNumber(t *testing.T) {
	var nilTree *Tree
	if got := nilTree.SequenceNumber(0); got != 0 {
		t.Fatalf("nil tree: SequenceNumber(0) = %d, want 0", got)
	}

	secret, err := ciphersuite.NewSecretRandom(32)
	if err != nil {
		t.Fatalf("NewSecretRandom: %v", err)
	}
	tree, err := NewTree(secret, 4, ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	if got := tree.SequenceNumber(2); got != 0 {
		t.Fatalf("leaf without a loaded ratchet: SequenceNumber(2) = %d, want 0", got)
	}

	leaf, err := tree.LeafForIndex(0)
	if err != nil {
		t.Fatalf("LeafForIndex(0): %v", err)
	}
	for i := uint64(0); i < 3; i++ {
		if got := tree.SequenceNumber(0); got != i {
			t.Fatalf("after %d messages SequenceNumber(0) = %d, want %d", i, got, i)
		}
		seq := leaf.NextSequenceNumber()
		if _, err := leaf.Encrypt([]byte("message"), nil, seq); err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
	}
	if got := tree.SequenceNumber(0); got != 3 {
		t.Fatalf("after 3 messages SequenceNumber(0) = %d, want 3", got)
	}
	if got := tree.SequenceNumber(1); got != 0 {
		t.Fatalf("another leaf: SequenceNumber(1) = %d, want 0", got)
	}
}
