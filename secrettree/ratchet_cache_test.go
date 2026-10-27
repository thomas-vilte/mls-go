package secrettree

import (
	"bytes"
	"testing"
)

// advanceInOrder consumes generations [0, upTo) in order, as an honest sender's messages arrive.
func advanceInOrder(t *testing.T, leaf *LeafSecret, upTo uint32) {
	t.Helper()
	for gen := range upTo {
		if _, err := leaf.ApplicationKey(gen); err != nil {
			t.Fatalf("in-order ApplicationKey(%d): %v", gen, err)
		}
	}
}

// TestRatchetCacheEvictsOldestGeneration checks bounded cache eviction while retaining recently skipped generations.
func TestRatchetCacheEvictsOldestGeneration(t *testing.T) {
	leaf := newRatchetTestLeaf(t)
	advanceInOrder(t, leaf, 2100)
	if got := len(leaf.secretCache); got != maxCachedGenerations {
		t.Fatalf("cache size after 2100 in-order generations = %d, want %d", got, maxCachedGenerations)
	}

	// Generation 2100 is skipped, then 2101 arrives first, and 2100 arrives late.
	if _, err := leaf.ApplicationKey(2101); err != nil {
		t.Fatalf("ApplicationKey(2101): %v", err)
	}
	if _, err := leaf.ApplicationKey(2100); err != nil {
		t.Fatalf("late ApplicationKey(2100) with a full cache: %v", err)
	}
	if got := len(leaf.secretCache); got != maxCachedGenerations {
		t.Fatalf("cache size after eviction = %d, want %d", got, maxCachedGenerations)
	}
	if got := len(leaf.secretCacheOrder); got != maxCachedGenerations {
		t.Fatalf("cache order size = %d, want %d (order and map must stay in step)", got, maxCachedGenerations)
	}
}

// TestRatchetForwardJumpRetainsSkippedGenerations checks that delayed generations remain available after an allowed forward jump.
func TestRatchetForwardJumpRetainsSkippedGenerations(t *testing.T) {
	leaf := newRatchetTestLeaf(t)
	advanceInOrder(t, leaf, 2100)
	if _, err := leaf.ApplicationKey(2100 + DefaultMaxForwardDistance - 1); err != nil {
		t.Fatalf("jump to the edge of the forward window: %v", err)
	}
	for gen := uint32(2100); gen < 2110; gen++ {
		if _, err := leaf.ApplicationKey(gen); err != nil {
			t.Errorf("honest ApplicationKey(%d) after a forward jump: %v", gen, err)
		}
	}
}

// TestPendingDecryptionCommitsRatchetAdvance checks that provisional decryption changes the ratchet only when committed.
func TestPendingDecryptionCommitsRatchetAdvance(t *testing.T) {
	leaf := newRatchetTestLeaf(t)

	pending, err := leaf.BeginDecryption(5)
	if err != nil {
		t.Fatalf("BeginDecryption(5): %v", err)
	}
	if gen := leaf.CurrentGeneration(); gen != 0 {
		t.Fatalf("BeginDecryption moved the ratchet to %d, want 0", gen)
	}
	pendingKey, err := pending.Key(false)
	if err != nil {
		t.Fatalf("pending.Key: %v", err)
	}
	pending.Discard()
	if got := len(leaf.secretCache); got != 0 {
		t.Fatalf("Discard left %d cached generation(s), want 0", got)
	}
	if gen := leaf.CurrentGeneration(); gen != 0 {
		t.Fatalf("Discard moved the ratchet to %d, want 0", gen)
	}

	// The keys derived by BeginDecryption are the keys that the committing API derives.
	directKey, err := leaf.ApplicationKey(5)
	if err != nil {
		t.Fatalf("ApplicationKey(5): %v", err)
	}
	if !bytes.Equal(pendingKey, directKey) {
		t.Fatal("pending key for generation 5 differs from ApplicationKey(5)")
	}

	// A committed pending decryption moves the leaf to its generation.
	committed, err := leaf.BeginDecryption(9)
	if err != nil {
		t.Fatalf("BeginDecryption(9): %v", err)
	}
	committedKey, err := committed.Key(false)
	if err != nil {
		t.Fatalf("committed.Key: %v", err)
	}
	committed.Commit()
	if gen := leaf.CurrentGeneration(); gen != 9 {
		t.Fatalf("after Commit the ratchet is at %d, want 9", gen)
	}
	afterCommit, err := leaf.ApplicationKey(9)
	if err != nil {
		t.Fatalf("ApplicationKey(9) after Commit: %v", err)
	}
	if !bytes.Equal(committedKey, afterCommit) {
		t.Fatal("committed key for generation 9 differs from ApplicationKey(9)")
	}
}

// TestPendingDecryptionRejectsExcessiveForwardDistance checks rejection of excessive provisional derivation without moving the ratchet.
func TestPendingDecryptionRejectsExcessiveForwardDistance(t *testing.T) {
	leaf := newRatchetTestLeaf(t)
	if _, err := leaf.BeginDecryption(DefaultMaxForwardDistance + 1); err == nil {
		t.Fatal("BeginDecryption beyond the forward window: err = nil, want rejection")
	}
	if gen := leaf.CurrentGeneration(); gen != 0 {
		t.Fatalf("refused generation moved the ratchet to %d, want 0", gen)
	}
}
