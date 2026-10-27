//go:build diagnostics

package secrettree

import "testing"

// Additional diagnostics for ratchet limits and cached generations.

// Control: in-order traffic past the 1000-step window must keep decrypting.
func TestRatchetInOrderTrafficBeyondForwardWindow(t *testing.T) {
	leaf := newRatchetTestLeaf(t)
	for gen := range uint32(2101) {
		if _, err := leaf.ApplicationKey(gen); err != nil {
			t.Fatalf("in-order ApplicationKey(%d): %v", gen, err)
		}
	}
}

// Checks whether a message that is one step late is still decryptable after the per-leaf cache
// is full (maxCachedGenerations = 2048). The DefaultMaxForwardDistance comment says that modest
// gaps are not affected; this test checks that claim after 2100 in-order generations.
func TestRatchetCachePreservesReorderedGeneration(t *testing.T) {
	t.Run("control_cache_not_full", func(t *testing.T) {
		leaf := newRatchetTestLeaf(t)
		for gen := range uint32(500) {
			if _, err := leaf.ApplicationKey(gen); err != nil {
				t.Fatalf("in-order ApplicationKey(%d): %v", gen, err)
			}
		}
		if _, err := leaf.ApplicationKey(501); err != nil {
			t.Fatalf("ApplicationKey(501): %v", err)
		}
		if _, err := leaf.ApplicationKey(500); err != nil {
			t.Errorf("control: late ApplicationKey(500) with cache not full: %v", err)
		}
	})
	t.Run("cache_full", func(t *testing.T) {
		leaf := newRatchetTestLeaf(t)
		for gen := range uint32(2100) {
			if _, err := leaf.ApplicationKey(gen); err != nil {
				t.Fatalf("in-order ApplicationKey(%d): %v", gen, err)
			}
		}
		// The next generation arrives first (inside the window), then the honest generation 2100.
		if _, err := leaf.ApplicationKey(2101); err != nil {
			t.Fatalf("ApplicationKey(2101) inside the window: %v", err)
		}
		if _, err := leaf.ApplicationKey(2100); err != nil {
			t.Errorf("late ApplicationKey(2100) one step behind, after 2100 in-order generations: %v", err)
		}
	})
}

// TestRatchetForwardJumpPreservesDelayedGenerations checks that an allowed jump at a full cache preserves recently skipped generations.
func TestRatchetForwardJumpPreservesDelayedGenerations(t *testing.T) {
	leaf := newRatchetTestLeaf(t)
	for gen := range uint32(2100) {
		if _, err := leaf.ApplicationKey(gen); err != nil {
			t.Fatalf("in-order ApplicationKey(%d): %v", gen, err)
		}
	}
	// Generation 2099 + 1000 = 3099 is the legal edge of the window.
	if _, err := leaf.ApplicationKey(3099); err != nil {
		t.Fatalf("forged jump to the window edge 3099: %v", err)
	}
	failed := 0
	for gen := uint32(2100); gen < 2110; gen++ {
		if _, err := leaf.ApplicationKey(gen); err != nil {
			failed++
			t.Errorf("honest ApplicationKey(%d), sent before the jump and delivered after: %v", gen, err)
		}
	}
	t.Logf("honest generations lost after one forged message: %d of 10", failed)
}
