package secrettree

import (
	"bytes"
	"testing"
	"time"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// TestRatchetForwardDistance checks fast rejection of excessive generation jumps without advancing the leaf and preserves valid reordered keys.
func TestRatchetForwardDistance(t *testing.T) {
	const hostileGen = uint32(1000000)

	ops := []struct {
		name string
		call func(ls *LeafSecret, gen uint32) error
	}{
		{"ApplicationKey", func(ls *LeafSecret, gen uint32) error {
			_, err := ls.ApplicationKey(gen)
			return err
		}},
		{"ApplicationNonce", func(ls *LeafSecret, gen uint32) error {
			_, err := ls.ApplicationNonce(gen)
			return err
		}},
		{"HandshakeKey", func(ls *LeafSecret, gen uint32) error {
			_, err := ls.HandshakeKey(gen)
			return err
		}},
		{"HandshakeNonce", func(ls *LeafSecret, gen uint32) error {
			_, err := ls.HandshakeNonce(gen)
			return err
		}},
	}

	for _, op := range ops {
		t.Run("reject_"+op.name, func(t *testing.T) {
			leaf := newRatchetTestLeaf(t)

			start := time.Now()
			err := op.call(leaf, hostileGen)
			elapsed := time.Since(start)
			if err == nil {
				t.Fatalf("%s(%d) succeeded after %v, want forward-distance rejection", op.name, hostileGen, elapsed)
			}
			if elapsed > 50*time.Millisecond {
				t.Errorf("%s(%d) rejected after %v, want < 50ms", op.name, hostileGen, elapsed)
			}
			if got := leaf.CurrentGeneration(); got != 0 {
				t.Fatalf("CurrentGeneration = %d after rejected jump, want 0", got)
			}
			// The leaf must still serve the legitimate next generation.
			if _, err := leaf.ApplicationKey(1); err != nil {
				t.Errorf("ApplicationKey(1) after rejected jump: %v", err)
			}
		})
	}

	t.Run("control_in_order_and_reordered_within_window", func(t *testing.T) {
		leaf := newRatchetTestLeaf(t)

		// Normal in-order receive over 500 generations.
		keys := make([][]byte, 500)
		for gen := range uint32(500) {
			key, err := leaf.ApplicationKey(gen)
			if err != nil {
				t.Fatalf("in-order ApplicationKey(%d): %v", gen, err)
			}
			keys[gen] = key
		}

		// Reordered delivery: generation 250 is behind the ratchet and must still decrypt.
		key250, err := leaf.ApplicationKey(250)
		if err != nil {
			t.Fatalf("reordered ApplicationKey(250): %v", err)
		}
		if !bytes.Equal(key250, keys[250]) {
			t.Error("reordered ApplicationKey(250) differs from the in-order key")
		}

		// A jump of exactly 1000 steps from generation 499 is still allowed.
		if _, err := leaf.ApplicationKey(499 + 1000); err != nil {
			t.Fatalf("ApplicationKey(1499) at the window edge: %v", err)
		}
		// One step beyond the window is rejected and leaves the leaf at 1499.
		if _, err := leaf.ApplicationKey(1499 + 1001); err == nil {
			t.Fatal("ApplicationKey(2500) succeeded, want rejection beyond the forward window")
		}
		if got := leaf.CurrentGeneration(); got != 1499 {
			t.Errorf("CurrentGeneration = %d after rejected jump, want 1499", got)
		}
	})
}

// newRatchetTestLeaf returns leaf 0 of a fresh four-leaf secret tree, at generation 0.
func newRatchetTestLeaf(t *testing.T) *LeafSecret {
	t.Helper()
	encSecret, err := ciphersuite.NewSecretRandom(32)
	if err != nil {
		t.Fatalf("NewSecretRandom: %v", err)
	}
	tree, err := NewTree(encSecret, 4, ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	leaf, err := tree.LeafForIndex(0)
	if err != nil {
		t.Fatalf("LeafForIndex(0): %v", err)
	}
	return leaf
}
