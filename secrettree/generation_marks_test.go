package secrettree

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// TestConsumedGenerationsAreBoundedAndNotReplayable checks that the replay bookkeeping stays bounded and that a
// consumed generation does not keep its secret in the cache (RFC 9420 §9.2), so a pruned mark never makes a
// cached secret replayable.
func TestConsumedGenerationsAreBoundedAndNotReplayable(t *testing.T) {
	t.Run("marks_bounded_after_100000_generations", func(t *testing.T) {
		leaf := newRatchetTestLeaf(t)
		for gen := uint32(0); gen < 100000; gen++ {
			if err := receiveGeneration(leaf, gen, false); err != nil {
				t.Fatalf("in-order application generation %d: %v", gen, err)
			}
			if err := receiveGeneration(leaf, gen, true); err != nil {
				t.Fatalf("in-order handshake generation %d: %v", gen, err)
			}
		}
		if got := len(leaf.usedApplicationGenerations); got > maxCachedGenerations {
			t.Fatalf("application marks after 100000 generations = %d, want <= %d", got, maxCachedGenerations)
		}
		if got := len(leaf.usedHandshakeGenerations); got > maxCachedGenerations {
			t.Fatalf("handshake marks after 100000 generations = %d, want <= %d", got, maxCachedGenerations)
		}
		if got := len(leaf.secretCache); got > maxCachedGenerations {
			t.Fatalf("cache after 100000 generations = %d, want <= %d", got, maxCachedGenerations)
		}

		// Consumed generations are refused, both recent ones and ones that were pruned long ago.
		for _, gen := range []uint32{0, 1, 99998, 99999} {
			if err := receiveGeneration(leaf, gen, false); err == nil {
				t.Fatalf("replay of application generation %d accepted after 100000 generations", gen)
			}
			if err := receiveGeneration(leaf, gen, true); err == nil {
				t.Fatalf("replay of handshake generation %d accepted after 100000 generations", gen)
			}
		}
	})

	t.Run("late_generation_in_window_decrypts_once", func(t *testing.T) {
		leaf := newRatchetTestLeaf(t)
		// Both ratchets skip generation 5 and then pass it, so each one caches its own secret for it.
		for _, handshake := range []bool{false, true} {
			for gen := uint32(0); gen < 10; gen++ {
				if gen == 5 {
					continue
				}
				if err := receiveGeneration(leaf, gen, handshake); err != nil {
					t.Fatalf("in-order generation %d (handshake=%v): %v", gen, handshake, err)
				}
			}
		}

		// Application generation 5 arrives late, inside the window, and is accepted once.
		if err := receiveGeneration(leaf, 5, false); err != nil {
			t.Fatalf("late application generation 5: %v", err)
		}
		if cached, ok := leaf.secretCache[5]; ok && cached.application != nil {
			t.Fatal("application secret of generation 5 is still cached after it was consumed")
		}
		if err := receiveGeneration(leaf, 5, false); err == nil {
			t.Fatal("replay of late application generation 5 accepted")
		}

		// The handshake secret of generation 5 is independent and still usable once.
		if err := receiveGeneration(leaf, 5, true); err != nil {
			t.Fatalf("late handshake generation 5 refused after application generation 5 was consumed: %v", err)
		}
		if err := receiveGeneration(leaf, 5, true); err == nil {
			t.Fatal("replay of late handshake generation 5 accepted")
		}
	})

	t.Run("decrypt_refuses_replay_of_consumed_generations", func(t *testing.T) {
		sender, receiver := newSenderReceiverLeaves(t)
		aad := []byte("aad")
		cts := make([][]byte, 10)
		for gen := range cts {
			ct, err := sender.Encrypt([]byte("msg"), aad, uint64(gen))
			if err != nil {
				t.Fatalf("Encrypt(generation %d): %v", gen, err)
			}
			cts[gen] = ct
		}

		// Generation 0 in order, then a jump to 3 that skips 1 and 2, then the skipped ones late.
		for _, gen := range []uint32{0, 3, 1, 2} {
			if _, err := receiver.Decrypt(cts[gen], aad, uint64(gen)); err != nil {
				t.Fatalf("Decrypt(generation %d): %v", gen, err)
			}
		}
		// Every generation was consumed. The one still in the ratchet (3) and the cached-then-consumed
		// ones (0, 1, 2) must all be refused.
		for _, gen := range []uint32{0, 1, 2, 3} {
			if _, err := receiver.Decrypt(cts[gen], aad, uint64(gen)); err == nil {
				t.Fatalf("replay of generation %d accepted by Decrypt", gen)
			}
		}
	})
}

// receiveGeneration runs the receiving steps of framing.Decrypt for one generation, without the AEAD: the replay
// check, the derivation that does not move the ratchet, the consumption of the generation once it is
// accepted, and the commit.
func receiveGeneration(leaf *LeafSecret, gen uint32, handshake bool) error {
	if err := leaf.CheckGenerationUnused(gen, handshake); err != nil {
		return err
	}
	pending, err := leaf.BeginDecryption(gen)
	if err != nil {
		return err
	}
	defer pending.Discard()
	if _, err := pending.Key(handshake); err != nil {
		return err
	}
	if err := leaf.MarkGenerationUsed(gen, handshake); err != nil {
		return err
	}
	pending.Commit()
	return nil
}

// newSenderReceiverLeaves returns the sending and the receiving view of leaf 0 of two secret trees built from the same
// encryption secret, so the receiver can decrypt what the sender encrypts.
func newSenderReceiverLeaves(t *testing.T) (sender, receiver *LeafSecret) {
	t.Helper()
	raw := bytes.Repeat([]byte{0x5a}, 32)
	newLeaf := func() *LeafSecret {
		t.Helper()
		tree, err := NewTree(ciphersuite.NewSecret(raw), 4, ciphersuite.MLS128DHKEMP256)
		if err != nil {
			t.Fatalf("NewTree: %v", err)
		}
		leaf, err := tree.LeafForIndex(0)
		if err != nil {
			t.Fatalf("LeafForIndex(0): %v", err)
		}
		return leaf
	}
	return newLeaf(), newLeaf()
}
