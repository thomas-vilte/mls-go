package secrettree

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// newPendingTestLeaf returns the secret ratchet of leaf 0 of a tree built from a fixed root, so two
// calls return leaves with identical secrets.
func newPendingTestLeaf(t *testing.T) *LeafSecret {
	t.Helper()
	tree, err := NewTree(ciphersuite.NewSecret(bytes.Repeat([]byte{0x42}, 32)), 2, ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	leaf, err := tree.LeafForIndex(0)
	if err != nil {
		t.Fatalf("LeafForIndex(0): %v", err)
	}
	return leaf
}

// TestPendingDecryptionMatchesDirectDerivation checks that the keys of a pending generation are the
// ones the leaf derives directly, for both ratchets.
func TestPendingDecryptionMatchesDirectDerivation(t *testing.T) {
	const gen = uint32(7)
	ref := newPendingTestLeaf(t)
	wantAppKey, _ := ref.ApplicationKey(gen)
	wantAppNonce, _ := ref.ApplicationNonce(gen)
	wantHsKey, _ := ref.HandshakeKey(gen)
	wantHsNonce, _ := ref.HandshakeNonce(gen)

	leaf := newPendingTestLeaf(t)
	p, err := leaf.BeginDecryption(gen)
	if err != nil {
		t.Fatalf("BeginDecryption(%d): %v", gen, err)
	}
	defer p.Discard()
	for _, c := range []struct {
		name      string
		handshake bool
		key       []byte
		nonce     []byte
	}{
		{"application", false, wantAppKey, wantAppNonce},
		{"handshake", true, wantHsKey, wantHsNonce},
	} {
		key, err := p.Key(c.handshake)
		if err != nil || !bytes.Equal(key, c.key) {
			t.Errorf("%s key = %x (err %v), want %x", c.name, key, err, c.key)
		}
		nonce, err := p.Nonce(c.handshake)
		if err != nil || !bytes.Equal(nonce, c.nonce) {
			t.Errorf("%s nonce = %x (err %v), want %x", c.name, nonce, err, c.nonce)
		}
	}
}

// TestPendingDecryptionDiscardLeavesRatchet checks that a rejected message changes neither the ratchet
// nor the cache, and that the generation can still be derived afterwards.
func TestPendingDecryptionDiscardLeavesRatchet(t *testing.T) {
	leaf := newPendingTestLeaf(t)
	p, err := leaf.BeginDecryption(5)
	if err != nil {
		t.Fatalf("BeginDecryption(5): %v", err)
	}
	p.Discard()
	p.Discard() // a second Discard is a no-op
	p.Commit()  // and so is a Commit after Discard

	if gen := leaf.CurrentGeneration(); gen != 0 {
		t.Fatalf("generation after Discard = %d, want 0", gen)
	}
	if n := len(leaf.secretCache); n != 0 {
		t.Fatalf("cache holds %d generations after Discard, want 0", n)
	}
	if _, err := leaf.ApplicationKey(0); err != nil {
		t.Fatalf("ApplicationKey(0) after Discard: %v", err)
	}
}

// TestPendingDecryptionCommitAdvances checks that Commit moves the ratchet to the generation, keeps the
// skipped generations in the cache with the keys they would have had, and is idempotent.
func TestPendingDecryptionCommitAdvances(t *testing.T) {
	ref := newPendingTestLeaf(t)
	want2, _ := ref.ApplicationKey(2)
	want5, _ := ref.ApplicationKey(5)

	leaf := newPendingTestLeaf(t)
	p, err := leaf.BeginDecryption(5)
	if err != nil {
		t.Fatalf("BeginDecryption(5): %v", err)
	}
	p.Commit()
	p.Commit()  // a second Commit is a no-op
	p.Discard() // and so is a Discard after Commit

	if gen := leaf.CurrentGeneration(); gen != 5 {
		t.Fatalf("generation after Commit = %d, want 5", gen)
	}
	if n := len(leaf.secretCache); n != 5 {
		t.Fatalf("cache holds %d skipped generations, want 5", n)
	}
	if got, err := leaf.ApplicationKey(5); err != nil || !bytes.Equal(got, want5) {
		t.Fatalf("ApplicationKey(5) = %x (err %v), want %x", got, err, want5)
	}
	if got, err := leaf.ApplicationKey(2); err != nil || !bytes.Equal(got, want2) {
		t.Fatalf("ApplicationKey(2) from the cache = %x (err %v), want %x", got, err, want2)
	}
}

// TestPendingDecryptionCachedAndCurrent checks the two cases that own no secrets of their own: a
// generation served from the cache and the current generation. Neither Commit nor Discard may change
// the ratchet or wipe secrets that belong to it.
func TestPendingDecryptionCachedAndCurrent(t *testing.T) {
	ref := newPendingTestLeaf(t)
	want3, _ := ref.ApplicationKey(3)
	want6, _ := ref.ApplicationKey(6)

	leaf := newPendingTestLeaf(t)
	adv, err := leaf.BeginDecryption(6)
	if err != nil {
		t.Fatalf("BeginDecryption(6): %v", err)
	}
	adv.Commit()

	cached, err := leaf.BeginDecryption(3)
	if err != nil {
		t.Fatalf("BeginDecryption(3) from the cache: %v", err)
	}
	if key, err := cached.Key(false); err != nil || !bytes.Equal(key, want3) {
		t.Fatalf("cached key = %x (err %v), want %x", key, err, want3)
	}
	cached.Discard()
	cached.Commit()

	current, err := leaf.BeginDecryption(6)
	if err != nil {
		t.Fatalf("BeginDecryption(6) for the current generation: %v", err)
	}
	if key, err := current.Key(false); err != nil || !bytes.Equal(key, want6) {
		t.Fatalf("current key = %x (err %v), want %x", key, err, want6)
	}
	current.Discard()
	current.Commit()

	if got, err := leaf.ApplicationKey(6); err != nil || !bytes.Equal(got, want6) {
		t.Fatalf("ratchet secret changed: ApplicationKey(6) = %x (err %v), want %x", got, err, want6)
	}
	if got, err := leaf.ApplicationKey(3); err != nil || !bytes.Equal(got, want3) {
		t.Fatalf("cache entry changed: ApplicationKey(3) = %x (err %v), want %x", got, err, want3)
	}
}

// TestPendingDecryptionPastGenerationNotCached checks that a generation behind the ratchet that is not
// in the cache is refused.
func TestPendingDecryptionPastGenerationNotCached(t *testing.T) {
	leaf := newPendingTestLeaf(t)
	p, err := leaf.BeginDecryption(4)
	if err != nil {
		t.Fatalf("BeginDecryption(4): %v", err)
	}
	p.Commit()
	delete(leaf.secretCache, 1)

	if _, err := leaf.BeginDecryption(1); err == nil {
		t.Fatal("BeginDecryption(1) accepted a generation that is behind the ratchet and not cached")
	}
}

// TestStoreCachedSecretKeepsFirstEntry checks that storing a generation that is already cached keeps the
// first secrets.
func TestStoreCachedSecretKeepsFirstEntry(t *testing.T) {
	leaf := newPendingTestLeaf(t)
	first := ciphersuite.NewSecret(bytes.Repeat([]byte{0x01}, 32))
	leaf.storeCachedSecret(9, first, ciphersuite.NewSecret(bytes.Repeat([]byte{0x02}, 32)))
	leaf.storeCachedSecret(9, ciphersuite.NewSecret(bytes.Repeat([]byte{0x03}, 32)), ciphersuite.NewSecret(bytes.Repeat([]byte{0x04}, 32)))

	if n := len(leaf.secretCache); n != 1 {
		t.Fatalf("cache holds %d generations, want 1", n)
	}
	if !bytes.Equal(leaf.secretCache[9].application.AsSlice(), bytes.Repeat([]byte{0x01}, 32)) {
		t.Fatal("the second store replaced the first entry")
	}
}

// TestGenerationReplayTracking checks that a consumed generation is reported as a replay, separately for
// the handshake and the application ratchet, and that checking records nothing.
func TestGenerationReplayTracking(t *testing.T) {
	leaf := newPendingTestLeaf(t)
	for _, handshake := range []bool{false, true} {
		if err := leaf.CheckGenerationUnused(3, handshake); err != nil {
			t.Fatalf("CheckGenerationUnused(3, %v) on a fresh leaf: %v", handshake, err)
		}
		if err := leaf.CheckGenerationUnused(3, handshake); err != nil {
			t.Fatalf("CheckGenerationUnused records the generation (handshake=%v): %v", handshake, err)
		}
		if err := leaf.MarkGenerationUsed(3, handshake); err != nil {
			t.Fatalf("MarkGenerationUsed(3, %v): %v", handshake, err)
		}
		if err := leaf.CheckGenerationUnused(3, handshake); err == nil {
			t.Errorf("CheckGenerationUnused(3, %v) after Mark = nil, want a replay error", handshake)
		}
		if err := leaf.MarkGenerationUsed(3, handshake); err == nil {
			t.Errorf("second MarkGenerationUsed(3, %v) = nil, want a replay error", handshake)
		}
	}
}
