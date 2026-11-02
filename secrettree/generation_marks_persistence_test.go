package secrettree

import (
	"encoding/json"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

const marksTestCipherSuite = ciphersuite.MLS128DHKEMP256

// newMarksTestTrees returns a sender tree and a receiver tree that share one encryption_secret.
func newMarksTestTrees(t *testing.T) (sender, receiver *Tree) {
	t.Helper()
	enc, err := ciphersuite.NewSecretRandom(32)
	if err != nil {
		t.Fatalf("NewSecretRandom: %v", err)
	}
	sender, err = NewTree(enc, 4, marksTestCipherSuite)
	if err != nil {
		t.Fatalf("NewTree(sender): %v", err)
	}
	receiver, err = NewTree(enc.Clone(), 4, marksTestCipherSuite)
	if err != nil {
		t.Fatalf("NewTree(receiver): %v", err)
	}
	return sender, receiver
}

// TestConsumedCurrentGenerationStaysConsumedAfterJSONRestore checks that a message consumed at the current
// generation is still refused after the receiver tree is persisted as JSON, as the group state stores it, and
// restored.
func TestConsumedCurrentGenerationStaysConsumedAfterJSONRestore(t *testing.T) {
	sender, receiver := newMarksTestTrees(t)
	aad := []byte("aad")
	sl, err := sender.LeafForIndex(0)
	if err != nil {
		t.Fatalf("LeafForIndex(sender): %v", err)
	}
	ct, err := sl.Encrypt([]byte("pay 10"), aad, 0)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	rl, err := receiver.LeafForIndex(0)
	if err != nil {
		t.Fatalf("LeafForIndex(receiver): %v", err)
	}
	if _, err := rl.Decrypt(ct, aad, 0); err != nil {
		t.Fatalf("Decrypt(first): %v", err)
	}

	raw, err := json.Marshal(receiver.MarshalFull())
	if err != nil {
		t.Fatalf("json.Marshal(TreeState): %v", err)
	}
	var state TreeState
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatalf("json.Unmarshal(TreeState): %v", err)
	}
	restored, err := UnmarshalFull(&state, marksTestCipherSuite)
	if err != nil {
		t.Fatalf("UnmarshalFull: %v", err)
	}
	restoredLeaf, err := restored.LeafForIndex(0)
	if err != nil {
		t.Fatalf("LeafForIndex(restored): %v", err)
	}
	if pt, err := restoredLeaf.Decrypt(ct, aad, 0); err == nil {
		t.Errorf("replay of consumed generation 0 accepted after a JSON round trip (plaintext %q)", pt)
	}
}

// TestMarksOfBothRatchetsSurviveRestore checks that the application and the handshake
// marks are persisted separately, and that a generation that was never marked stays usable.
func TestMarksOfBothRatchetsSurviveRestore(t *testing.T) {
	_, receiver := newMarksTestTrees(t)
	leaf, err := receiver.LeafForIndex(0)
	if err != nil {
		t.Fatalf("LeafForIndex: %v", err)
	}
	if err := leaf.MarkGenerationUsed(0, false); err != nil {
		t.Fatalf("MarkGenerationUsed(0, application): %v", err)
	}
	if err := leaf.MarkGenerationUsed(0, true); err != nil {
		t.Fatalf("MarkGenerationUsed(0, handshake): %v", err)
	}

	restored, err := UnmarshalFull(receiver.MarshalFull(), marksTestCipherSuite)
	if err != nil {
		t.Fatalf("UnmarshalFull: %v", err)
	}
	rl, err := restored.LeafForIndex(0)
	if err != nil {
		t.Fatalf("LeafForIndex(restored): %v", err)
	}
	if err := rl.CheckGenerationUnused(0, false); err == nil {
		t.Error("application generation 0 accepted after restore, although it was marked used")
	}
	if err := rl.CheckGenerationUnused(0, true); err == nil {
		t.Error("handshake generation 0 accepted after restore, although it was marked used")
	}
	if err := rl.CheckGenerationUnused(1, false); err != nil {
		t.Errorf("unmarked generation 1 refused after restore: %v", err)
	}
}

// TestMarksAreSerializedInOrder checks the persisted form of the marks: ascending order,
// and only in the fields of their own ratchet.
func TestMarksAreSerializedInOrder(t *testing.T) {
	_, receiver := newMarksTestTrees(t)
	leaf, err := receiver.LeafForIndex(0)
	if err != nil {
		t.Fatalf("LeafForIndex: %v", err)
	}
	// Marks ahead of the ratchet position do not move the ratchet.
	for _, gen := range []uint32{2, 1} {
		if err := leaf.MarkGenerationUsed(gen, false); err != nil {
			t.Fatalf("MarkGenerationUsed(%d, application): %v", gen, err)
		}
	}

	ls := receiver.MarshalFull().LeafStates[0]
	if len(ls.UsedApplicationGenerations) != 2 || ls.UsedApplicationGenerations[0] != 1 || ls.UsedApplicationGenerations[1] != 2 {
		t.Errorf("UsedApplicationGenerations = %v, want [1 2]", ls.UsedApplicationGenerations)
	}
	if len(ls.UsedHandshakeGenerations) != 0 {
		t.Errorf("UsedHandshakeGenerations = %v, want none", ls.UsedHandshakeGenerations)
	}
}

// TestRestoreDropsMarksBehindRatchet checks that a mark behind the ratchet position is not restored, as
// cacheSkippedGeneration prunes it when the ratchet moves past it.
func TestRestoreDropsMarksBehindRatchet(t *testing.T) {
	marks := restoreGenerationMarks([]uint32{1, 3, 5}, 3)
	if _, ok := marks[1]; ok {
		t.Error("mark 1, behind position 3, was restored")
	}
	if _, ok := marks[3]; !ok {
		t.Error("mark at position 3 was dropped")
	}
	if _, ok := marks[5]; !ok {
		t.Error("mark 5, ahead of position 3, was dropped")
	}
	if got := restoreGenerationMarks(nil, 0); got != nil {
		t.Errorf("restoreGenerationMarks(nil) = %v, want nil", got)
	}
}
