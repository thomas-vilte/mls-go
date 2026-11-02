//go:build diagnostics

package secrettree

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// Additional diagnostics for used-generation marks, pruning and cached secrets.

const diagnosticMarksCipherSuite = ciphersuite.MLS128DHKEMP256

// newDiagnosticTrees creates a sender tree and a receiver tree with the same encryption_secret.
func newDiagnosticTrees(t *testing.T) (sender, receiver *Tree) {
	t.Helper()
	enc, err := ciphersuite.NewSecretRandom(32)
	if err != nil {
		t.Fatalf("NewSecretRandom: %v", err)
	}
	sender, err = NewTree(enc, 4, diagnosticMarksCipherSuite)
	if err != nil {
		t.Fatalf("NewTree(sender): %v", err)
	}
	receiver, err = NewTree(enc.Clone(), 4, diagnosticMarksCipherSuite)
	if err != nil {
		t.Fatalf("NewTree(receiver): %v", err)
	}
	return sender, receiver
}

// diagnosticLeaf returns the LeafSecret of leaf 0 of tree.
func diagnosticLeaf(t *testing.T, tree *Tree) *LeafSecret {
	t.Helper()
	leaf, err := tree.LeafForIndex(0)
	if err != nil {
		t.Fatalf("LeafForIndex(0): %v", err)
	}
	return leaf
}

// TestCurrentGenerationReplayRefusedAfterStateRestore checks that a consumed current generation is refused
// after the tree is persisted and restored with MarshalFull and UnmarshalFull, as the group does on every
// operation with CacheNone.
func TestCurrentGenerationReplayRefusedAfterStateRestore(t *testing.T) {
	sender, receiver := newDiagnosticTrees(t)
	aad := []byte("aad")
	ct, err := diagnosticLeaf(t, sender).Encrypt([]byte("pay 10"), aad, 0)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	rl := diagnosticLeaf(t, receiver)
	if _, err := rl.Decrypt(ct, aad, 0); err != nil {
		t.Fatalf("Decrypt(first): %v", err)
	}
	restored, err := UnmarshalFull(receiver.MarshalFull(), diagnosticMarksCipherSuite)
	if err != nil {
		t.Fatalf("UnmarshalFull: %v", err)
	}
	if pt, err := diagnosticLeaf(t, restored).Decrypt(ct, aad, 0); err == nil {
		t.Errorf("replay of generation 0 accepted after the tree was restored from MarshalFull (plaintext %q)", pt)
	}
}

// TestOlderGenerationReplayRefusedAfterRestore checks that a generation older than the ratchet, consumed before
// the tree was persisted, is refused after the restore.
func TestOlderGenerationReplayRefusedAfterRestore(t *testing.T) {
	sender, receiver := newDiagnosticTrees(t)
	aad := []byte("aad")
	sl := diagnosticLeaf(t, sender)
	var cts [][]byte
	for seq := uint64(0); seq < 3; seq++ {
		ct, err := sl.Encrypt([]byte{byte('a' + seq)}, aad, seq)
		if err != nil {
			t.Fatalf("Encrypt(%d): %v", seq, err)
		}
		cts = append(cts, ct)
	}
	rl := diagnosticLeaf(t, receiver)
	if _, err := rl.Decrypt(cts[0], aad, 0); err != nil {
		t.Fatalf("Decrypt(0): %v", err)
	}
	if _, err := rl.Decrypt(cts[2], aad, 2); err != nil {
		t.Fatalf("Decrypt(2): %v", err)
	}
	restored, err := UnmarshalFull(receiver.MarshalFull(), diagnosticMarksCipherSuite)
	if err != nil {
		t.Fatalf("UnmarshalFull: %v", err)
	}
	if _, err := diagnosticLeaf(t, restored).Decrypt(cts[0], aad, 0); err == nil {
		t.Errorf("replay of generation 0 (behind the ratchet) accepted after restore")
	}
}

// TestFailedAuthDoesNotConsumeGeneration checks that a message that fails authentication does not consume its
// generation.
func TestFailedAuthDoesNotConsumeGeneration(t *testing.T) {
	sender, receiver := newDiagnosticTrees(t)
	aad := []byte("aad")
	msg := []byte("hello")
	ct, err := diagnosticLeaf(t, sender).Encrypt(msg, aad, 0)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	rl := diagnosticLeaf(t, receiver)
	if _, err := rl.Decrypt(ct, []byte("other aad"), 0); err == nil {
		t.Fatalf("Decrypt with wrong AAD succeeded")
	}
	pt, err := rl.Decrypt(ct, aad, 0)
	if err != nil || !bytes.Equal(pt, msg) {
		t.Errorf("valid message rejected after a failed authentication: pt=%q err=%v", pt, err)
	}
}

// TestForgedFutureGenerationLeavesStateUnchanged checks that a forged message with a future generation inside
// the limit does not move the ratchet or block the later honest delivery.
func TestForgedFutureGenerationLeavesStateUnchanged(t *testing.T) {
	sender, receiver := newDiagnosticTrees(t)
	aad := []byte("aad")
	ct, err := diagnosticLeaf(t, sender).Encrypt([]byte("legit"), aad, 0)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	rl := diagnosticLeaf(t, receiver)
	forged := bytes.Repeat([]byte{0x5A}, 64)
	if _, err := rl.Decrypt(forged, aad, uint64(DefaultMaxForwardDistance)-1); err == nil {
		t.Fatalf("forged message accepted")
	}
	if gen := rl.CurrentGeneration(); gen != 0 {
		t.Errorf("forged future generation moved the ratchet to %d", gen)
	}
	if pt, err := rl.Decrypt(ct, aad, 0); err != nil || string(pt) != "legit" {
		t.Errorf("legit message after a forged one: pt=%q err=%v", pt, err)
	}
}

// TestOutOfOrderGenerationsAcceptedOnce checks out-of-order delivery with a forward jump: each generation is
// accepted once, and the replay of a cached or consumed generation is refused.
func TestOutOfOrderGenerationsAcceptedOnce(t *testing.T) {
	sender, receiver := newDiagnosticTrees(t)
	aad := []byte("aad")
	sl := diagnosticLeaf(t, sender)
	cts := make([][]byte, 4)
	for seq := range cts {
		ct, err := sl.Encrypt([]byte{byte('a' + seq)}, aad, uint64(seq))
		if err != nil {
			t.Fatalf("Encrypt(%d): %v", seq, err)
		}
		cts[seq] = ct
	}
	rl := diagnosticLeaf(t, receiver)
	order := []int{0, 3, 1, 2}
	for _, seq := range order {
		if _, err := rl.Decrypt(cts[seq], aad, uint64(seq)); err != nil {
			t.Fatalf("first delivery of %d: %v", seq, err)
		}
	}
	for _, seq := range order {
		if _, err := rl.Decrypt(cts[seq], aad, uint64(seq)); err == nil {
			t.Errorf("replay of generation %d accepted", seq)
		}
	}
}

// TestHandshakeAndApplicationMarksAreIndependent checks that the application and the handshake ratchets keep
// separate marks.
func TestHandshakeAndApplicationMarksAreIndependent(t *testing.T) {
	_, receiver := newDiagnosticTrees(t)
	rl := diagnosticLeaf(t, receiver)
	if err := rl.MarkGenerationUsed(0, false); err != nil {
		t.Fatalf("MarkGenerationUsed(0, application): %v", err)
	}
	if err := rl.CheckGenerationUnused(0, true); err != nil {
		t.Errorf("handshake generation 0 refused after application generation 0 was used: %v", err)
	}
	if err := rl.CheckGenerationUnused(0, false); err == nil {
		t.Errorf("application generation 0 accepted after it was marked used")
	}
}

// TestDecryptAfterDeleteLeafDoesNotPanic checks that a Decrypt after DeleteLeaf, which leaves the ratchets nil,
// does not panic and accepts no message.
func TestDecryptAfterDeleteLeafDoesNotPanic(t *testing.T) {
	sender, receiver := newDiagnosticTrees(t)
	aad := []byte("aad")
	ct, err := diagnosticLeaf(t, sender).Encrypt([]byte("x"), aad, 0)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	rl := diagnosticLeaf(t, receiver)
	rl.DeleteLeaf()
	for _, seq := range []uint64{0, 5} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic: Decrypt(seq=%d) after DeleteLeaf: %v", seq, r)
				}
			}()
			if _, err := rl.Decrypt(ct, aad, seq); err == nil {
				t.Errorf("Decrypt(seq=%d) after DeleteLeaf succeeded", seq)
			}
		}()
	}
}
