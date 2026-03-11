package secrettree

import (
	"bytes"
	"testing"

	"github.com/openmls/go/ciphersuite"
)

// ============================================================================
// Tree creation
// ============================================================================

func TestSecretTreeCreation(t *testing.T) {
	encSecret, err := ciphersuite.NewSecretRandom(32)
	if err != nil {
		t.Fatalf("NewSecretRandom: %v", err)
	}
	tree, err := NewTree(encSecret, 4, ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	if tree.LeafCount() != 4 {
		t.Errorf("LeafCount = %d, want 4", tree.LeafCount())
	}
	if tree.Generation() != 0 {
		t.Errorf("Generation = %d, want 0", tree.Generation())
	}
}

func TestLeafForIndex_OutOfRange(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 4, ciphersuite.MLS128DHKEMP256)
	if _, err := tree.LeafForIndex(4); err == nil {
		t.Error("expected error for out-of-range leaf index")
	}
}

// ============================================================================
// Application ratchet — RFC 9420 §9.1
// ============================================================================

func TestApplicationKey_SizeAndDiverge(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 4, ciphersuite.MLS128DHKEMP256)
	leaf, _ := tree.LeafForIndex(0)

	k0, err := leaf.ApplicationKey(0)
	if err != nil {
		t.Fatalf("ApplicationKey(0): %v", err)
	}
	if len(k0) != 16 {
		t.Errorf("key len = %d, want 16", len(k0))
	}

	n0, err := leaf.ApplicationNonce(0)
	if err != nil {
		t.Fatalf("ApplicationNonce(0): %v", err)
	}
	if len(n0) != 12 {
		t.Errorf("nonce len = %d, want 12", len(n0))
	}

	// Different generations → different outputs.
	k1, _ := leaf.ApplicationKey(1)
	if bytes.Equal(k0, k1) {
		t.Error("ApplicationKey: gen 0 and gen 1 must differ")
	}
	n1, _ := leaf.ApplicationNonce(1)
	if bytes.Equal(n0, n1) {
		t.Error("ApplicationNonce: gen 0 and gen 1 must differ")
	}
}

// ============================================================================
// Handshake ratchet — RFC 9420 §9.1
// ============================================================================

func TestHandshakeKey_SizeAndDiverge(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 4, ciphersuite.MLS128DHKEMP256)
	leaf, _ := tree.LeafForIndex(0)

	hk0, err := leaf.HandshakeKey(0)
	if err != nil {
		t.Fatalf("HandshakeKey(0): %v", err)
	}
	if len(hk0) != 16 {
		t.Errorf("key len = %d, want 16", len(hk0))
	}

	hn0, err := leaf.HandshakeNonce(0)
	if err != nil {
		t.Fatalf("HandshakeNonce(0): %v", err)
	}
	if len(hn0) != 12 {
		t.Errorf("nonce len = %d, want 12", len(hn0))
	}

	hk1, _ := leaf.HandshakeKey(1)
	if bytes.Equal(hk0, hk1) {
		t.Error("HandshakeKey: gen 0 and gen 1 must differ")
	}
}

// TestHandshakeAppKeysDiffer verifies that handshake and application ratchets
// produce distinct keys for the same generation (RFC 9420 §9.1).
func TestHandshakeAppKeysDiffer(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 4, ciphersuite.MLS128DHKEMP256)
	leaf, _ := tree.LeafForIndex(0)

	appKey, _ := leaf.ApplicationKey(0)
	hsKey, _ := leaf.HandshakeKey(0)
	if bytes.Equal(appKey, hsKey) {
		t.Error("application and handshake keys must differ for the same generation")
	}
}

// ============================================================================
// Advance — forward secrecy (RFC 9420 §9.1)
// ============================================================================

// TestAdvance_ForwardSecrecy verifies that Advance() bumps CurrentGeneration and
// that keys derived after Advance differ from those before.
func TestAdvance_ForwardSecrecy(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 4, ciphersuite.MLS128DHKEMP256)
	leaf, _ := tree.LeafForIndex(0)

	// Derive gen-0 key before advancing.
	keyBefore, err := leaf.ApplicationKey(0)
	if err != nil {
		t.Fatalf("ApplicationKey(0) before Advance: %v", err)
	}

	if err := leaf.Advance(); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	if leaf.CurrentGeneration() != 1 {
		t.Errorf("CurrentGeneration = %d, want 1", leaf.CurrentGeneration())
	}

	// After advancing, gen-1 key must differ from gen-0.
	keyAfter, err := leaf.ApplicationKey(1)
	if err != nil {
		t.Fatalf("ApplicationKey(1) after Advance: %v", err)
	}
	if bytes.Equal(keyBefore, keyAfter) {
		t.Error("key must change after Advance")
	}
}

// ============================================================================
// CurrentGeneration
// ============================================================================

func TestCurrentGeneration(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 4, ciphersuite.MLS128DHKEMP256)
	leaf, _ := tree.LeafForIndex(0)

	if leaf.CurrentGeneration() != 0 {
		t.Errorf("initial generation = %d, want 0", leaf.CurrentGeneration())
	}
	leaf.Advance()
	if leaf.CurrentGeneration() != 1 {
		t.Errorf("after Advance generation = %d, want 1", leaf.CurrentGeneration())
	}
	leaf.Advance()
	if leaf.CurrentGeneration() != 2 {
		t.Errorf("after 2x Advance generation = %d, want 2", leaf.CurrentGeneration())
	}
}

// ============================================================================
// DeleteLeaf — RFC 9420 §9.1 forward secrecy
// ============================================================================

// TestDeleteLeaf verifies that after DeleteLeaf the ratchet secrets are zeroed
// so that subsequent decrypt attempts fail (keys are no longer meaningful).
func TestDeleteLeaf(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 4, ciphersuite.MLS128DHKEMP256)
	leaf, _ := tree.LeafForIndex(0)

	// Encrypt a message before deletion.
	plaintext := []byte("secret message")
	seqNum := leaf.NextSequenceNumber()
	ciphertext, err := leaf.Encrypt(plaintext, nil, seqNum)
	if err != nil {
		t.Fatalf("Encrypt before DeleteLeaf: %v", err)
	}

	// Capture key before deletion.
	keyBefore, _ := leaf.ApplicationKey(0)

	leaf.DeleteLeaf()

	// After deletion, key derivation still succeeds (it uses zeroed ratchet
	// state) but must produce a different (zeroed-derived) key than before.
	keyAfter, err := leaf.ApplicationKey(0)
	if err != nil {
		t.Fatalf("ApplicationKey after DeleteLeaf: %v", err)
	}
	if bytes.Equal(keyBefore, keyAfter) {
		t.Error("DeleteLeaf must change the derived key (secrets should be zeroed)")
	}

	// Decryption with the zeroed ratchet should fail or produce garbage.
	decrypted, err := leaf.Decrypt(ciphertext, nil, seqNum)
	if err == nil && bytes.Equal(decrypted, plaintext) {
		t.Error("Decrypt after DeleteLeaf should not recover the original plaintext")
	}
}

// ============================================================================
// Encrypt / Decrypt roundtrip
// ============================================================================

func TestEncryptDecrypt(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 4, ciphersuite.MLS128DHKEMP256)
	leaf, _ := tree.LeafForIndex(0)

	plaintext := []byte("Hello, MLS!")
	aad := []byte("additional data")
	seqNum := leaf.NextSequenceNumber()

	ct, err := leaf.Encrypt(plaintext, aad, seqNum)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := leaf.Decrypt(ct, aad, seqNum)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(plaintext, got) {
		t.Errorf("decrypted = %q, want %q", got, plaintext)
	}
}

func TestDecrypt_WrongAAD(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 4, ciphersuite.MLS128DHKEMP256)
	leaf, _ := tree.LeafForIndex(0)

	seqNum := leaf.NextSequenceNumber()
	ct, _ := leaf.Encrypt([]byte("msg"), []byte("aad"), seqNum)
	if _, err := leaf.Decrypt(ct, []byte("wrong-aad"), seqNum); err == nil {
		t.Error("Decrypt should fail with wrong AAD")
	}
}

// ============================================================================
// SequenceNumber
// ============================================================================

func TestSequenceNumber(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 4, ciphersuite.MLS128DHKEMP256)
	leaf, _ := tree.LeafForIndex(0)

	if leaf.NextSequenceNumber() != 0 {
		t.Error("first NextSequenceNumber should be 0")
	}
	if leaf.NextSequenceNumber() != 1 {
		t.Error("second NextSequenceNumber should be 1")
	}
	leaf.SetSequenceNumber(100)
	if leaf.NextSequenceNumber() != 100 {
		t.Error("after SetSequenceNumber(100), next should be 100")
	}
}

// ============================================================================
// IncrementGeneration
// ============================================================================

func TestGenerationIncrement(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 4, ciphersuite.MLS128DHKEMP256)

	if tree.Generation() != 0 {
		t.Error("initial tree generation should be 0")
	}
	tree.IncrementGeneration()
	if tree.Generation() != 1 {
		t.Errorf("after IncrementGeneration = %d, want 1", tree.Generation())
	}

	leaf, _ := tree.LeafForIndex(0)
	if leaf.generation != 1 {
		t.Errorf("leaf generation = %d, want 1", leaf.generation)
	}
}

// ============================================================================
// Multiple leaves produce distinct secrets
// ============================================================================

func TestMultipleLeaves_DistinctKeys(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 8, ciphersuite.MLS128DHKEMP256)

	keys := make([][]byte, 3)
	for i := range keys {
		leaf, _ := tree.LeafForIndex(uint32(i))
		k, err := leaf.ApplicationKey(0)
		if err != nil {
			t.Fatalf("ApplicationKey leaf %d: %v", i, err)
		}
		keys[i] = k
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if bytes.Equal(keys[i], keys[j]) {
				t.Errorf("leaves %d and %d share the same key", i, j)
			}
		}
	}
}

// ============================================================================
// Marshal / Unmarshal
// ============================================================================

func TestMarshalUnmarshal(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 4, ciphersuite.MLS128DHKEMP256)
	tree.IncrementGeneration()

	data := tree.Marshal()
	tree2, err := Unmarshal(data, ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if tree2.LeafCount() != tree.LeafCount() {
		t.Errorf("LeafCount = %d, want %d", tree2.LeafCount(), tree.LeafCount())
	}
	if tree2.Generation() != tree.Generation() {
		t.Errorf("Generation = %d, want %d", tree2.Generation(), tree.Generation())
	}
}
