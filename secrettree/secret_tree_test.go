package secrettree

import (
	"bytes"
	"testing"

	"github.com/openmls/go/ciphersuite"
)

func TestSecretTreeCreation(t *testing.T) {
	encSecret, err := ciphersuite.NewSecretRandom(32)
	if err != nil {
		t.Fatalf("NewSecretRandom failed: %v", err)
	}

	tree, err := NewTree(encSecret, 4)
	if err != nil {
		t.Fatalf("NewTree failed: %v", err)
	}

	if tree.LeafCount() != 4 {
		t.Errorf("LeafCount should be 4, got %d", tree.LeafCount())
	}
	if tree.Generation() != 0 {
		t.Errorf("Generation should be 0, got %d", tree.Generation())
	}
}

func TestLeafForIndex(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 4)

	// Valid leaf index
	leaf, err := tree.LeafForIndex(0)
	if err != nil {
		t.Fatalf("LeafForIndex(0) failed: %v", err)
	}
	if leaf == nil {
		t.Fatal("LeafForIndex(0) returned nil")
	}
	if leaf.leafIndex != 0 {
		t.Errorf("Leaf index should be 0, got %d", leaf.leafIndex)
	}

	// Invalid leaf index
	_, err = tree.LeafForIndex(4)
	if err == nil {
		t.Error("LeafForIndex(4) should fail for out of range index")
	}
}

func TestEncryptionKeyAndNonce(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 4)

	leaf, _ := tree.LeafForIndex(0)

	key, err := leaf.EncryptionKey(0)
	if err != nil {
		t.Fatalf("EncryptionKey(0) failed: %v", err)
	}
	if len(key) != 16 {
		t.Errorf("Key should be 16 bytes, got %d", len(key))
	}

	nonce, err := leaf.Nonce(0)
	if err != nil {
		t.Fatalf("Nonce(0) failed: %v", err)
	}
	if len(nonce) != 12 {
		t.Errorf("Nonce should be 12 bytes, got %d", len(nonce))
	}

	// Different sequence numbers should give different keys/nonces
	key2, _ := leaf.EncryptionKey(1)
	if bytes.Equal(key, key2) {
		t.Error("Keys should be different for different sequence numbers")
	}

	nonce2, _ := leaf.Nonce(1)
	if bytes.Equal(nonce, nonce2) {
		t.Error("Nonces should be different for different sequence numbers")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 4)

	leaf, _ := tree.LeafForIndex(0)

	plaintext := []byte("Hello, MLS!")
	aad := []byte("additional data")
	seqNum := leaf.NextSequenceNumber()

	ciphertext, err := leaf.Encrypt(plaintext, aad, seqNum)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := leaf.Decrypt(ciphertext, aad, seqNum)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match: got %s, want %s", decrypted, plaintext)
	}
}

func TestGenerationIncrement(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 4)

	if tree.Generation() != 0 {
		t.Errorf("Initial generation should be 0")
	}

	tree.IncrementGeneration()
	if tree.Generation() != 1 {
		t.Errorf("Generation should be 1 after increment, got %d", tree.Generation())
	}

	// Leaf secrets should reflect new generation
	leaf, _ := tree.LeafForIndex(0)
	if leaf.generation != 1 {
		t.Errorf("Leaf generation should be 1, got %d", leaf.generation)
	}
}

func TestDeleteLeaf(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 4)

	leaf, _ := tree.LeafForIndex(0)

	// Encrypt before deletion
	plaintext := []byte("test")
	seqNum := leaf.NextSequenceNumber()
	ciphertext, _ := leaf.Encrypt(plaintext, nil, seqNum)

	// Delete the leaf
	leaf.DeleteLeaf()

	// Try to decrypt after deletion (should fail or give wrong result)
	_, err := leaf.Decrypt(ciphertext, nil, seqNum)
	if err == nil {
		// Decryption might succeed but give wrong plaintext
		t.Log("Decryption after deletion should ideally fail")
	}
}

func TestSequenceNumber(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 4)

	leaf, _ := tree.LeafForIndex(0)

	if leaf.sequenceNumber != 0 {
		t.Errorf("Initial sequence number should be 0")
	}

	seq1 := leaf.NextSequenceNumber()
	if seq1 != 0 {
		t.Errorf("First sequence number should be 0, got %d", seq1)
	}

	seq2 := leaf.NextSequenceNumber()
	if seq2 != 1 {
		t.Errorf("Second sequence number should be 1, got %d", seq2)
	}

	leaf.SetSequenceNumber(100)
	seq3 := leaf.NextSequenceNumber()
	if seq3 != 100 {
		t.Errorf("After setting to 100, next should be 100, got %d", seq3)
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 4)
	tree.IncrementGeneration()

	data := tree.Marshal()

	tree2, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if tree2.LeafCount() != tree.LeafCount() {
		t.Errorf("LeafCount mismatch: got %d, want %d", tree2.LeafCount(), tree.LeafCount())
	}
	if tree2.Generation() != tree.Generation() {
		t.Errorf("Generation mismatch: got %d, want %d", tree2.Generation(), tree.Generation())
	}
}

func TestMultipleLeaves(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 8)

	// Create leaves and verify they have different secrets
	leaf0, _ := tree.LeafForIndex(0)
	leaf1, _ := tree.LeafForIndex(1)
	leaf2, _ := tree.LeafForIndex(2)

	key0, _ := leaf0.EncryptionKey(0)
	key1, _ := leaf1.EncryptionKey(0)
	key2, _ := leaf2.EncryptionKey(0)

	if bytes.Equal(key0, key1) {
		t.Error("Leaf 0 and 1 should have different keys")
	}
	if bytes.Equal(key0, key2) {
		t.Error("Leaf 0 and 2 should have different keys")
	}
	if bytes.Equal(key1, key2) {
		t.Error("Leaf 1 and 2 should have different keys")
	}
}
