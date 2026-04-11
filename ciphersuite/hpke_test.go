package ciphersuite

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

// TestHPKE_EncryptDecrypt tests complete HPKE encryption/decryption.
func TestHPKE_EncryptDecrypt(t *testing.T) {
	// Generate key pair
	privKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	publicKey := privKey.PublicKey().Bytes()

	plaintext := []byte("Hello, MLS!")
	label := "test encryption"
	context := []byte("context data")
	cs := MLS128DHKEMP256

	// Encrypt
	ciphertext, err := EncryptWithLabel(publicKey, label, context, plaintext, cs)
	if err != nil {
		t.Fatalf("EncryptWithLabel() error = %v", err)
	}

	// Verify ciphertext has KEMOutput and Ciphertext
	if len(ciphertext.KEMOutput) == 0 {
		t.Error("KEMOutput should not be empty")
	}
	if len(ciphertext.Ciphertext) == 0 {
		t.Error("Ciphertext should not be empty")
	}

	// Decrypt
	privKeyBytes := privKey.Bytes()
	decrypted, err := DecryptWithLabel(privKeyBytes, label, context, ciphertext, cs)
	if err != nil {
		t.Fatalf("DecryptWithLabel() error = %v", err)
	}

	// Verify
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption mismatch:\ngot  %s\nwant %s", decrypted, plaintext)
	}
}

// TestHPKE_WrongKey tests that it fails with wrong private key.
func TestHPKE_WrongKey(t *testing.T) {
	// Generate two key pairs
	privKey1, _ := ecdh.P256().GenerateKey(rand.Reader)
	privKey2, _ := ecdh.P256().GenerateKey(rand.Reader)

	publicKey1 := privKey1.PublicKey().Bytes()
	plaintext := []byte("Secret message")
	label := "test"
	var context []byte
	cs := MLS128DHKEMP256

	// Encrypt with key 1
	ciphertext, err := EncryptWithLabel(publicKey1, label, context, plaintext, cs)
	if err != nil {
		t.Fatalf("EncryptWithLabel() error = %v", err)
	}

	// Try decrypt with key 2 (wrong)
	privKey2Bytes := privKey2.Bytes()
	_, err = DecryptWithLabel(privKey2Bytes, label, context, ciphertext, cs)
	if err == nil {
		t.Error("DecryptWithLabel() should fail with wrong private key")
	}
}

// TestHPKE_TamperedCiphertext tests that it detects modified ciphertext.
func TestHPKE_TamperedCiphertext(t *testing.T) {
	privKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey().Bytes()

	plaintext := []byte("Secret message")
	label := "test"
	var context []byte
	cs := MLS128DHKEMP256

	// Encrypt
	ciphertext, err := EncryptWithLabel(publicKey, label, context, plaintext, cs)
	if err != nil {
		t.Fatalf("EncryptWithLabel() error = %v", err)
	}

	// Tamper with ciphertext
	tampered := &HpkeCiphertext{
		KEMOutput:  make([]byte, len(ciphertext.KEMOutput)),
		Ciphertext: make([]byte, len(ciphertext.Ciphertext)),
	}
	copy(tampered.KEMOutput, ciphertext.KEMOutput)
	copy(tampered.Ciphertext, ciphertext.Ciphertext)
	tampered.Ciphertext[0] ^= 0xFF // Modify first byte

	// Decrypt with modified data should fail
	privKeyBytes := privKey.Bytes()
	_, err = DecryptWithLabel(privKeyBytes, label, context, tampered, cs)
	if err == nil {
		t.Error("DecryptWithLabel() should fail with tampered ciphertext")
	}
}

// TestHPKE_EmptyPlaintext tests empty plaintext encryption.
func TestHPKE_EmptyPlaintext(t *testing.T) {
	privKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey().Bytes()

	var plaintext []byte
	label := "test"
	var context []byte
	cs := MLS128DHKEMP256

	// Encrypt empty plaintext
	ciphertext, err := EncryptWithLabel(publicKey, label, context, plaintext, cs)
	if err != nil {
		t.Fatalf("EncryptWithLabel() error = %v", err)
	}

	// Decrypt
	privKeyBytes := privKey.Bytes()
	decrypted, err := DecryptWithLabel(privKeyBytes, label, context, ciphertext, cs)
	if err != nil {
		t.Fatalf("DecryptWithLabel() error = %v", err)
	}

	// Check
	if len(decrypted) != 0 {
		t.Errorf("Expected empty decrypted data, got %d bytes", len(decrypted))
	}
}

// TestHPKE_LargePlaintext tests large plaintext encryption.
func TestHPKE_LargePlaintext(t *testing.T) {
	privKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey().Bytes()

	// 1KB plaintext
	plaintext := make([]byte, 1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	label := "test"
	var context []byte
	cs := MLS128DHKEMP256

	// Encrypt
	ciphertext, err := EncryptWithLabel(publicKey, label, context, plaintext, cs)
	if err != nil {
		t.Fatalf("EncryptWithLabel() error = %v", err)
	}

	// Decrypt
	privKeyBytes := privKey.Bytes()
	decrypted, err := DecryptWithLabel(privKeyBytes, label, context, ciphertext, cs)
	if err != nil {
		t.Fatalf("DecryptWithLabel() error = %v", err)
	}

	// Verify
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption mismatch for large plaintext")
	}
}

// TestHPKE_DifferentLabels tests that different labels produce different ciphertexts.
func TestHPKE_DifferentLabels(t *testing.T) {
	privKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey().Bytes()

	plaintext := []byte("Same plaintext")
	var context []byte
	cs := MLS128DHKEMP256

	// Encrypt with different labels
	ciphertext1, err := EncryptWithLabel(publicKey, "label1", context, plaintext, cs)
	if err != nil {
		t.Fatalf("EncryptWithLabel() error = %v", err)
	}

	ciphertext2, err := EncryptWithLabel(publicKey, "label2", context, plaintext, cs)
	if err != nil {
		t.Fatalf("EncryptWithLabel() error = %v", err)
	}

	// Ciphertexts should be different (different KEMOutput due to different ephemeral key)
	if bytes.Equal(ciphertext1.KEMOutput, ciphertext2.KEMOutput) {
		t.Error("Different labels should produce different KEMOutputs")
	}
}

// TestHPKE_InvalidPublicKey tests that it fails with invalid public key.
func TestHPKE_InvalidPublicKey(t *testing.T) {
	invalidPublicKey := []byte("invalid key")
	plaintext := []byte("test")
	label := "test"
	var context []byte
	cs := MLS128DHKEMP256

	_, err := EncryptWithLabel(invalidPublicKey, label, context, plaintext, cs)
	if err == nil {
		t.Error("EncryptWithLabel() should fail with invalid public key")
	}
}

// TestHPKE_InvalidPrivateKey tests that it fails with invalid private key.
func TestHPKE_InvalidPrivateKey(t *testing.T) {
	privKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey().Bytes()

	plaintext := []byte("test")
	label := "test"
	var context []byte
	cs := MLS128DHKEMP256

	// Encrypt
	ciphertext, err := EncryptWithLabel(publicKey, label, context, plaintext, cs)
	if err != nil {
		t.Fatalf("EncryptWithLabel() error = %v", err)
	}

	// Decrypt with invalid private key
	invalidPrivKey := []byte("invalid key")
	_, err = DecryptWithLabel(invalidPrivKey, label, context, ciphertext, cs)
	if err == nil {
		t.Error("DecryptWithLabel() should fail with invalid private key")
	}
}

// TestEncryptContext tests EncryptContext creation and serialization.
func TestEncryptContext(t *testing.T) {
	label := "test label"
	context := []byte("test context")

	encContext := NewEncryptContext(label, context)

	// Verify label has MLS prefix
	expectedLabel := LabelPrefix + label
	if !bytes.Equal(encContext.Label, []byte(expectedLabel)) {
		t.Errorf("Label mismatch:\ngot  %s\nwant %s", encContext.Label, expectedLabel)
	}

	// Verify context
	if !bytes.Equal(encContext.Context, context) {
		t.Errorf("Context mismatch:\ngot  %v\nwant %v", encContext.Context, context)
	}

	// Verify marshaling
	marshaled := encContext.Marshal()
	if len(marshaled) == 0 {
		t.Error("Marshaled context should not be empty")
	}
}

// BenchmarkHPKE_Encrypt measures encrypt performance.
func BenchmarkHPKE_Encrypt(b *testing.B) {
	privKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey().Bytes()
	plaintext := []byte("Hello, MLS!")
	label := "benchmark"
	var context []byte
	cs := MLS128DHKEMP256

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := EncryptWithLabel(publicKey, label, context, plaintext, cs); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHPKE_Decrypt measures decrypt performance.
func BenchmarkHPKE_Decrypt(b *testing.B) {
	privKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey().Bytes()
	plaintext := []byte("Hello, MLS!")
	label := "benchmark"
	var context []byte
	cs := MLS128DHKEMP256

	// Pre-encrypt
	ciphertext, err := EncryptWithLabel(publicKey, label, context, plaintext, cs)
	if err != nil {
		b.Fatal(err)
	}
	privKeyBytes := privKey.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := DecryptWithLabel(privKeyBytes, label, context, ciphertext, cs); err != nil {
			b.Fatal(err)
		}
	}
}
