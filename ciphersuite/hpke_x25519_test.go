package ciphersuite

import (
	"bytes"
	"crypto/ecdh"
	"testing"
)

// TestX25519_HPKE_RoundTrip verifica HPKE con X25519
func TestX25519_HPKE_RoundTrip(t *testing.T) {
	cs := MLS128DHKEMX25519 // CS1: X25519 + AES-GCM
	
	// Generar key pair
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubKey := privKey.PublicKey()
	
	// Encrypt
	plaintext := []byte("Hello, X25519 HPKE!")
	label := "Test"
	context := []byte("test context")
	
	ct, err := EncryptWithLabel(pubKey.Bytes(), label, context, plaintext, cs)
	if err != nil {
		t.Fatalf("EncryptWithLabel: %v", err)
	}
	
	t.Logf("KEM output length: %d (expected: 32 for X25519)", len(ct.KEMOutput))
	t.Logf("Ciphertext length: %d", len(ct.Ciphertext))
	
	if len(ct.KEMOutput) != 32 {
		t.Errorf("KEM output length = %d, want 32 (X25519 public key size)", len(ct.KEMOutput))
	}
	
	// Decrypt
	decrypted, err := DecryptWithLabel(privKey.Bytes(), label, context, ct, cs)
	if err != nil {
		t.Fatalf("DecryptWithLabel: %v", err)
	}
	
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted = %x, want %x", decrypted, plaintext)
	}
}

// TestP256_HPKE_RoundTrip verifica HPKE con P256
func TestP256_HPKE_RoundTrip(t *testing.T) {
	cs := MLS128DHKEMP256 // CS2: P256 + AES-GCM
	
	// Generar key pair
	curve := ecdh.P256()
	privKey, err := curve.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubKey := privKey.PublicKey()
	
	// Encrypt
	plaintext := []byte("Hello, P256 HPKE!")
	label := "Test"
	context := []byte("test context")
	
	ct, err := EncryptWithLabel(pubKey.Bytes(), label, context, plaintext, cs)
	if err != nil {
		t.Fatalf("EncryptWithLabel: %v", err)
	}
	
	t.Logf("KEM output length: %d (expected: 65 for P256 uncompressed)", len(ct.KEMOutput))
	t.Logf("Ciphertext length: %d", len(ct.Ciphertext))
	
	if len(ct.KEMOutput) != 65 {
		t.Errorf("KEM output length = %d, want 65 (P256 uncompressed point size)", len(ct.KEMOutput))
	}
	
	// Decrypt
	decrypted, err := DecryptWithLabel(privKey.Bytes(), label, context, ct, cs)
	if err != nil {
		t.Fatalf("DecryptWithLabel: %v", err)
	}
	
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted = %x, want %x", decrypted, plaintext)
	}
}

// TestCS3_HPKE_RoundTrip verifica HPKE con X25519 + ChaCha20
func TestCS3_HPKE_RoundTrip(t *testing.T) {
	cs := MLS128DHKEMX25519ChaCha20 // CS3: X25519 + ChaCha20
	
	// Generar key pair
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubKey := privKey.PublicKey()
	
	// Encrypt
	plaintext := []byte("Hello, CS3 HPKE!")
	label := "Test"
	context := []byte("test context")
	
	ct, err := EncryptWithLabel(pubKey.Bytes(), label, context, plaintext, cs)
	if err != nil {
		t.Fatalf("EncryptWithLabel: %v", err)
	}
	
	t.Logf("KEM output length: %d (expected: 32 for X25519)", len(ct.KEMOutput))
	t.Logf("Ciphertext length: %d", len(ct.Ciphertext))
	
	if len(ct.KEMOutput) != 32 {
		t.Errorf("KEM output length = %d, want 32 (X25519 public key size)", len(ct.KEMOutput))
	}
	
	// Decrypt
	decrypted, err := DecryptWithLabel(privKey.Bytes(), label, context, ct, cs)
	if err != nil {
		t.Fatalf("DecryptWithLabel: %v", err)
	}
	
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted = %x, want %x", decrypted, plaintext)
	}
}
