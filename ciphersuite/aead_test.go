// Copyright 2024 MLS-Go Authors. All rights reserved.
// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE file.

package ciphersuite

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// ============================================================================
// AES-128-GCM Tests
// ============================================================================

// TestAESEncrypt_RoundTrip tests AES-128-GCM encryption/decryption round-trip.
func TestAESEncrypt_RoundTrip(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	plaintext := []byte("Hello, AES-GCM!")
	aad := []byte("additional data")

	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating key: %v", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generating nonce: %v", err)
	}

	ciphertext, err := AESEncrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("AESEncrypt() error = %v", err)
	}

	decrypted, err := AESDecrypt(key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("AESDecrypt() error = %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption mismatch:\ngot  %q\nwant %q", decrypted, plaintext)
	}
}

// TestAESEncrypt_WrongKey tests that wrong key causes decryption failure.
func TestAESEncrypt_WrongKey(t *testing.T) {
	key1 := make([]byte, 16)
	key2 := make([]byte, 16)
	nonce := make([]byte, 12)
	plaintext := []byte("Secret message")
	aad := []byte("aad")

	if _, err := rand.Read(key1); err != nil {
		t.Fatalf("generating key1: %v", err)
	}
	if _, err := rand.Read(key2); err != nil {
		t.Fatalf("generating key2: %v", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generating nonce: %v", err)
	}

	ciphertext, err := AESEncrypt(key1, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("AESEncrypt() error = %v", err)
	}

	// Decrypt with wrong key should fail
	_, err = AESDecrypt(key2, nonce, ciphertext, aad)
	if err == nil {
		t.Error("AESDecrypt() should fail with wrong key")
	}
}

// TestAESEncrypt_TamperedData tests that tampered ciphertext causes failure.
func TestAESEncrypt_TamperedData(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	plaintext := []byte("Secret message")
	aad := []byte("aad")

	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating key: %v", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generating nonce: %v", err)
	}

	ciphertext, err := AESEncrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("AESEncrypt() error = %v", err)
	}

	// Tamper with ciphertext
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[0] ^= 0xFF

	// Decrypt tampered data should fail
	_, err = AESDecrypt(key, nonce, tampered, aad)
	if err == nil {
		t.Error("AESDecrypt() should fail with tampered ciphertext")
	}
}

// TestAESEncrypt_WrongAAD tests that wrong AAD causes decryption failure.
func TestAESEncrypt_WrongAAD(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	plaintext := []byte("Secret message")
	aad1 := []byte("aad1")
	aad2 := []byte("aad2")

	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating key: %v", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generating nonce: %v", err)
	}

	ciphertext, err := AESEncrypt(key, nonce, plaintext, aad1)
	if err != nil {
		t.Fatalf("AESEncrypt() error = %v", err)
	}

	// Decrypt with wrong AAD should fail
	_, err = AESDecrypt(key, nonce, ciphertext, aad2)
	if err == nil {
		t.Error("AESDecrypt() should fail with wrong AAD")
	}
}

// TestAESEncrypt_WrongKeyLength tests invalid key length.
func TestAESEncrypt_WrongKeyLength(t *testing.T) {
	key := make([]byte, 20) // Wrong length (should be 16)
	nonce := make([]byte, 12)
	plaintext := []byte("test")

	_, err := AESEncrypt(key, nonce, plaintext, nil)
	if err == nil {
		t.Error("AESEncrypt() should fail with wrong key length")
	}
}

// TestAESEncrypt_WrongNonceLength tests invalid nonce length.
func TestAESEncrypt_WrongNonceLength(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 16) // Wrong length (should be 12)
	plaintext := []byte("test")

	_, err := AESEncrypt(key, nonce, plaintext, nil)
	if err == nil {
		t.Error("AESEncrypt() should fail with wrong nonce length")
	}
}

// TestAESDecrypt_WrongKeyLength tests invalid key length for decryption.
func TestAESDecrypt_WrongKeyLength(t *testing.T) {
	key := make([]byte, 20) // Wrong length
	nonce := make([]byte, 12)
	ciphertext := []byte("test")

	_, err := AESDecrypt(key, nonce, ciphertext, nil)
	if err == nil {
		t.Error("AESDecrypt() should fail with wrong key length")
	}
}

// TestAESDecrypt_WrongNonceLength tests invalid nonce length for decryption.
func TestAESDecrypt_WrongNonceLength(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 16) // Wrong length
	ciphertext := []byte("test")

	_, err := AESDecrypt(key, nonce, ciphertext, nil)
	if err == nil {
		t.Error("AESDecrypt() should fail with wrong nonce length")
	}
}

// ============================================================================
// ChaCha20-Poly1305 Tests
// ============================================================================

// TestChaCha20Poly1305_RoundTrip tests ChaCha20-Poly1305 round-trip.
func TestChaCha20Poly1305_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	plaintext := []byte("Hello, ChaCha20!")
	aad := []byte("additional data")

	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating key: %v", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generating nonce: %v", err)
	}

	ciphertext, err := ChaCha20Poly1305Encrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("ChaCha20Poly1305Encrypt() error = %v", err)
	}

	decrypted, err := ChaCha20Poly1305Decrypt(key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("ChaCha20Poly1305Decrypt() error = %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption mismatch:\ngot  %q\nwant %q", decrypted, plaintext)
	}
}

// TestChaCha20Poly1305_WrongKey tests wrong key for ChaCha20.
func TestChaCha20Poly1305_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	nonce := make([]byte, 12)
	plaintext := []byte("Secret message")
	aad := []byte("aad")

	if _, err := rand.Read(key1); err != nil {
		t.Fatalf("generating key1: %v", err)
	}
	if _, err := rand.Read(key2); err != nil {
		t.Fatalf("generating key2: %v", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generating nonce: %v", err)
	}

	ciphertext, err := ChaCha20Poly1305Encrypt(key1, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("ChaCha20Poly1305Encrypt() error = %v", err)
	}

	_, err = ChaCha20Poly1305Decrypt(key2, nonce, ciphertext, aad)
	if err == nil {
		t.Error("ChaCha20Poly1305Decrypt() should fail with wrong key")
	}
}

// TestChaCha20Poly1305_TamperedData tests tampered ciphertext for ChaCha20.
func TestChaCha20Poly1305_TamperedData(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	plaintext := []byte("Secret message")
	aad := []byte("aad")

	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating key: %v", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generating nonce: %v", err)
	}

	ciphertext, err := ChaCha20Poly1305Encrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("ChaCha20Poly1305Encrypt() error = %v", err)
	}

	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[0] ^= 0xFF

	_, err = ChaCha20Poly1305Decrypt(key, nonce, tampered, aad)
	if err == nil {
		t.Error("ChaCha20Poly1305Decrypt() should fail with tampered ciphertext")
	}
}

// TestChaCha20Poly1305_WrongAAD tests wrong AAD for ChaCha20.
func TestChaCha20Poly1305_WrongAAD(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	plaintext := []byte("Secret message")
	aad1 := []byte("aad1")
	aad2 := []byte("aad2")

	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating key: %v", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generating nonce: %v", err)
	}

	ciphertext, err := ChaCha20Poly1305Encrypt(key, nonce, plaintext, aad1)
	if err != nil {
		t.Fatalf("ChaCha20Poly1305Encrypt() error = %v", err)
	}

	_, err = ChaCha20Poly1305Decrypt(key, nonce, ciphertext, aad2)
	if err == nil {
		t.Error("ChaCha20Poly1305Decrypt() should fail with wrong AAD")
	}
}

// ============================================================================
// EncryptWithCipherSuite / DecryptWithCipherSuite Tests
// ============================================================================

// TestEncryptWithCipherSuite_AES tests AES-GCM via EncryptWithCipherSuite.
func TestEncryptWithCipherSuite_AES(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	plaintext := []byte("Test AES encryption")
	aad := []byte("aad")

	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating key: %v", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generating nonce: %v", err)
	}

	ciphertext, err := EncryptWithCipherSuite(key, nonce, plaintext, aad, MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("EncryptWithCipherSuite(AES) error = %v", err)
	}

	decrypted, err := DecryptWithCipherSuite(key, nonce, ciphertext, aad, MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("DecryptWithCipherSuite(AES) error = %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption mismatch:\ngot  %q\nwant %q", decrypted, plaintext)
	}
}

// TestEncryptWithCipherSuite_ChaCha20 tests ChaCha20 via EncryptWithCipherSuite.
func TestEncryptWithCipherSuite_ChaCha20(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	plaintext := []byte("Test ChaCha20 encryption")
	aad := []byte("aad")

	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating key: %v", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generating nonce: %v", err)
	}

	ciphertext, err := EncryptWithCipherSuite(key, nonce, plaintext, aad, MLS256DHKEMX25519ChaCha20)
	if err != nil {
		t.Fatalf("EncryptWithCipherSuite(ChaCha20) error = %v", err)
	}

	decrypted, err := DecryptWithCipherSuite(key, nonce, ciphertext, aad, MLS256DHKEMX25519ChaCha20)
	if err != nil {
		t.Fatalf("DecryptWithCipherSuite(ChaCha20) error = %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption mismatch:\ngot  %q\nwant %q", decrypted, plaintext)
	}
}

// TestEncryptWithCipherSuite_Unsupported tests unsupported cipher suite.
func TestEncryptWithCipherSuite_Unsupported(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	plaintext := []byte("test")

	var unsupported CipherSuite = 0xFFFF
	_, err := EncryptWithCipherSuite(key, nonce, plaintext, nil, unsupported)
	if err == nil {
		t.Error("EncryptWithCipherSuite() should fail with unsupported cipher suite")
	}
}

// TestDecryptWithCipherSuite_Unsupported tests unsupported cipher suite for decryption.
func TestDecryptWithCipherSuite_Unsupported(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	ciphertext := []byte("test")

	var unsupported CipherSuite = 0xFFFF
	_, err := DecryptWithCipherSuite(key, nonce, ciphertext, nil, unsupported)
	if err == nil {
		t.Error("DecryptWithCipherSuite() should fail with unsupported cipher suite")
	}
}

// ============================================================================
// Benchmarks
// ============================================================================

// BenchmarkAESEncrypt measures AES-128-GCM encryption performance.
func BenchmarkAESEncrypt(b *testing.B) {
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	plaintext := make([]byte, 1024)
	aad := []byte("aad")

	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}
	if _, err := rand.Read(nonce); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AESEncrypt(key, nonce, plaintext, aad)
	}
}

// BenchmarkAESDecrypt measures AES-128-GCM decryption performance.
func BenchmarkAESDecrypt(b *testing.B) {
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	plaintext := make([]byte, 1024)
	aad := []byte("aad")

	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}
	if _, err := rand.Read(nonce); err != nil {
		b.Fatal(err)
	}

	ciphertext, _ := AESEncrypt(key, nonce, plaintext, aad)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AESDecrypt(key, nonce, ciphertext, aad)
	}
}

// BenchmarkChaCha20Poly1305Encrypt measures ChaCha20-Poly1305 encryption performance.
func BenchmarkChaCha20Poly1305Encrypt(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	plaintext := make([]byte, 1024)
	aad := []byte("aad")

	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}
	if _, err := rand.Read(nonce); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ChaCha20Poly1305Encrypt(key, nonce, plaintext, aad)
	}
}

// BenchmarkChaCha20Poly1305Decrypt measures ChaCha20-Poly1305 decryption performance.
func BenchmarkChaCha20Poly1305Decrypt(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	plaintext := make([]byte, 1024)
	aad := []byte("aad")

	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}
	if _, err := rand.Read(nonce); err != nil {
		b.Fatal(err)
	}

	ciphertext, _ := ChaCha20Poly1305Encrypt(key, nonce, plaintext, aad)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ChaCha20Poly1305Decrypt(key, nonce, ciphertext, aad)
	}
}
