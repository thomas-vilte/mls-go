package ciphersuite

import (
	"bytes"
	"testing"
)

// FuzzAEAD fuzzes the AEAD encryption/decryption roundtrip.
// Run: go test -fuzz=FuzzAEAD -fuzztime=1m
func FuzzAEAD(f *testing.F) {
	// Seed corpus with valid cases
	f.Add([]byte("0123456789abcdef"), []byte("0123456789ab"), []byte("plaintext"))
	f.Add([]byte("0123456789abcdef"), []byte("0123456789ab"), []byte(""))
	f.Add([]byte("0123456789abcdef"), []byte("0123456789ab"), []byte("large plaintext with more data to test"))

	f.Fuzz(func(t *testing.T, key, nonce, plaintext []byte) {
		// Validate lengths
		if len(key) != 16 {
			return // Only test AES-128
		}
		if len(nonce) != 12 {
			return // Only test 12-byte nonces
		}

		// Encrypt
		ciphertext, err := AESEncrypt(key, nonce, plaintext, nil)
		if err != nil {
			return // Encryption errors are OK, just return
		}

		// Decrypt
		decrypted, err := AESDecrypt(key, nonce, ciphertext, nil)
		if err != nil {
			t.Fatalf("AESDecrypt failed: %v", err)
		}

		// Verify roundtrip
		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("Decryption mismatch:\ngot  %v\nwant %v", decrypted, plaintext)
		}
	})
}

// FuzzHKDF fuzzes HKDF Extract-Expand roundtrip.
// Run: go test -fuzz=FuzzHKDF -fuzztime=1m
func FuzzHKDF(f *testing.F) {
	// Seed corpus
	f.Add([]byte("salt"), []byte("ikm"), []byte("info"), 32)
	f.Add([]byte(""), []byte(""), []byte(""), 16)
	f.Add([]byte("long salt value"), []byte("long ikm value"), []byte("context"), 64)

	f.Fuzz(func(t *testing.T, salt, ikm, info []byte, length int) {
		// Limit length to avoid slow tests
		if length <= 0 || length > 1024 {
			return
		}

		hkdf := NewHKDF()

		// Extract
		prk := hkdf.Extract(salt, ikm)
		if len(prk) != 32 {
			t.Errorf("HKDF Extract returned wrong length: got %d, want 32", len(prk))
		}

		// Expand
		okm, err := hkdf.Expand(prk, info, length)
		if err != nil {
			return // Expand errors are OK for invalid inputs
		}

		// Verify length
		if len(okm) != length {
			t.Errorf("HKDF Expand returned wrong length: got %d, want %d", len(okm), length)
		}

		// Verify determinism
		okm2, err := hkdf.Expand(prk, info, length)
		if err != nil {
			t.Fatalf("HKDF Expand failed on second call: %v", err)
		}
		if !bytes.Equal(okm, okm2) {
			t.Errorf("HKDF Expand is not deterministic")
		}
	})
}

// FuzzSecret fuzzes Secret operations.
// Run: go test -fuzz=FuzzSecret -fuzztime=1m
func FuzzSecret(f *testing.F) {
	// Seed corpus
	f.Add([]byte("secret value"))
	f.Add([]byte(""))
	f.Add([]byte("long secret value for testing"))

	f.Fuzz(func(t *testing.T, value []byte) {
		// Create secret
		secret := NewSecret(value)

		// Verify AsSlice
		slice := secret.AsSlice()
		if !bytes.Equal(slice, value) {
			t.Errorf("Secret.AsSlice() mismatch")
		}

		// Verify Len
		if secret.Len() != len(value) {
			t.Errorf("Secret.Len() mismatch: got %d, want %d", secret.Len(), len(value))
		}

		// Verify Clone
		clone := secret.Clone()
		if !clone.Equal(secret) {
			t.Errorf("Secret.Clone() is not equal to original")
		}

		// Verify Equal
		if !secret.Equal(NewSecret(value)) {
			t.Errorf("Secret.Equal() should return true for same value")
		}

		// Verify not equal to different value
		if secret.Equal(NewSecret([]byte("different"))) {
			t.Errorf("Secret.Equal() should return false for different value")
		}
	})
}

// TestAEAD_Roundtrip verifies AEAD encryption/decryption.
func TestAEAD_Roundtrip(t *testing.T) {
	key := []byte("0123456789abcdef") // 16 bytes = AES-128
	nonce := []byte("0123456789ab")   // 12 bytes
	plaintext := []byte("Hello, World!")
	aad := []byte("additional data")

	// Encrypt
	ciphertext, err := AESEncrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("AESEncrypt() error = %v", err)
	}

	// Ciphertext must be longer than plaintext because it includes the auth tag.
	if len(ciphertext) <= len(plaintext) {
		t.Errorf("Ciphertext should be longer than plaintext")
	}

	// Decrypt
	decrypted, err := AESDecrypt(key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("AESDecrypt() error = %v", err)
	}

	// Verify
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption mismatch:\ngot  %s\nwant %s", decrypted, plaintext)
	}
}

// TestAEAD_WrongKey verifies that decryption fails with the wrong key.
func TestAEAD_WrongKey(t *testing.T) {
	key := []byte("0123456789abcdef")
	wrongKey := []byte("wrong key value!")
	nonce := []byte("0123456789ab")
	plaintext := []byte("Hello, World!")

	// Encrypt
	ciphertext, err := AESEncrypt(key, nonce, plaintext, nil)
	if err != nil {
		t.Fatalf("AESEncrypt() error = %v", err)
	}

	// Decryption with the wrong key must fail.
	_, err = AESDecrypt(wrongKey, nonce, ciphertext, nil)
	if err == nil {
		t.Error("AESDecrypt() should fail with wrong key")
	}
}

// TestAEAD_WrongNonce verifies that decryption fails with the wrong nonce.
func TestAEAD_WrongNonce(t *testing.T) {
	key := []byte("0123456789abcdef")
	nonce := []byte("0123456789ab")
	wrongNonce := []byte("wrong nonce!!")
	plaintext := []byte("Hello, World!")

	// Encrypt
	ciphertext, err := AESEncrypt(key, nonce, plaintext, nil)
	if err != nil {
		t.Fatalf("AESEncrypt() error = %v", err)
	}

	// Decryption with the wrong nonce must fail.
	_, err = AESDecrypt(key, wrongNonce, ciphertext, nil)
	if err == nil {
		t.Error("AESDecrypt() should fail with wrong nonce")
	}
}

// TestAEAD_TamperedData verifies tamper detection.
func TestAEAD_TamperedData(t *testing.T) {
	key := []byte("0123456789abcdef")
	nonce := []byte("0123456789ab")
	plaintext := []byte("Hello, World!")

	// Encrypt
	ciphertext, err := AESEncrypt(key, nonce, plaintext, nil)
	if err != nil {
		t.Fatalf("AESEncrypt() error = %v", err)
	}

	// Tamper the ciphertext
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[0] ^= 0xFF // Modify first byte

	// Decryption of tampered data must fail.
	_, err = AESDecrypt(key, nonce, tampered, nil)
	if err == nil {
		t.Error("AESDecrypt() should fail with tampered data")
	}
}
