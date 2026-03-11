// Package ciphersuite provides AEAD encryption/decryption functions.
package ciphersuite

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// AESEncrypt encrypts plaintext using AES-128-GCM.
func AESEncrypt(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("key must be 16 bytes for AES-128, got %d", len(key))
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("nonce must be 12 bytes for AES-GCM, got %d", len(nonce))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	// Seal appends the ciphertext to the destination
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nil
}

// AESDecrypt decrypts ciphertext using AES-128-GCM.
func AESDecrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("key must be 16 bytes for AES-128, got %d", len(key))
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("nonce must be 12 bytes for AES-GCM, got %d", len(nonce))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	// Open decrypts the ciphertext in place
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return plaintext, nil
}

// EncryptWithCipherSuite encrypts using the appropriate AEAD for the cipher suite.
func EncryptWithCipherSuite(key, nonce, plaintext, aad []byte, cs CipherSuite) ([]byte, error) {
	switch cs.AeadAlgorithm() {
	case AES128GCM:
		return AESEncrypt(key, nonce, plaintext, aad)
	case ChaCha20Poly1305:
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, fmt.Errorf("creating ChaCha20-Poly1305: %w", err)
		}
		return aead.Seal(nil, nonce, plaintext, aad), nil
	default:
		return nil, fmt.Errorf("unsupported AEAD algorithm for cipher suite %d", cs)
	}
}

// DecryptWithCipherSuite decrypts using the appropriate AEAD for the cipher suite.
func DecryptWithCipherSuite(key, nonce, ciphertext, aad []byte, cs CipherSuite) ([]byte, error) {
	switch cs.AeadAlgorithm() {
	case AES128GCM:
		return AESDecrypt(key, nonce, ciphertext, aad)
	case ChaCha20Poly1305:
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, fmt.Errorf("creating ChaCha20-Poly1305: %w", err)
		}
		return aead.Open(nil, nonce, ciphertext, aad)
	default:
		return nil, fmt.Errorf("unsupported AEAD algorithm for cipher suite %d", cs)
	}
}
