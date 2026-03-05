// Package ciphersuite provides AEAD encryption/decryption functions.
package ciphersuite

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
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
