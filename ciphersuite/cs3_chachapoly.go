// Package ciphersuite - Cipher Suite 3 (MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519)
//
// Native implementation using Go 1.26 crypto/ecdh and crypto/hpke.
package ciphersuite

import "golang.org/x/crypto/chacha20poly1305"

// ChaCha20Poly1305Encrypt encrypts using ChaCha20-Poly1305 directly.
//
// Uses golang.org/x/crypto/chacha20poly1305 (Go standard library).
func ChaCha20Poly1305Encrypt(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// ChaCha20Poly1305Decrypt decrypts using ChaCha20-Poly1305 directly.
func ChaCha20Poly1305Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}
