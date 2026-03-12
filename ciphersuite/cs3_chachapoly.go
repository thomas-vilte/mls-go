// Package ciphersuite - Cipher Suite 3 (MLS_256_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519)
//
// Native implementation using Go 1.26 crypto/ecdh and crypto/hpke.
package ciphersuite

import (
	"crypto/rand"

	"golang.org/x/crypto/chacha20poly1305"
)

// GenerateX25519KeyPairCS3 generates an X25519 key pair for CS3.
// This is a wrapper of GenerateX25519KeyPair for CS1.
func GenerateX25519KeyPairCS3() (publicKey, privateKey []byte, err error) {
	return GenerateX25519KeyPair()
}

// DeriveKeyPairX25519CS3 derives an X25519 key pair from IKM for CS3.
// This is a wrapper of DeriveKeyPairX25519 for CS1.
func DeriveKeyPairX25519CS3(ikm []byte) ([]byte, []byte, error) {
	return DeriveKeyPairX25519(ikm)
}

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

// GenerateChaCha20Key generates a 32-byte key for ChaCha20-Poly1305.
func GenerateChaCha20Key() ([]byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateChaCha20Nonce generates a 12-byte nonce for ChaCha20-Poly1305.
func GenerateChaCha20Nonce() ([]byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	return nonce, nil
}
