// Package ciphersuite - Cipher Suite 3 (MLS_256_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519)
//
// Implementación nativa usando crypto/ecdh y crypto/hpke de Go 1.26.
package ciphersuite

import (
	"crypto/rand"

	"golang.org/x/crypto/chacha20poly1305"
)

// GenerateX25519KeyPairCS3 genera un X25519 key pair para CS3.
// Es un wrapper de GenerateX25519KeyPair para CS1.
func GenerateX25519KeyPairCS3() (publicKey, privateKey []byte, err error) {
	return GenerateX25519KeyPair()
}

// DeriveKeyPairX25519CS3 deriva un X25519 key pair desde IKM para CS3.
// Es un wrapper de DeriveKeyPairX25519 para CS1.
func DeriveKeyPairX25519CS3(ikm []byte) ([]byte, []byte, error) {
	return DeriveKeyPairX25519(ikm)
}

// ChaCha20Poly1305Encrypt encripta usando ChaCha20-Poly1305 directamente.
//
// Usa golang.org/x/crypto/chacha20poly1305 (librería estándar de Go).
func ChaCha20Poly1305Encrypt(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// ChaCha20Poly1305Decrypt desencripta usando ChaCha20-Poly1305 directamente.
func ChaCha20Poly1305Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

// GenerateChaCha20Key genera una key de 32 bytes para ChaCha20-Poly1305.
func GenerateChaCha20Key() ([]byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateChaCha20Nonce genera un nonce de 12 bytes para ChaCha20-Poly1305.
func GenerateChaCha20Nonce() ([]byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	return nonce, nil
}
