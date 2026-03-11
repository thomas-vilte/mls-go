// Package ciphersuite - Ed25519 signature implementation for MLS cipher suite 1 (RFC 9420 §5.1.2)
package ciphersuite

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// Ed25519PrivateKey represents an Ed25519 private key.
type Ed25519PrivateKey struct {
	key ed25519.PrivateKey
}

// Ed25519PublicKey represents an Ed25519 public key.
type Ed25519PublicKey struct {
	key ed25519.PublicKey
}

// GenerateEd25519KeyPair generates a new Ed25519 key pair.
func GenerateEd25519KeyPair() (*Ed25519PrivateKey, *Ed25519PublicKey, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating Ed25519 key: %w", err)
	}

	return &Ed25519PrivateKey{key: privKey}, &Ed25519PublicKey{key: pubKey}, nil
}

// NewEd25519PrivateKey creates an Ed25519 private key from bytes (32 or 64 bytes).
func NewEd25519PrivateKey(key interface{}) (*Ed25519PrivateKey, error) {
	switch k := key.(type) {
	case []byte:
		if len(k) == 32 {
			// 32-byte seed, derive full key
			fullKey := ed25519.NewKeyFromSeed(k)
			return &Ed25519PrivateKey{key: fullKey}, nil
		}
		if len(k) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid Ed25519 private key length: %d (expected 32 or 64)", len(k))
		}
		return &Ed25519PrivateKey{key: ed25519.PrivateKey(k)}, nil

	case ed25519.PrivateKey:
		return &Ed25519PrivateKey{key: k}, nil

	default:
		return nil, fmt.Errorf("invalid key type: %T", key)
	}
}

// NewEd25519PublicKey creates an Ed25519 public key from bytes.
func NewEd25519PublicKey(bytes []byte) (*Ed25519PublicKey, error) {
	if len(bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length: %d", len(bytes))
	}
	return &Ed25519PublicKey{key: ed25519.PublicKey(bytes)}, nil
}

// Sign signs data using Ed25519.
func (k *Ed25519PrivateKey) Sign(data []byte) (*Signature, error) {
	sig := ed25519.Sign(k.key, data)
	return NewSignature(sig), nil
}

// SignWithLabel signs data with MLS label prefix (RFC 9420 §5.1.2).
func (k *Ed25519PrivateKey) SignWithLabel(label string, content []byte) (*Signature, error) {
	signContent := NewSignContent(label, content)
	return k.Sign(signContent.Marshal())
}

// Verify verifies an Ed25519 signature.
func (k *Ed25519PublicKey) Verify(data []byte, sig *Signature) error {
	if !ed25519.Verify(k.key, data, sig.AsSlice()) {
		return ErrInvalidSignature
	}
	return nil
}

// VerifyWithLabel verifies an Ed25519 signature with MLS label prefix.
func (k *Ed25519PublicKey) VerifyWithLabel(label string, content []byte, sig *Signature) error {
	signContent := NewSignContent(label, content)
	return k.Verify(signContent.Marshal(), sig)
}

// Bytes returns the private key bytes (64 bytes).
func (k *Ed25519PrivateKey) Bytes() []byte {
	return []byte(k.key)
}

// PublicBytes returns the public key bytes (32 bytes).
func (k *Ed25519PrivateKey) PublicBytes() []byte {
	return []byte(k.key.Public().(ed25519.PublicKey))
}

// Bytes returns the public key bytes (32 bytes).
func (k *Ed25519PublicKey) Bytes() []byte {
	return []byte(k.key)
}
