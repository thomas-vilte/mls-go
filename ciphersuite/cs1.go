// Copyright 2024 MLS-Go Authors. All rights reserved.
// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE file.

// Package ciphersuite implements Cipher Suite 1: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.
//
// Cipher Suite 1 combines:
//   - KEM: DHKEM_X25519_HKDF_SHA256 (RFC 9180 §4.1)
//   - AEAD: AES-128-GCM (RFC 9420 §5.1)
//   - Hash: SHA-256 (RFC 9420 §5.2)
//   - Sign: Ed25519 (RFC 8410)
//
// This cipher suite is recommended for most deployments per RFC 9420 §17.1.
package ciphersuite

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// ============================================================================
// Ed25519 Signatures for CS1
// ============================================================================

// Ed25519PrivateKey represents an Ed25519 private key for CS1.
//
// Ed25519 is used for signatures in CS1 as specified in RFC 9420 §5.1.2.
// The private key is 64 bytes (32-byte seed + 32-byte public key).
type Ed25519PrivateKey struct {
	key ed25519.PrivateKey
}

// Ed25519PublicKey represents an Ed25519 public key for CS1.
//
// The public key is 32 bytes as specified in RFC 8410 §3.
type Ed25519PublicKey struct {
	key ed25519.PublicKey
}

// GenerateEd25519KeyPair generates a new Ed25519 key pair for CS1.
//
// Returns:
//   - privateKey: 64-byte Ed25519 private key
//   - publicKey: 32-byte Ed25519 public key
//   - error: ErrInsufficientRandom if randomness generation fails
func GenerateEd25519KeyPair() (*Ed25519PrivateKey, *Ed25519PublicKey, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating Ed25519 key: %w", err)
	}

	return &Ed25519PrivateKey{key: privKey}, &Ed25519PublicKey{key: pubKey}, nil
}

// NewEd25519PrivateKey creates an Ed25519 private key from bytes.
//
// Accepts:
//   - 32 bytes: seed, derives full 64-byte key
//   - 64 bytes: full private key (seed + public key)
//
// Per RFC 8410 §3, Ed25519 private keys are 64 bytes.
func NewEd25519PrivateKey(key any) (*Ed25519PrivateKey, error) {
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
		return &Ed25519PrivateKey{key: k}, nil

	case ed25519.PrivateKey:
		return &Ed25519PrivateKey{key: k}, nil

	default:
		return nil, fmt.Errorf("invalid key type: %T", key)
	}
}

// NewEd25519PublicKey creates an Ed25519 public key from bytes.
//
// Expects 32-byte public key as specified in RFC 8410 §3.
func NewEd25519PublicKey(bytes []byte) (*Ed25519PublicKey, error) {
	if len(bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length: %d", len(bytes))
	}
	return &Ed25519PublicKey{key: bytes}, nil
}

// Sign signs data using Ed25519 as specified in RFC 8410.
//
// Returns a 64-byte signature.
func (k *Ed25519PrivateKey) Sign(data []byte) (*Signature, error) {
	sig := ed25519.Sign(k.key, data)
	return NewSignature(sig), nil
}

// SignWithLabel signs data with MLS label prefix per RFC 9420 §5.1.2.
//
// The label prefix "MLS 1.0 " prevents signature confusion attacks.
func (k *Ed25519PrivateKey) SignWithLabel(label string, content []byte) (*Signature, error) {
	signContent := NewSignContent(label, content)
	return k.Sign(signContent.Marshal())
}

// Verify verifies an Ed25519 signature per RFC 8410.
//
// Returns ErrInvalidSignature if verification fails.
func (k *Ed25519PublicKey) Verify(data []byte, sig *Signature) error {
	if !ed25519.Verify(k.key, data, sig.AsSlice()) {
		return ErrInvalidSignature
	}
	return nil
}

// VerifyWithLabel verifies an Ed25519 signature with MLS label prefix.
//
// Per RFC 9420 §5.1.2, the label must match the one used for signing.
func (k *Ed25519PublicKey) VerifyWithLabel(label string, content []byte, sig *Signature) error {
	signContent := NewSignContent(label, content)
	return k.Verify(signContent.Marshal(), sig)
}

// Bytes returns the private key bytes (64 bytes).
func (k *Ed25519PrivateKey) Bytes() []byte {
	return k.key
}

// PublicBytes returns the public key bytes (32 bytes).
func (k *Ed25519PrivateKey) PublicBytes() []byte {
	return k.key.Public().(ed25519.PublicKey)
}

// Bytes returns the public key bytes (32 bytes).
func (k *Ed25519PublicKey) Bytes() []byte {
	return k.key
}

// ============================================================================
// X25519 DHKEM for CS1
// ============================================================================

// GenerateX25519KeyPair generates an X25519 key pair for CS1.
//
// Uses Go 1.26+ native crypto/ecdh for X25519 operations.
// X25519 is used for key encapsulation in CS1 per RFC 9180 §4.1.
//
// Returns:
//   - publicKey: 32-byte X25519 public key
//   - privateKey: 32-byte X25519 private key
//   - error: ErrInsufficientRandom if randomness generation fails
func GenerateX25519KeyPair() (publicKey, privateKey []byte, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pub := priv.PublicKey()
	return pub.Bytes(), priv.Bytes(), nil
}

// DeriveKeyPairX25519 derives an X25519 key pair from IKM using HKDF.
//
// Implements RFC 9180 §4.1 DeriveKeyPair:
//  1. PRK = HKDF.Extract(salt="", ikm)
//  2. seed = HKDF.Expand(PRK, "DKEM X25519", 32)
//  3. sk = seed as X25519 private key
//  4. pk = sk.PublicKey()
//
// This is used for deterministic key derivation in HPKE.
func DeriveKeyPairX25519(ikm []byte) (pubKey, privKey []byte, err error) {
	hkdf := NewHKDF()
	prk := hkdf.Extract(nil, ikm)

	// Expand to get 32-byte seed for X25519
	seed, err := hkdf.Expand(prk, []byte("DKEM X25519"), 32)
	if err != nil {
		return nil, nil, fmt.Errorf("HKDF expand: %w", err)
	}

	priv, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return nil, nil, err
	}

	pub := priv.PublicKey()
	return pub.Bytes(), priv.Bytes(), nil
}

// EncapToBytes performs DHKEM encapsulation per RFC 9180 §4.1.
//
// Generates an ephemeral key pair and computes the shared secret:
//   - enc = ephemeral public key (KEM output)
//   - shared_secret = ECDH(ephemeral private key, recipient public key)
//
// Returns:
//   - kem_output: Encapsulated key (32 bytes for X25519, 65 bytes for P256)
//   - shared_secret: Shared secret for key derivation
//   - error: if encapsulation fails
//
// Supports CS1 (X25519), CS2 (P256), and CS3 (X25519).
func EncapToBytes(recipientPubKeyBytes []byte, cs CipherSuite) (kemOutput, sharedSecret []byte, err error) {
	switch cs {
	case MLS128DHKEMX25519, MLS128DHKEMX25519ChaCha20:
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}

		pub, err := ecdh.X25519().NewPublicKey(recipientPubKeyBytes)
		if err != nil {
			return nil, nil, err
		}

		sharedSecret, err := priv.ECDH(pub)
		if err != nil {
			return nil, nil, err
		}

		return priv.PublicKey().Bytes(), sharedSecret, nil

	case MLS128DHKEMP256:
		priv, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}

		pub, err := ecdh.P256().NewPublicKey(recipientPubKeyBytes)
		if err != nil {
			return nil, nil, err
		}

		sharedSecret, err := priv.ECDH(pub)
		if err != nil {
			return nil, nil, err
		}

		return priv.PublicKey().Bytes(), sharedSecret, nil

	default:
		return nil, nil, fmt.Errorf("unsupported cipher suite: %d", cs)
	}
}

// DecapToBytes performs DHKEM decapsulation per RFC 9180 §4.1.
//
// Computes the shared secret:
//   - shared_secret = ECDH(recipient private key, encapsulated key)
//
// Returns:
//   - shared_secret: Shared secret for key derivation
//   - error: if decapsulation fails
//
// Supports CS1 (X25519), CS2 (P256), and CS3 (X25519).
func DecapToBytes(enc, privKeyBytes []byte, cs CipherSuite) ([]byte, error) {
	switch cs {
	case MLS128DHKEMX25519, MLS128DHKEMX25519ChaCha20:
		priv, err := ecdh.X25519().NewPrivateKey(privKeyBytes)
		if err != nil {
			return nil, err
		}

		pub, err := ecdh.X25519().NewPublicKey(enc)
		if err != nil {
			return nil, err
		}

		sharedSecret, err := priv.ECDH(pub)
		return sharedSecret, err

	case MLS128DHKEMP256:
		priv, err := ecdh.P256().NewPrivateKey(privKeyBytes)
		if err != nil {
			return nil, err
		}

		pub, err := ecdh.P256().NewPublicKey(enc)
		if err != nil {
			return nil, err
		}

		sharedSecret, err := priv.ECDH(pub)
		return sharedSecret, err

	default:
		return nil, fmt.Errorf("unsupported cipher suite: %d", cs)
	}
}
