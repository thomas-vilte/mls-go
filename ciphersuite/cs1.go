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
	"crypto/hpke"
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

// EncapToBytes performs HPKE encapsulation per RFC 9420 §5.1.3 and RFC 9180 §4.1.
//
// Uses SetupBaseS with the cipher suite's KEM/KDF/AEAD and returns the KEM output
// (ephemeral public key) and the exported secret via context.Export(string(info), Nh).
//
// Per RFC 9420 §12.4.3.2, ExternalInit uses:
//   - info = "MLS 1.0 external init"
//   - exported secret = init_secret_for_new_epoch
//
// Returns:
//   - kem_output: Encapsulated key (32 bytes for X25519, 65 bytes for P256)
//   - exported_secret: Exported secret of length Nh
//   - error: if encapsulation fails
//
// externalInitExportCtx is the HPKE export context for ExternalInit per RFC 9420 §12.4.3.2.
// Both mlspp (Cisco) and OpenMLS use: SetupBaseS(external_pub, info="") + Export("MLS 1.0 external init secret", Nh).
const externalInitExportCtx = "MLS 1.0 external init secret"

// EncapToBytes performs HPKE encapsulation for ExternalInit (RFC 9420 §12.4.3.2, RFC 9180 §4.1).
//
// Uses SetupBaseS with empty info and exports via context.Export("MLS 1.0 external init secret", Nh).
// Returns the KEM output (enc) and the exported init_secret.
func EncapToBytes(recipientPubKeyBytes []byte, cs CipherSuite) (kemOutput, exportedSecret []byte, err error) {
	curve := cs.Curve()
	if curve == nil {
		return nil, nil, fmt.Errorf("unsupported cipher suite: %d", cs)
	}
	aead, err := hpkeAEAD(cs)
	if err != nil {
		return nil, nil, err
	}
	pub, err := curve.NewPublicKey(recipientPubKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing recipient public key: %w", err)
	}
	hpkePub, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("creating HPKE public key: %w", err)
	}
	// RFC 9420 §12.4.3.2: info = "" (empty), export context = "MLS 1.0 external init secret"
	enc, sender, err := hpke.NewSender(hpkePub, hpke.HKDFSHA256(), aead, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("HPKE NewSender: %w", err)
	}
	secret, err := sender.Export(externalInitExportCtx, cs.HashLength())
	if err != nil {
		return nil, nil, fmt.Errorf("HPKE Export: %w", err)
	}
	return enc, secret, nil
}

// DecapToBytes performs HPKE decapsulation for ExternalInit (RFC 9420 §12.4.3.2, RFC 9180 §4.1).
//
// Uses SetupBaseR with empty info and exports via context.Export("MLS 1.0 external init secret", Nh).
func DecapToBytes(enc, privKeyBytes []byte, cs CipherSuite) ([]byte, error) {
	curve := cs.Curve()
	if curve == nil {
		return nil, fmt.Errorf("unsupported cipher suite: %d", cs)
	}
	aead, err := hpkeAEAD(cs)
	if err != nil {
		return nil, err
	}
	priv, err := curve.NewPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	hpkePriv, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("creating HPKE private key: %w", err)
	}
	// RFC 9420 §12.4.3.2: info = "" (empty), export context = "MLS 1.0 external init secret"
	recipient, err := hpke.NewRecipient(enc, hpkePriv, hpke.HKDFSHA256(), aead, nil)
	if err != nil {
		return nil, fmt.Errorf("HPKE NewRecipient: %w", err)
	}
	return recipient.Export(externalInitExportCtx, cs.HashLength())
}
