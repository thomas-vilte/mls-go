// Package ciphersuite implements HPKE operations for MLS per RFC 9420 §5.1.3 and RFC 9180.
//
// This package provides native HPKE (Hybrid Public Key Encryption) operations
// using Go 1.26's crypto/hpke package. It implements RFC 9180 (HPKE) and
// RFC 9420 (MLS) specifications for encrypted key encapsulation.
//
// # HPKE in MLS
//
// HPKE is used throughout MLS for:
//   - Welcome messages: Encrypt group secrets to new members (§11.2.2)
//   - UpdatePath: Encrypt path secrets in commits (§12.4.3.1)
//   - External senders: Encrypt to external sender keys (§8.3)
//
// # Domain Separation (RFC 9420 §5.1.3)
//
// All HPKE operations use the "MLS 1.0 " prefix to prevent cross-protocol attacks:
//
//	info = Serialize(VL("MLS 1.0 " + label) || VL(context))
//
//
// # Supported Cipher Suites
//
//   - MLS_128_DHKEMP256_AES128GCM_SHA256_P256 (0x0002) - Mandatory for MLS 1.0
//   - MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001)
//   - MLS_256_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 (0x0003)
//
// # References
//
//   - RFC 9180: Hybrid Public Key Encryption (HPKE)
//   - RFC 9420 §5.1.3: Public Key Encryption
//   - RFC 9420 §11.2.2: Welcome Messages
package ciphersuite

import (
	"crypto/ecdh"
	"crypto/hpke"
	"fmt"

	"github.com/thomas-vilte/mls-go/internal/tls"
)

// EncryptWithLabel encrypts using HPKE with label as defined in RFC 9420 §5.1.3.
//
// Implements RFC 9180 §4.1 (HPKE) with MLS-specific labeling:
//
//	HPKE.Encrypt(pkR, info, aad, plaintext) -> (enc, ciphertext)
//
// Where:
//   - info = Serialize(VL("MLS 1.0 " + label) || context)
//   - pkR is the receiver's public key
//   - enc is the encapsulated key (KEM output)
//
// The label prefix "MLS 1.0 " ensures domain separation as required by
// RFC 9420 §5.1.3 to prevent cross-protocol attacks.
//
// Uses Go 1.26 native crypto/hpke for all cipher suites.
func EncryptWithLabel(
	publicKey []byte,
	label string,
	context []byte,
	plaintext []byte,
	cs CipherSuite,
) (*HpkeCiphertext, error) {
	curve := cs.Curve()
	if curve == nil {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedSuite, cs)
	}
	aead, err := hpkeAEAD(cs)
	if err != nil {
		return nil, err
	}
	return encryptWithLabelNative(publicKey, label, context, plaintext, curve, hpkeKDF(cs), aead)
}

// encryptWithLabelNative is the native implementation using crypto/hpke.
//
// RFC 9180 §4.1 (HPKE Base Mode), labeled per RFC 9420 §5.1.3.
//
// HPKE Encryption Flow:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                    HPKE Encryption                               │
//	├─────────────────────────────────────────────────────────────────┤
//	│                                                                 │
//	│  Sender                          Receiver                       │
//	│    │                              │                              │
//	│    │  pkR (public key)            │                              │
//	│    │◄─────────────────────────────│                              │
//	│    │                              │                              │
//	│    │  [enc, shared_secret]        │                              │
//	│    │  = Encapsulate(pkR)          │                              │
//	│    │                              │                              │
//	│    │  info = "MLS 1.0 " + label   │                              │
//	│    │  Context = Hash(context)     │                              │
//	│    │                              │                              │
//	│    │  DeriveKeyingMaterial(...)   │                              │
//	│    │                              │                              │
//	│    │  ciphertext = AEAD.Seal(...) │                              │
//	│    │──────────────────────────────►│                              │
//	│    │                              │                              │
//	│    │                   shared_secret = Decapsulate(skR, enc)     │
//	│    │                   DeriveKeyingMaterial(...)                 │
//	│    │                   plaintext = AEAD.Open(...)                │
//	│                                                                 │
//	└─────────────────────────────────────────────────────────────────┘
//
// KEM Output Lengths:
//   - X25519: 32 bytes
//   - P-256: 65 bytes (uncompressed point: 0x04 || X || Y)
func encryptWithLabelNative(
	publicKey []byte,
	label string,
	context []byte,
	plaintext []byte,
	curve ecdh.Curve,
	kdf hpke.KDF,
	aead hpke.AEAD,
) (*HpkeCiphertext, error) {
	// Build info = Serialize(VL("MLS 1.0 " + label) || VL(context))
	// Per RFC 9420 §5.1.3, both fields are length-prefixed
	encContext := NewEncryptContext(label, context)
	info := encContext.Marshal()

	// Parse public key
	pubKey, err := curve.NewPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	pk, err := hpke.NewDHKEMPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("creating HPKE public key: %w", err)
	}

	// Encrypt using HPKE Seal (RFC 9180 §4.1)
	// Seal returns enc || ciphertext concatenated
	encapsulatedAndCt, err := hpke.Seal(pk, kdf, aead, info, plaintext)
	if err != nil {
		return nil, fmt.Errorf("HPKE seal: %w", err)
	}

	// Separate KEM output from ciphertext
	// KEM output length depends on the curve:
	// - X25519: 32 bytes
	// - P-256: 65 bytes (uncompressed point: 0x04 || X || Y)
	kemOutputLen := len(publicKey) // Same length as the public key
	if len(encapsulatedAndCt) < kemOutputLen {
		return nil, fmt.Errorf("HPKE output too short: %d bytes", len(encapsulatedAndCt))
	}

	return &HpkeCiphertext{
		KEMOutput:  encapsulatedAndCt[:kemOutputLen],
		Ciphertext: encapsulatedAndCt[kemOutputLen:],
	}, nil
}

// DecryptWithLabel decrypts using HPKE with label as defined in RFC 9420 §5.1.3.
//
// Implements RFC 9180 §4.1 (HPKE) with MLS-specific labeling:
//
//	HPKE.Decrypt(skR, info, aad, enc, ciphertext) -> plaintext
//
// Where:
//   - info = Serialize(VL("MLS 1.0 " + label) || context)
//   - skR is the receiver's private key
//   - enc is the encapsulated key (KEM output)
//
// The label prefix "MLS 1.0 " ensures domain separation as required by
// RFC 9420 §5.1.3 to prevent cross-protocol attacks.
func DecryptWithLabel(
	privateKey []byte,
	label string,
	context []byte,
	ciphertext *HpkeCiphertext,
	cs CipherSuite,
) ([]byte, error) {
	curve := cs.Curve()
	if curve == nil {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedSuite, cs)
	}
	aead, err := hpkeAEAD(cs)
	if err != nil {
		return nil, err
	}
	return decryptWithLabelNative(privateKey, label, context, ciphertext, curve, hpkeKDF(cs), aead)
}

// decryptWithLabelNative is the native implementation using crypto/hpke.
//
// This function implements RFC 9180 §4.1 (HPKE Base Mode) decryption with
// MLS-specific labeling per RFC 9420 §5.1.3.
//
// HPKE Decryption Flow:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                    HPKE Decryption                               │
//	├─────────────────────────────────────────────────────────────────┤
//	│                                                                 │
//	│  Receive: enc || ciphertext                                     │
//	│    │                                                            │
//	│    │  skR (private key)                                         │
//	│    │                                                            │
//	│    │  shared_secret = Decapsulate(skR, enc)                     │
//	│    │                                                            │
//	│    │  info = "MLS 1.0 " + label                                 │
//	│    │  Context = Hash(context)                                   │
//	│    │                                                            │
//	│    │  DeriveKeyingMaterial(...)                                 │
//	│    │                                                            │
//	│    │  plaintext = AEAD.Open(...)                                │
//	│                                                                 │
//	└─────────────────────────────────────────────────────────────────┘
//
// Returns:
//   - Decrypted plaintext
//   - Error if decapsulation fails, AEAD open fails, or key parsing fails
func decryptWithLabelNative(
	privateKey []byte,
	label string,
	context []byte,
	ciphertext *HpkeCiphertext,
	curve ecdh.Curve,
	kdf hpke.KDF,
	aead hpke.AEAD,
) ([]byte, error) {
	// Build info = Serialize(VL("MLS 1.0 " + label) || VL(context))
	// Per RFC 9420 §5.1.3, both fields are length-prefixed
	encContext := NewEncryptContext(label, context)
	info := encContext.Marshal()

	// Parse private key
	privKey, err := curve.NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	sk, err := hpke.NewDHKEMPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("creating HPKE private key: %w", err)
	}

	// Concatenate KEM output and ciphertext for HPKE Open
	encapsulatedAndCt := make([]byte, 0, len(ciphertext.KEMOutput)+len(ciphertext.Ciphertext))
	encapsulatedAndCt = append(encapsulatedAndCt, ciphertext.KEMOutput...)
	encapsulatedAndCt = append(encapsulatedAndCt, ciphertext.Ciphertext...)

	// Decrypt using HPKE Open (RFC 9180 §4.1)
	plaintext, err := hpke.Open(sk, kdf, aead, info, encapsulatedAndCt)
	if err != nil {
		return nil, fmt.Errorf("HPKE open: %w", err)
	}

	return plaintext, nil
}

// DeriveKeyPair derives an HPKE key pair from IKM as defined in RFC 9180 §4.1.
//
// Implements the exact DeriveKeyPair algorithm from RFC 9180 §4.1:
//  1. pk = KEM.DeriveKeyPair(ikm)
//  2. Returns the derived key pair
//
// The function uses LabeledExtract / LabeledExpand with the KEM-specific
// suite_id as required by RFC 9180 §4.1 for domain separation.
//
// See also: RFC 9420 §5.1.3 for HPKE usage in MLS
func DeriveKeyPair(cs CipherSuite, ikm []byte) (*ecdh.PrivateKey, error) {
	curve := cs.Curve()
	if curve == nil {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedSuite, cs)
	}

	kem := hpke.DHKEM(curve)
	privKey, err := kem.DeriveKeyPair(ikm)
	if err != nil {
		return nil, fmt.Errorf("DeriveKeyPair: %w", err)
	}

	// hpke.PrivateKey → *ecdh.PrivateKey via bytes round-trip.
	privBytes, err := privKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("DeriveKeyPair marshal: %w", err)
	}
	return curve.NewPrivateKey(privBytes)
}

// hpkeAEAD returns the crypto/hpke AEAD algorithm for the cipher suite (RFC 9420 §5.1.3).
func hpkeAEAD(cs CipherSuite) (hpke.AEAD, error) {
	switch cs.AeadAlgorithm() {
	case AES128GCM:
		return hpke.AES128GCM(), nil
	case AES256GCM:
		return hpke.AES256GCM(), nil
	case ChaCha20Poly1305:
		return hpke.ChaCha20Poly1305(), nil
	default:
		return nil, fmt.Errorf("%w: no HPKE AEAD for cipher suite %d", ErrUnsupportedSuite, cs)
	}
}

// hpkeKDF returns the crypto/hpke KDF for the cipher suite (RFC 9180 §4.1).
func hpkeKDF(cs CipherSuite) hpke.KDF {
	switch cs {
	case MLS256DHKEMP521AES256GCM:
		return hpke.HKDFSHA512()
	default:
		return hpke.HKDFSHA256()
	}
}

// EncryptContext represents the context for HPKE encryption (RFC 9420 §5.1.3).
//
//	struct {
//	    opaque label<V> = "MLS 1.0 " + Label;
//	    opaque context<V> = Context;
//	} EncryptContext;
type EncryptContext struct {
	Label   []byte
	Context []byte
}

// NewEncryptContext creates an encryption context with MLS prefix.
func NewEncryptContext(label string, context []byte) *EncryptContext {
	return &EncryptContext{
		Label:   []byte(LabelPrefix + label),
		Context: context,
	}
}

// Marshal serializes to TLS format.
func (ec *EncryptContext) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteVLBytes(ec.Label)
	w.WriteVLBytes(ec.Context)
	return w.Bytes()
}
