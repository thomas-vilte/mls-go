// Package ciphersuite implements digital signature operations per RFC 9420 §5.1.2.
package ciphersuite

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/thomas-vilte/mls-go/internal/tls"
)

// Signature represents a digital signature as defined in RFC 9420 §5.1.2.
//
// For ECDSA signatures (P-256), the signature is encoded in ASN.1 DER format
// as specified in RFC 5480 §2.2.3.
//
// For Ed25519 signatures, the signature is a raw 64-byte value as specified
// in RFC 8410 §3.
type Signature struct {
	value []byte
}

// NewSignature creates a signature from bytes.
func NewSignature(value []byte) *Signature {
	return &Signature{value: value}
}

// AsSlice returns the signature bytes.
func (s *Signature) AsSlice() []byte {
	return s.value
}

// SignaturePublicKey represents a public signature key as defined in RFC 9420 §5.1.2.
//
// For ECDSA P-256, the key is encoded as an uncompressed point (0x04 || X || Y, 65 bytes)
// as specified in SEC 1 §2.3.3.
//
// For Ed25519, the key is a raw 32-byte value as specified in RFC 8410 §3.
type SignaturePublicKey struct {
	value []byte
}

// NewSignaturePublicKey creates a public key from bytes.
func NewSignaturePublicKey(value []byte) *SignaturePublicKey {
	return &SignaturePublicKey{value: value}
}

// AsSlice returns the key bytes.
func (k *SignaturePublicKey) AsSlice() []byte {
	return k.value
}

// ToECDSA converts to an ECDSA public key (P-256).
// Expects uncompressed SEC 1 point: 0x04 || X || Y (P256UncompressedKeySize = 65 bytes, RFC 5480 §2.2).
func (k *SignaturePublicKey) ToECDSA() (*ecdsa.PublicKey, error) {
	if len(k.value) != P256UncompressedKeySize || k.value[0] != 0x04 {
		return nil, fmt.Errorf("invalid uncompressed point format: expected %d bytes starting with 0x04, got %d bytes",
			P256UncompressedKeySize, len(k.value))
	}

	// Note: crypto/elliptic is deprecated since Go 1.21, but ecdsa.PublicKey
	// still requires Curve/X/Y fields for ecdsa.Verify compatibility.
	// This usage is maintained for compatibility with the standard library.
	x := new(big.Int).SetBytes(k.value[1:33])
	y := new(big.Int).SetBytes(k.value[33:65])

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

// SignaturePrivateKey represents a private signature key as defined in RFC 9420 §5.1.2.
// It is a union type supporting both ECDSA (P-256) and Ed25519.
//
// For ECDSA P-256, the private key is a scalar used with the P-256 curve.
// For Ed25519, the private key is a 64-byte value (32-byte seed + 32-byte public key).
type SignaturePrivateKey struct {
	scheme     SignatureScheme
	ecdsaKey   *ecdsa.PrivateKey
	ed25519Key ed25519.PrivateKey // non-nil only for Ed25519
}

// NewSignaturePrivateKey creates a wrapper from an existing ecdsa.PrivateKey.
func NewSignaturePrivateKey(priv *ecdsa.PrivateKey) *SignaturePrivateKey {
	return &SignaturePrivateKey{scheme: ECDSA_SECP256R1_SHA256, ecdsaKey: priv}
}

// NewEd25519SignaturePrivateKey creates a wrapper from an Ed25519 private key.
func NewEd25519SignaturePrivateKey(priv ed25519.PrivateKey) *SignaturePrivateKey {
	return &SignaturePrivateKey{scheme: ED25519, ed25519Key: priv}
}

// NewSignaturePrivateKeyP521 creates a wrapper from an existing P-521 ecdsa.PrivateKey.
func NewSignaturePrivateKeyP521(priv *ecdsa.PrivateKey) *SignaturePrivateKey {
	return &SignaturePrivateKey{scheme: ECDSA_SECP521R1_SHA512, ecdsaKey: priv}
}

// GenerateSignaturePrivateKey generates a new P-256 private key.
func GenerateSignaturePrivateKey() (*SignaturePrivateKey, error) {
	// P-256 generation using ecdsa standard library function.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating P-256 key: %w", err)
	}
	return &SignaturePrivateKey{scheme: ECDSA_SECP256R1_SHA256, ecdsaKey: priv}, nil
}

// GenerateSignaturePrivateKeyForCS generates a new private key appropriate for the cipher suite.
//
// Per RFC 9420 §5.1.2:
//   - CS1/CS3: Ed25519
//   - CS2: ECDSA with P-256 and SHA-256 (mandatory)
//   - CS5: ECDSA with P-521 and SHA-512
func GenerateSignaturePrivateKeyForCS(cs CipherSuite) (*SignaturePrivateKey, error) {
	switch cs.SignatureScheme() {
	case ED25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating Ed25519 key: %w", err)
		}
		return &SignaturePrivateKey{scheme: ED25519, ed25519Key: priv}, nil
	case ECDSA_SECP256R1_SHA256:
		return GenerateSignaturePrivateKey()
	case ECDSA_SECP521R1_SHA512:
		priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating P-521 key: %w", err)
		}
		return &SignaturePrivateKey{scheme: ECDSA_SECP521R1_SHA512, ecdsaKey: priv}, nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedSuite, cs)
	}
}

// Scheme returns the signature scheme of this key.
func (k *SignaturePrivateKey) Scheme() SignatureScheme {
	return k.scheme
}

// PublicKey returns the public key bytes as defined in RFC 9420 §5.1.2.
//
// For ECDSA P-256: returns uncompressed point format (0x04 || X || Y, 65 bytes)
// as specified in SEC 1 §2.3.3.
//
// For Ed25519: returns raw 32-byte public key as specified in RFC 8410 §3.
func (k *SignaturePrivateKey) PublicKey() *SignaturePublicKey {
	if k.scheme == ED25519 {
		pub := k.ed25519Key.Public().(ed25519.PublicKey)
		return NewSignaturePublicKey(pub)
	}

	// ECDSA P-256: uncompressed format via crypto/ecdh
	ecdhKey, err := k.ecdsaKey.ECDH()
	if err != nil {
		// Fallback should never happen for a valid P-256 key
		return NewSignaturePublicKey(nil)
	}
	return NewSignaturePublicKey(ecdhKey.PublicKey().Bytes())
}

// Sign signs the given data as defined in RFC 9420 §5.1.2.
//
// For ECDSA: pre-hashes with the scheme's hash function (SHA-256 for P-256),
// then signs the digest in ASN.1 DER format (RFC 5480 §2.2.3).
// For Ed25519: signs the raw message without pre-hashing (RFC 8032 §5.1).
func (k *SignaturePrivateKey) Sign(data []byte) (*Signature, error) {
	if k.scheme == ED25519 {
		sig := ed25519.Sign(k.ed25519Key, data)
		return NewSignature(sig), nil
	}

	// ECDSA: pre-hash with the scheme's hash function (RFC 9420 §5.1.2).
	hf := k.scheme.HashFunction()
	h := hf()
	h.Write(data)
	digest := h.Sum(nil)

	// Use modern ecdsa.SignASN1 (returns ASN.1 DER encoded signature, RFC 5480 §2.2.3).
	sigDER, err := ecdsa.SignASN1(rand.Reader, k.ecdsaKey, digest)
	if err != nil {
		return nil, fmt.Errorf("signing with ECDSA: %w", err)
	}

	return NewSignature(sigDER), nil
}

// MLSSignaturePublicKey is an enriched public key with signature scheme.
type MLSSignaturePublicKey struct {
	SignatureScheme SignatureScheme
	Value           []byte
}

// NewMLSSignaturePublicKey creates an enriched public key.
func NewMLSSignaturePublicKey(value []byte, scheme SignatureScheme) *MLSSignaturePublicKey {
	return &MLSSignaturePublicKey{
		SignatureScheme: scheme,
		Value:           value,
	}
}

// AsSlice returns the key bytes.
func (k *MLSSignaturePublicKey) AsSlice() []byte {
	return k.Value
}

// Scheme returns the signature scheme.
func (k *MLSSignaturePublicKey) Scheme() SignatureScheme {
	return k.SignatureScheme
}

// Verify verifies a signature using the appropriate algorithm for the signature scheme.
// For ECDSA: expects signature in ASN.1 DER format.
// For Ed25519: expects raw 64-byte signature.
func (k *MLSSignaturePublicKey) Verify(data []byte, sig *Signature) error {
	switch k.SignatureScheme {
	case ECDSA_SECP256R1_SHA256, ECDSA_SECP521R1_SHA512:
		return k.verifyECDSA(data, sig)
	case ED25519:
		return k.verifyEd25519(data, sig)
	default:
		return fmt.Errorf("unsupported signature scheme: %v", k.SignatureScheme)
	}
}

// verifyECDSA verifies an ECDSA signature, supporting both P-256 and P-521.
func (k *MLSSignaturePublicKey) verifyECDSA(data []byte, sig *Signature) error {
	var curve elliptic.Curve
	var coordLen int
	switch k.SignatureScheme {
	case ECDSA_SECP256R1_SHA256:
		curve = elliptic.P256()
		coordLen = 32
	case ECDSA_SECP521R1_SHA512:
		curve = elliptic.P521()
		coordLen = 66
	default:
		return fmt.Errorf("unsupported ECDSA scheme: %v", k.SignatureScheme)
	}

	expectedLen := 1 + 2*coordLen
	if len(k.Value) != expectedLen || k.Value[0] != 0x04 {
		return fmt.Errorf("invalid uncompressed point: expected %d bytes starting with 0x04, got %d bytes",
			expectedLen, len(k.Value))
	}

	x := new(big.Int).SetBytes(k.Value[1 : 1+coordLen])
	y := new(big.Int).SetBytes(k.Value[1+coordLen:])
	pubKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	// Pre-hash with the scheme's digest algorithm (RFC 9420 §5.1.2).
	hf := k.SignatureScheme.HashFunction()
	h := hf()
	h.Write(data)
	digest := h.Sum(nil)

	if !ecdsa.VerifyASN1(pubKey, digest, sig.AsSlice()) {
		return ErrInvalidSignature
	}

	return nil
}

// verifyEd25519 verifies an Ed25519 signature.
func (k *MLSSignaturePublicKey) verifyEd25519(data []byte, sig *Signature) error {
	// Ed25519 public keys are Ed25519KeySize = 32 bytes (RFC 8410 §3).
	if len(k.Value) != Ed25519KeySize {
		return fmt.Errorf("invalid Ed25519 public key length: %d", len(k.Value))
	}

	// Ed25519 signatures are 64 bytes (RFC 8032 §5.1.6).
	const ed25519SignatureSize = 64
	if len(sig.AsSlice()) != ed25519SignatureSize {
		return fmt.Errorf("invalid Ed25519 signature length: %d", len(sig.AsSlice()))
	}

	if !ed25519.Verify(k.Value, data, sig.AsSlice()) {
		return ErrInvalidSignature
	}
	return nil
}

// SignContent represents labeled content for signing as defined in RFC 9420 §5.1.2.
//
// The label prefix "MLS 1.0 " is prepended to prevent signature confusion attacks
// across different protocol versions and contexts.
//
//	struct {
//	    opaque label<V> = "MLS 1.0 " + Label;
//	    opaque content<V> = Content;
//	} SignContent;
type SignContent struct {
	Label   []byte
	Content []byte
}

// NewSignContent creates labeled signing content.
func NewSignContent(label string, content []byte) *SignContent {
	return &SignContent{
		Label:   []byte(LabelPrefix + label),
		Content: content,
	}
}

// Marshal serializes to TLS format.
func (sc *SignContent) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteVLBytes(sc.Label)
	w.WriteVLBytes(sc.Content)
	return w.Bytes()
}

// VerifyWithLabel verifies a signature with a specific label.
//
// This is a lower-level function for custom signing scenarios.
// Prefer Verify() for RFC 9420 compliance.
func VerifyWithLabel(pk *MLSSignaturePublicKey, label string, payload []byte, sig *Signature) error {
	signContent := NewSignContent(label, payload)
	signContentBytes := signContent.Marshal()
	return pk.Verify(signContentBytes, sig)
}

// SignWithLabel signs data with a specific label.
//
// This is a lower-level function for custom signing scenarios.
// Prefer Sign() for RFC 9420 compliance.
func SignWithLabel(signer *SignaturePrivateKey, label string, payload []byte) (*Signature, error) {
	signContent := NewSignContent(label, payload)
	signContentBytes := signContent.Marshal()
	return signer.Sign(signContentBytes)
}
