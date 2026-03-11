package ciphersuite

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/openmls/go/internal/tls"
)

// Signature represents a digital signature.
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

// SignaturePublicKey represents a public signature key.
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
// Expects uncompressed point format: 0x04 || X || Y (65 bytes total).
func (k *SignaturePublicKey) ToECDSA() (*ecdsa.PublicKey, error) {
	if len(k.value) != 65 || k.value[0] != 0x04 {
		return nil, fmt.Errorf("invalid uncompressed point format: expected 65 bytes starting with 0x04, got %d bytes", len(k.value))
	}

	x := new(big.Int).SetBytes(k.value[1:33])
	y := new(big.Int).SetBytes(k.value[33:65])

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

// SignaturePrivateKey represents a private signature key.
// It is a union type supporting both ECDSA (P-256) and Ed25519.
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

// GenerateSignaturePrivateKey generates a new P-256 private key.
func GenerateSignaturePrivateKey() (*SignaturePrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating P-256 key: %w", err)
	}
	return &SignaturePrivateKey{scheme: ECDSA_SECP256R1_SHA256, ecdsaKey: priv}, nil
}

// GenerateSignaturePrivateKeyForCS generates a new private key appropriate for the cipher suite.
// CS1/CS3 use Ed25519; CS2 uses P-256 ECDSA.
func GenerateSignaturePrivateKeyForCS(cs CipherSuite) (*SignaturePrivateKey, error) {
	switch cs.SignatureScheme() {
	case ED25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating Ed25519 key: %w", err)
		}
		return &SignaturePrivateKey{scheme: ED25519, ed25519Key: priv}, nil
	default:
		return GenerateSignaturePrivateKey()
	}
}

// Scheme returns the signature scheme of this key.
func (k *SignaturePrivateKey) Scheme() SignatureScheme {
	return k.scheme
}

// PublicKey returns the public key bytes.
// For ECDSA: returns uncompressed point (0x04 || X || Y, 65 bytes).
// For Ed25519: returns raw 32-byte public key.
func (k *SignaturePrivateKey) PublicKey() *SignaturePublicKey {
	if k.scheme == ED25519 {
		pub := k.ed25519Key.Public().(ed25519.PublicKey)
		return NewSignaturePublicKey([]byte(pub))
	}

	// ECDSA P-256: uncompressed format via crypto/ecdh (avoids deprecated .X/.Y access)
	ecdhKey, err := k.ecdsaKey.ECDH()
	if err != nil {
		// Fallback should never happen for a valid P-256 key
		return NewSignaturePublicKey(nil)
	}
	return NewSignaturePublicKey(ecdhKey.PublicKey().Bytes())
}

// Sign signs the given data.
// For ECDSA: uses ECDSA-SHA256, returns ASN.1 DER format.
// For Ed25519: returns raw 64-byte signature.
func (k *SignaturePrivateKey) Sign(data []byte) (*Signature, error) {
	if k.scheme == ED25519 {
		sig := ed25519.Sign(k.ed25519Key, data)
		return NewSignature(sig), nil
	}

	// ECDSA-SHA256
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, k.ecdsaKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	// Convert to ASN.1 DER format
	type ecdsaSignature struct {
		R, S *big.Int
	}
	sigDER, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
	if err != nil {
		return nil, fmt.Errorf("marshaling signature: %w", err)
	}

	return NewSignature(sigDER), nil
}

// OpenMlsSignaturePublicKey is an enriched public key with signature scheme.
type OpenMlsSignaturePublicKey struct {
	SignatureScheme SignatureScheme
	Value           []byte
}

// NewOpenMlsSignaturePublicKey creates an enriched public key.
func NewOpenMlsSignaturePublicKey(value []byte, scheme SignatureScheme) *OpenMlsSignaturePublicKey {
	return &OpenMlsSignaturePublicKey{
		SignatureScheme: scheme,
		Value:           value,
	}
}

// AsSlice returns the key bytes.
func (k *OpenMlsSignaturePublicKey) AsSlice() []byte {
	return k.Value
}

// Scheme returns the signature scheme.
func (k *OpenMlsSignaturePublicKey) Scheme() SignatureScheme {
	return k.SignatureScheme
}

// Verify verifies a signature using the appropriate algorithm for the signature scheme.
// For ECDSA: expects signature in ASN.1 DER format.
// For Ed25519: expects raw 64-byte signature.
func (k *OpenMlsSignaturePublicKey) Verify(data []byte, sig *Signature) error {
	switch k.SignatureScheme {
	case ECDSA_SECP256R1_SHA256:
		return k.verifyECDSA(data, sig)
	case ED25519:
		return k.verifyEd25519(data, sig)
	default:
		return fmt.Errorf("unsupported signature scheme: %v", k.SignatureScheme)
	}
}

// verifyECDSA verifies an ECDSA-SHA256 signature.
func (k *OpenMlsSignaturePublicKey) verifyECDSA(data []byte, sig *Signature) error {
	pubKey, err := NewSignaturePublicKey(k.Value).ToECDSA()
	if err != nil {
		return err
	}

	hash := sha256.Sum256(data)

	// Parse ASN.1 DER signature
	type ecdsaSignature struct {
		R, S *big.Int
	}
	var ecdsaSig ecdsaSignature
	if _, err := asn1.Unmarshal(sig.AsSlice(), &ecdsaSig); err != nil {
		return ErrInvalidSignature
	}

	if !ecdsa.Verify(pubKey, hash[:], ecdsaSig.R, ecdsaSig.S) {
		return ErrInvalidSignature
	}
	return nil
}

// verifyEd25519 verifies an Ed25519 signature.
func (k *OpenMlsSignaturePublicKey) verifyEd25519(data []byte, sig *Signature) error {
	// Ed25519 public keys are 32 bytes
	if len(k.Value) != 32 {
		return fmt.Errorf("invalid Ed25519 public key length: %d", len(k.Value))
	}

	// Ed25519 signatures are 64 bytes
	if len(sig.AsSlice()) != 64 {
		return fmt.Errorf("invalid Ed25519 signature length: %d", len(sig.AsSlice()))
	}

	if !ed25519.Verify(k.Value, data, sig.AsSlice()) {
		return ErrInvalidSignature
	}
	return nil
}

// SignContent represents labeled content for signing (RFC 9420 §5.1.2).
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
