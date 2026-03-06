package ciphersuite

import (
	"crypto/ecdsa"
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
type SignaturePrivateKey struct {
	ecdsa *ecdsa.PrivateKey
}

// NewSignaturePrivateKey creates a wrapper from an existing ecdsa.PrivateKey.
func NewSignaturePrivateKey(priv *ecdsa.PrivateKey) *SignaturePrivateKey {
	return &SignaturePrivateKey{ecdsa: priv}
}

// GenerateSignaturePrivateKey generates a new P-256 private key.
func GenerateSignaturePrivateKey() (*SignaturePrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating P-256 key: %w", err)
	}
	return &SignaturePrivateKey{ecdsa: priv}, nil
}

// PublicKey returns the public key in uncompressed format.
// RFC 9420 §5.1.2: Public keys are encoded in uncompressed format (0x04 || X || Y).
func (k *SignaturePrivateKey) PublicKey() *SignaturePublicKey {
	// Usar la API moderna de ecdh para obtener los bytes de la public key
	// Convertir las coordenadas X, Y a formato uncompressed
	pubKey := k.ecdsa.PublicKey

	// Formato uncompressed: 0x04 || X || Y (65 bytes para P-256)
	// X e Y son cada uno 32 bytes
	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()

	// Asegurar que tengan 32 bytes (padding con ceros si es necesario)
	if len(xBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(xBytes):], xBytes)
		xBytes = padded
	}
	if len(yBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(yBytes):], yBytes)
		yBytes = padded
	}

	// Construir formato uncompressed
	bytes := make([]byte, 65)
	bytes[0] = 0x04
	copy(bytes[1:33], xBytes)
	copy(bytes[33:65], yBytes)

	return NewSignaturePublicKey(bytes)
}

// Sign signs the given data using ECDSA-SHA256.
// Returns the signature in ASN.1 DER format.
func (k *SignaturePrivateKey) Sign(data []byte) (*Signature, error) {
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, k.ecdsa, hash[:])
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

// Verify verifies a signature using ECDSA-SHA256.
// Expects signature in ASN.1 DER format.
func (k *OpenMlsSignaturePublicKey) Verify(data []byte, sig *Signature) error {
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
