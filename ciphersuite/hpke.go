// Package ciphersuite - HPKE operations for MLS (RFC 9420 §5.1.3, RFC 9180)
//
// Implementación nativa usando crypto/hpke de Go 1.26.
// Sigue RFC 9180 (HPKE) y RFC 9420 (MLS) al pie de la letra.
package ciphersuite

import (
	"crypto/ecdh"
	"crypto/hpke"
	"fmt"

	"github.com/mls-go/internal/tls"
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
	ciphersuite CipherSuite,
) (*HpkeCiphertext, error) {
	switch ciphersuite {
	case MLS128DHKEMX25519:
		return encryptWithLabelNative(publicKey, label, context, plaintext, ecdh.X25519(), hpke.AES128GCM())
	case MLS256DHKEMX25519ChaCha20:
		return encryptWithLabelNative(publicKey, label, context, plaintext, ecdh.X25519(), hpke.ChaCha20Poly1305())
	case MLS128DHKEMP256:
		return encryptWithLabelNative(publicKey, label, context, plaintext, ecdh.P256(), hpke.AES128GCM())
	default:
		return nil, fmt.Errorf("unsupported cipher suite: %d", ciphersuite)
	}
}

// encryptWithLabelNative is the native implementation using crypto/hpke.
func encryptWithLabelNative(
	publicKey []byte,
	label string,
	context []byte,
	plaintext []byte,
	curve ecdh.Curve,
	aead hpke.AEAD,
) (*HpkeCiphertext, error) {
	// Construir info = Serialize(VL("MLS 1.0 " + label) || VL(context))
	// Según RFC 9420 §5.1.3, ambos campos llevan length prefix
	encContext := NewEncryptContext(label, context)
	info := encContext.Marshal()

	// Parsear public key
	pubKey, err := curve.NewPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	pk, err := hpke.NewDHKEMPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("creating HPKE public key: %w", err)
	}

	// Encrypt usando HPKE Seal (RFC 9180 §4.1)
	// Seal retorna enc || ciphertext concatenado
	encapsulatedAndCt, err := hpke.Seal(pk, hpke.HKDFSHA256(), aead, info, plaintext)
	if err != nil {
		return nil, fmt.Errorf("HPKE seal: %w", err)
	}

	// Separar KEM output del ciphertext
	// El largo del KEM output depende de la curva:
	// - X25519: 32 bytes
	// - P256: 65 bytes (punto sin comprimir: 0x04 + 32 + 32)
	kemOutputLen := len(publicKey) // Mismo largo que la public key
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
	ciphersuite CipherSuite,
) ([]byte, error) {
	switch ciphersuite {
	case MLS128DHKEMX25519:
		return decryptWithLabelNative(privateKey, label, context, ciphertext, ecdh.X25519(), hpke.AES128GCM())
	case MLS256DHKEMX25519ChaCha20:
		return decryptWithLabelNative(privateKey, label, context, ciphertext, ecdh.X25519(), hpke.ChaCha20Poly1305())
	case MLS128DHKEMP256:
		return decryptWithLabelNative(privateKey, label, context, ciphertext, ecdh.P256(), hpke.AES128GCM())
	default:
		return nil, fmt.Errorf("unsupported cipher suite: %d", ciphersuite)
	}
}

// decryptWithLabelNative is the native implementation using crypto/hpke.
func decryptWithLabelNative(
	privateKey []byte,
	label string,
	context []byte,
	ciphertext *HpkeCiphertext,
	curve ecdh.Curve,
	aead hpke.AEAD,
) ([]byte, error) {
	// Construir info = Serialize(VL("MLS 1.0 " + label) || VL(context))
	// Según RFC 9420 §5.1.3, ambos campos llevan length prefix
	encContext := NewEncryptContext(label, context)
	info := encContext.Marshal()

	// Parsear private key
	privKey, err := curve.NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	sk, err := hpke.NewDHKEMPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("creating HPKE private key: %w", err)
	}

	// Concat KEM output and ciphertext for HPKE Open
	encapsulatedAndCt := make([]byte, 0, len(ciphertext.KEMOutput)+len(ciphertext.Ciphertext))
	encapsulatedAndCt = append(encapsulatedAndCt, ciphertext.KEMOutput...)
	encapsulatedAndCt = append(encapsulatedAndCt, ciphertext.Ciphertext...)

	// Decrypt usando HPKE Open (RFC 9180 §4.1)
	plaintext, err := hpke.Open(sk, hpke.HKDFSHA256(), aead, info, encapsulatedAndCt)
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
	var kem hpke.KEM
	switch cs {
	case MLS128DHKEMX25519, MLS256DHKEMX25519ChaCha20:
		kem = hpke.DHKEM(ecdh.X25519())
	case MLS128DHKEMP256:
		kem = hpke.DHKEM(ecdh.P256())
	default:
		return nil, fmt.Errorf("unsupported cipher suite: %d", cs)
	}

	privKey, err := kem.DeriveKeyPair(ikm)
	if err != nil {
		return nil, fmt.Errorf("DeriveKeyPair: %w", err)
	}

	// hpke.PrivateKey → *ecdh.PrivateKey via bytes round-trip
	privBytes, err := privKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("DeriveKeyPair marshal: %w", err)
	}
	switch cs {
	case MLS128DHKEMX25519, MLS256DHKEMX25519ChaCha20:
		return ecdh.X25519().NewPrivateKey(privBytes)
	case MLS128DHKEMP256:
		return ecdh.P256().NewPrivateKey(privBytes)
	default:
		return nil, fmt.Errorf("unsupported cipher suite: %d", cs)
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
