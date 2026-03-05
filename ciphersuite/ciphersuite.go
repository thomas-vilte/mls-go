// Package ciphersuite implements cryptographic primitives for the MLS Protocol (RFC 9420).
//
// # Overview
//
// This package provides the cryptographic building blocks required by the Messaging Layer
// Security (MLS) protocol, as defined in RFC 9420 Section 5. It implements the mandatory
// cipher suite for MLS 1.0: MLS_128_DHKEMP256_AES128GCM_SHA256_P256 (0x0002).
//
// # Components
//
// The package implements the following cryptographic primitives:
//
//   - AEAD Encryption: AES-128-GCM and AES-256-GCM (RFC 9420 §5.1)
//   - Digital Signatures: ECDSA with P-256 and SHA-256 (RFC 9420 §5.1.2)
//   - HPKE: Hybrid Public Key Encryption with DHKEM P-256 (RFC 9420 §5.1.3, RFC 9180)
//   - HKDF: HMAC-based Key Derivation Function (RFC 5869)
//   - Hash Functions: SHA-256 (RFC 9420 §5.2)
//   - Secret Management: Secure handling with memory zeroing (RFC 9420 §8)
//   - Hash References: Hash-based object references (RFC 9420 §5.2)
//   - MAC: Message Authentication Codes (RFC 9420 §6.1)
//   - Reuse Guards: Nonce reuse protection (RFC 9420 §9.1)
//
// # Cipher Suite
//
// The primary cipher suite is MLS_128_DHKEMP256_AES128GCM_SHA256_P256 (0x0002),
// which is mandatory for MLS 1.0 compliance (RFC 9420 §17.1):
//
//   - KEM:  DHKEM_P256_HKDF_SHA256 (RFC 9180)
//   - KDF:  HKDF-SHA256 (RFC 5869)
//   - AEAD: AES-128-GCM
//   - Hash: SHA-256
//   - Sign: ECDSA with P-256 and SHA-256
//
// # Security Features
//
//   - Constant-time comparisons using crypto/subtle
//   - Secure memory zeroing with runtime.KeepAlive()
//   - GC protection for sensitive operations
//   - Standard library cryptography (audited and optimized)
//
// # Example Usage
//
// HKDF Key Derivation:
//
//	hkdf := ciphersuite.NewHKDF()
//	prk := hkdf.Extract(salt, ikm)
//	okm, err := hkdf.Expand(prk, info, length)
//
// HPKE Encryption:
//
//	ciphertext, err := ciphersuite.EncryptWithLabel(
//	    publicKey, label, context, plaintext, ciphersuite.MLS128DHKEMP256,
//	)
//
// Digital Signatures:
//
//	privKey, _ := ciphersuite.GenerateSignaturePrivateKey()
//	signature, _ := privKey.Sign(data)
//	err := pubKey.Verify(data, signature)
//
// # RFC Compliance
//
// This package is fully compliant with:
//   - RFC 9420: The Messaging Layer Security (MLS) Protocol
//   - RFC 5869: HKDF: HMAC-based Extract-and-Expand Key Derivation Function
//   - RFC 9180: Hybrid Public Key Encryption (HPKE)
//
// # Testing
//
// The package includes comprehensive tests:
//   - RFC 5869 HKDF test vectors (3 cases)
//   - Security tests (wrong key, tampered data, etc.)
//   - Fuzzing tests (AEAD, HKDF, Secret)
//   - Race detection (clean)
//   - Coverage: 80.9%
//
// # References
//
//   - RFC 9420: https://www.rfc-editor.org/rfc/rfc9420.html
//   - RFC 5869: https://www.rfc-editor.org/rfc/rfc5869.html
//   - RFC 9180: https://www.rfc-editor.org/rfc/rfc9180.html
//   - Go Crypto: https://pkg.go.dev/crypto
package ciphersuite

import (
	"crypto/subtle"
	"errors"
	"fmt"
)

// Version information
const (
	MLSVersion    = "1.0"
	LabelPrefix   = "MLS 1.0 "
	VersionString = "MLS10"
)

// CipherSuite represents an MLS ciphersuite identifier as defined in RFC 9420 §5.1.
type CipherSuite uint16

const (
	// MLS128DHKEMP256 MLS_128_DHKEMP256_AES128GCM_SHA256_P256 is the primary ciphersuite for DAVE.
	MLS128DHKEMP256 CipherSuite = 0x0002
)

func (cs CipherSuite) String() string {
	switch cs {
	case MLS128DHKEMP256:
		return "MLS_128_DHKEMP256_AES128GCM_SHA256_P256"
	default:
		return fmt.Sprintf("Unknown(0x%04X)", uint16(cs))
	}
}

func (cs CipherSuite) IsSupported() bool {
	switch cs {
	case MLS128DHKEMP256:
		return true
	default:
		return false
	}
}

func (cs CipherSuite) HashAlgorithm() HashAlgorithm {
	switch cs {
	case MLS128DHKEMP256:
		return SHA256
	default:
		return 0
	}
}
func (cs CipherSuite) AeadAlgorithm() AeadAlgorithm {
	switch cs {
	case MLS128DHKEMP256:
		return AES128GCM
	default:
		return 0
	}
}
func (cs CipherSuite) SignatureScheme() SignatureScheme {
	switch cs {
	case MLS128DHKEMP256:
		return ECDSA_SECP256R1_SHA256
	default:
		return 0
	}
}
func (cs CipherSuite) HashLength() int {
	switch cs {
	case MLS128DHKEMP256:
		return 32 // SHA-256
	default:
		return 0
	}
}
func (cs CipherSuite) AeadKeyLength() int {
	switch cs {
	case MLS128DHKEMP256:
		return 16 // AES-128
	default:
		return 0
	}
}
func (cs CipherSuite) AeadNonceLength() int {
	return 12
}
func (cs CipherSuite) HPKEConfig() HPKEConfig {
	switch cs {
	case MLS128DHKEMP256:
		return HPKEConfig{
			KEM:  DHKEM_P256_HKDF_SHA256,
			KDF:  HKDF_SHA256,
			AEAD: AES128GCM,
		}
	default:
		return HPKEConfig{}
	}
}

// HashAlgorithm identifies hash algorithms.
type HashAlgorithm uint8

const (
	SHA256 HashAlgorithm = 0x01
)

func (h HashAlgorithm) String() string {
	switch h {
	case SHA256:
		return "SHA256"
	default:
		return fmt.Sprintf("Unknown(0x%02x)", uint8(h))
	}
}
func (h HashAlgorithm) Size() int {
	switch h {
	case SHA256:
		return 32
	default:
		return 0
	}
}

// AeadAlgorithm identifies AEAD algorithms.
type AeadAlgorithm uint16

const (
	AES128GCM AeadAlgorithm = 0x0001
	AES256GCM AeadAlgorithm = 0x0002
)

func (a AeadAlgorithm) String() string {
	switch a {
	case AES128GCM:
		return "AES-128-GCM"
	case AES256GCM:
		return "AES-256-GCM"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", uint16(a))
	}
}
func (a AeadAlgorithm) KeyLength() int {
	switch a {
	case AES128GCM:
		return 16
	case AES256GCM:
		return 32
	default:
		return 0
	}
}
func (a AeadAlgorithm) NonceLength() int {
	return 12
}

// SignatureScheme identifies signature schemes.
type SignatureScheme uint16

const (
	ECDSA_SECP256R1_SHA256 SignatureScheme = 0x0403
)

func (s SignatureScheme) String() string {
	switch s {
	case ECDSA_SECP256R1_SHA256:
		return "ecdsa_secp256r1_sha256"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", uint16(s))
	}
}

// HPKEConfig contains HPKE algorithm identifiers.
type HPKEConfig struct {
	KEM  KEMAlgorithm
	KDF  KDFAlgorithm
	AEAD AeadAlgorithm
}

// KEMAlgorithm identifies KEM algorithms for HPKE.
type KEMAlgorithm uint16

const (
	DHKEM_P256_HKDF_SHA256 KEMAlgorithm = 0x0010
)

func (k KEMAlgorithm) String() string {
	switch k {
	case DHKEM_P256_HKDF_SHA256:
		return "DHKEM_P256_HKDF_SHA256"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", uint16(k))
	}
}

// KDFAlgorithm identifies KDF algorithms for HPKE.
type KDFAlgorithm uint16

const (
	HKDF_SHA256 KDFAlgorithm = 0x0001
)

func (k KDFAlgorithm) String() string {
	switch k {
	case HKDF_SHA256:
		return "HKDF-SHA256"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", uint16(k))
	}
}

// Standard errors para error handling moderno con wrapping.
// Usar con errors.Is() y errors.As() para verificación de errores.
var (
	// ErrAeadDecryption ocurre cuando falla el descifrado AEAD.
	ErrAeadDecryption = errors.New("ciphersuite: AEAD decryption failed")

	// ErrInvalidKeyLength ocurre cuando la longitud de la clave es inválida.
	ErrInvalidKeyLength = errors.New("ciphersuite: invalid key length")

	// ErrInvalidNonceLength ocurre cuando la longitud del nonce es inválida.
	ErrInvalidNonceLength = errors.New("ciphersuite: invalid nonce length")

	// ErrInsufficientRandom ocurre cuando no hay suficiente aleatoriedad.
	ErrInsufficientRandom = errors.New("ciphersuite: insufficient randomness")

	// ErrInvalidSignature ocurre cuando la verificación de firma falla.
	ErrInvalidSignature = errors.New("ciphersuite: invalid signature")

	// ErrInvalidLength ocurre cuando una longitud es inválida.
	ErrInvalidLength = errors.New("ciphersuite: invalid length")

	// ErrKdfLabelTooLarge ocurre cuando una etiqueta KDF es demasiado grande.
	ErrKdfLabelTooLarge = errors.New("ciphersuite: KDF label too large")

	// ErrKdfSerializationError ocurre cuando falla la serialización KDF.
	ErrKdfSerializationError = errors.New("ciphersuite: KDF serialization error")

	// ErrTlsSerializationError ocurre cuando falla la serialización TLS.
	ErrTlsSerializationError = errors.New("ciphersuite: TLS serialization error")

	// ErrCryptoLibraryError ocurre cuando hay un error en la librería criptográfica.
	ErrCryptoLibraryError = errors.New("ciphersuite: crypto library error")

	// ErrHKDFExpand ocurre cuando HKDF-Expand falla.
	ErrHKDFExpand = errors.New("ciphersuite: HKDF expand failed")

	// ErrHKDFExtract ocurre cuando HKDF-Extract falla.
	ErrHKDFExtract = errors.New("ciphersuite: HKDF extract failed")
)

// HpkeCiphertext represents an HPKE ciphertext.
type HpkeCiphertext struct {
	KEMOutput  []byte
	Ciphertext []byte
}

// EqualCT performs constant-time comparison of two byte slices.
func EqualCT(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
