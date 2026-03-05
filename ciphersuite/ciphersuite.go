// Package ciphersuite implements MLS ciphersuite operations according to RFC 9420.
//
// This package provides cryptographic primitives used by the MLS protocol including:
//   - AEAD encryption/decryption (AES-128-GCM)
//   - Digital signatures (ECDSA with P-256)
//   - HPKE (Hybrid Public Key Encryption with DHKEM P-256)
//   - HKDF key derivation
//   - Hash functions (SHA-256)
//
// The primary ciphersuite for DAVE protocol is MLS_128_DHKEMP256_AES128GCM_SHA256_P256.
package ciphersuite

import (
	"crypto/subtle"
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

// CryptoError represents cryptographic operation errors.
type CryptoError string

const (
	ErrCryptoLibraryError     CryptoError = "crypto library error"
	ErrAeadDecryptionError    CryptoError = "AEAD decryption failed"
	ErrInvalidLength          CryptoError = "invalid length"
	ErrKdfLabelTooLarge       CryptoError = "KDF label too large"
	ErrKdfSerializationError  CryptoError = "KDF serialization error"
	ErrTlsSerializationError  CryptoError = "TLS serialization error"
	ErrInsufficientRandomness CryptoError = "insufficient randomness"
	ErrInvalidSignature       CryptoError = "invalid signature"
)

func (e CryptoError) Error() string {
	return string(e)
}

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
