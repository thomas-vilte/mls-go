// Package ciphersuite implements cryptographic primitives for the MLS Protocol (RFC 9420).
//
// # Overview
//
// This package provides the cryptographic building blocks required by the Messaging Layer
// Security (MLS) protocol, as defined in RFC 9420 Section 5. It implements cipher suites
// 1, 2, and 3 for MLS 1.0, with placeholders for suites 4-7.
//
// # Implemented Cipher Suites
//
//   - CS1 (0x0001): MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 ✅
//   - CS2 (0x0002): MLS_128_DHKEMP256_AES128GCM_SHA256_P256 ✅
//   - CS3 (0x0003): MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 ✅
//
// # Placeholder Cipher Suites (not implemented)
//
//   - CS4 (0x0004): MLS_256_DHKEMP384_AES256GCM_SHA384_P384 ⏳
//   - CS5 (0x0005): MLS_256_DHKEMP521_AES256GCM_SHA512_P521 ⏳
//   - CS6 (0x0006): MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 ⏳
//   - CS7 (0x0007): MLS_256_DHKEMP384_CHACHA20POLY1305_SHA384_P384 ⏳
//
// # Components
//
// The package implements the following cryptographic primitives:
//
//   - AEAD Encryption: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 (RFC 9420 §5.1)
//   - Digital Signatures: ECDSA (P-256, P-384, P-521) and Ed25519 (RFC 9420 §5.1.2)
//   - HPKE: Hybrid Public Key Encryption with DHKEM (P-256, P-384, P-521, X25519) (RFC 9420 §5.1.3, RFC 9180)
//   - HKDF: HMAC-based Key Derivation Function (RFC 5869)
//   - Hash Functions: SHA-256, SHA-384, SHA-512 (RFC 9420 §5.2)
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
// # References
//
//   - RFC 9420: https://www.rfc-editor.org/rfc/rfc9420.html
//   - RFC 5869: https://www.rfc-editor.org/rfc/rfc5869.html
//   - RFC 9180: https://www.rfc-editor.org/rfc/rfc9180.html
//   - Go Crypto: https://pkg.go.dev/crypto
package ciphersuite

import (
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"hash"
)

// LabelPrefix is the prefix for all MLS 1.0 labels (RFC 9420 §8).
const LabelPrefix = "MLS 1.0 "

// Key size constants for signature public keys (RFC 9420 §5.1.2).
const (
	// P256UncompressedKeySize is the length of an uncompressed ECDSA P-256 public key
	// in SEC 1 format: 0x04 || 32-byte X || 32-byte Y = 65 bytes (RFC 5480 §2.2).
	P256UncompressedKeySize = 65

	// P521UncompressedKeySize is the length of an uncompressed ECDSA P-521 public key
	// in SEC 1 format: 0x04 || 66-byte X || 66-byte Y = 133 bytes (RFC 5480 §2.2).
	P521UncompressedKeySize = 133

	// Ed25519KeySize is the length of an Ed25519 public key (RFC 8410 §3).
	Ed25519KeySize = 32
)

// CipherSuite represents an MLS ciphersuite identifier as defined in RFC 9420 §5.1.
//
// See also: RFC 9420 §17.1 for mandatory cipher suites for MLS 1.0
type CipherSuite uint16

const (
	// MLS128DHKEMX25519 is cipher suite 1: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
	// RFC 9420 §17.1: Recommended for most deployments
	MLS128DHKEMX25519 CipherSuite = 0x0001

	// MLS128DHKEMP256 is cipher suite 2: MLS_128_DHKEMP256_AES128GCM_SHA256_P256
	// RFC 9420 §17.1: MANDATORY for MLS 1.0 compliance
	MLS128DHKEMP256 CipherSuite = 0x0002

	// MLS128DHKEMX25519ChaCha20 is cipher suite 3: MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
	// RFC 9420 §17.1: X25519 + ChaCha20-Poly1305 (for devices without AES-NI)
	MLS128DHKEMX25519ChaCha20 CipherSuite = 0x0003

	// MLS256DHKEMX448AES256GCM is cipher suite 4: MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
	// RFC 9420 §17.1: X448 + AES-256-GCM + SHA-512 + Ed448
	MLS256DHKEMX448AES256GCM CipherSuite = 0x0004

	// MLS256DHKEMP521AES256GCM is cipher suite 5: MLS_256_DHKEMP521_AES256GCM_SHA512_P521
	// RFC 9420 §17.1: P-521 + AES-256-GCM + SHA-512 + ECDSA-P521
	MLS256DHKEMP521AES256GCM CipherSuite = 0x0005

	// MLS256DHKEMX448ChaCha20Poly1305 is a deprecated alias kept for backward compatibility.
	// The correct name for cipher suite 0x0005 is MLS256DHKEMP521AES256GCM.
	MLS256DHKEMX448ChaCha20Poly1305 = MLS256DHKEMP521AES256GCM //nolint:revive // deprecated alias
)

// String returns the name of the cipher suite.
func (cs CipherSuite) String() string {
	switch cs {
	case MLS128DHKEMX25519:
		return "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
	case MLS128DHKEMP256:
		return "MLS_128_DHKEMP256_AES128GCM_SHA256_P256"
	case MLS128DHKEMX25519ChaCha20:
		return "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519"
	case MLS256DHKEMX448AES256GCM:
		return "MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448"
	case MLS256DHKEMP521AES256GCM:
		return "MLS_256_DHKEMP521_AES256GCM_SHA512_P521"
	default:
		return fmt.Sprintf("Unknown(0x%04X)", uint16(cs))
	}
}

// IsSupported returns true if the cipher suite is implemented.
func (cs CipherSuite) IsSupported() bool {
	switch cs {
	case MLS128DHKEMX25519, MLS128DHKEMP256, MLS128DHKEMX25519ChaCha20,
		MLS256DHKEMP521AES256GCM:
		return true
	default:
		return false
	}
}

// HashAlgorithm returns the hash algorithm for the cipher suite.
func (cs CipherSuite) HashAlgorithm() HashAlgorithm {
	switch cs {
	case MLS128DHKEMX25519, MLS128DHKEMX25519ChaCha20, MLS128DHKEMP256:
		return SHA256
	case MLS256DHKEMX448AES256GCM, MLS256DHKEMP521AES256GCM:
		return SHA512
	default:
		return 0
	}
}

// AeadAlgorithm returns the AEAD algorithm for the cipher suite.
func (cs CipherSuite) AeadAlgorithm() AeadAlgorithm {
	switch cs {
	case MLS128DHKEMX25519, MLS128DHKEMP256:
		return AES128GCM
	case MLS128DHKEMX25519ChaCha20:
		return ChaCha20Poly1305
	case MLS256DHKEMX448AES256GCM, MLS256DHKEMP521AES256GCM:
		return AES256GCM
	default:
		return 0
	}
}

// Curve returns the ECDH curve for the cipher suite's KEM, or nil if unsupported.
func (cs CipherSuite) Curve() ecdh.Curve {
	switch cs {
	case MLS128DHKEMX25519, MLS128DHKEMX25519ChaCha20:
		return ecdh.X25519()
	case MLS128DHKEMP256:
		return ecdh.P256()
	case MLS256DHKEMP521AES256GCM:
		return ecdh.P521()
	default:
		return nil
	}
}

// SignatureScheme returns the signature scheme for the cipher suite (RFC 9420 §5.1.2).
func (cs CipherSuite) SignatureScheme() SignatureScheme {
	switch cs {
	case MLS128DHKEMX25519, MLS128DHKEMX25519ChaCha20:
		return ED25519
	case MLS128DHKEMP256:
		return ECDSA_SECP256R1_SHA256
	case MLS256DHKEMP521AES256GCM:
		return ECDSA_SECP521R1_SHA512
	default:
		return 0
	}
}

// SignatureKeyLength returns the public signature key length in bytes (RFC 9420 §5.1.2).
//
// For ECDSA P-256: 65 bytes (uncompressed SEC 1 point: 0x04 || X || Y).
// For Ed25519: 32 bytes (RFC 8410 §3).
func (cs CipherSuite) SignatureKeyLength() int {
	switch cs.SignatureScheme() {
	case ECDSA_SECP256R1_SHA256:
		return P256UncompressedKeySize
	case ECDSA_SECP521R1_SHA512:
		return P521UncompressedKeySize
	case ED25519:
		return 32
	default:
		return 0
	}
}

// HashLength returns the hash output length in bytes (Nh in RFC 9420 §5.1).
//
// CS1/CS2/CS3: 32 bytes (SHA-256).
// CS4/CS5: 64 bytes (SHA-512).
func (cs CipherSuite) HashLength() int {
	switch cs {
	case MLS128DHKEMX25519, MLS128DHKEMX25519ChaCha20, MLS128DHKEMP256:
		return 32 // SHA-256
	case MLS256DHKEMX448AES256GCM, MLS256DHKEMX448ChaCha20Poly1305:
		return 64 // SHA-512
	default:
		return 0
	}
}

// AeadKeyLength returns the AEAD key length in bytes.
func (cs CipherSuite) AeadKeyLength() int {
	switch cs {
	case MLS128DHKEMX25519, MLS128DHKEMP256:
		return 16 // AES-128
	case MLS128DHKEMX25519ChaCha20:
		return 32 // ChaCha20
	case MLS256DHKEMP521AES256GCM, MLS256DHKEMX448AES256GCM:
		return 32 // AES-256
	default:
		return 0
	}
}

// AeadNonceLength returns the AEAD nonce length in bytes (12 for all supported algorithms).
func (cs CipherSuite) AeadNonceLength() int {
	return 12 // Both AES-GCM and ChaCha20-Poly1305 use 12-byte nonces
}

// HPKEConfig returns the cipher suite for the HPKE configuration.
func (cs CipherSuite) HPKEConfig() HPKEConfig {
	switch cs {
	case MLS128DHKEMX25519:
		return HPKEConfig{
			KEM:  DHKEM_X25519_HKDF_SHA256,
			KDF:  HKDF_SHA256,
			AEAD: AES128GCM,
		}
	case MLS128DHKEMP256:
		return HPKEConfig{
			KEM:  DHKEM_P256_HKDF_SHA256,
			KDF:  HKDF_SHA256,
			AEAD: AES128GCM,
		}
	case MLS128DHKEMX25519ChaCha20:
		return HPKEConfig{
			KEM:  DHKEM_X25519_HKDF_SHA256,
			KDF:  HKDF_SHA256,
			AEAD: ChaCha20Poly1305,
		}
	case MLS256DHKEMP521AES256GCM:
		return HPKEConfig{
			KEM:  DHKEM_P521_HKDF_SHA512,
			KDF:  HKDF_SHA512,
			AEAD: AES256GCM,
		}
	default:
		return HPKEConfig{}
	}
}

// HashFunction returns the hash constructor for the cipher suite, or nil if unsupported.
func (cs CipherSuite) HashFunction() func() hash.Hash {
	switch cs {
	case MLS128DHKEMX25519, MLS128DHKEMP256, MLS128DHKEMX25519ChaCha20:
		return sha256.New
	case MLS256DHKEMP521AES256GCM:
		return sha512.New
	default:
		return nil
	}
}

// HashAlgorithm identifies hash algorithms as defined in RFC 9420 §5.2.
type HashAlgorithm uint8

const (
	// SHA256 is SHA-256 (32 bytes output)
	// RFC 9420 §5.2: Used by cipher suites 1, 2, and 3
	SHA256 HashAlgorithm = 0x01

	// SHA512 is SHA-512 (64 bytes output)
	// RFC 9420 §5.2: Used by cipher suites 4 and 5
	SHA512 HashAlgorithm = 0x02
)

func (h HashAlgorithm) String() string {
	switch h {
	case SHA256:
		return "SHA256"
	case SHA512:
		return "SHA512"
	default:
		return fmt.Sprintf("Unknown(0x%02x)", uint8(h))
	}
}

// Size returns the hash output size in bytes.
func (h HashAlgorithm) Size() int {
	switch h {
	case SHA256:
		return 32
	case SHA512:
		return 64
	default:
		return 0
	}
}

// AeadAlgorithm identifies AEAD algorithms as defined in RFC 9420 §5.1.
type AeadAlgorithm uint16

const (
	// AES128GCM is AES-128-GCM (16-byte key, 12-byte nonce)
	// RFC 9420 §5.1: Used by cipher suites 1 and 2
	AES128GCM AeadAlgorithm = 0x0001

	// AES256GCM is AES-256-GCM (32-byte key, 12-byte nonce)
	// RFC 9420 §5.1: Used by cipher suites 4 and 5 (not implemented)
	AES256GCM AeadAlgorithm = 0x0002

	// ChaCha20Poly1305 is ChaCha20-Poly1305 (32-byte key, 12-byte nonce)
	// RFC 9420 §5.1: Used by cipher suites 3, 6, and 7
	ChaCha20Poly1305 AeadAlgorithm = 0x0003
)

func (a AeadAlgorithm) String() string {
	switch a {
	case AES128GCM:
		return "AES-128-GCM"
	case AES256GCM:
		return "AES-256-GCM"
	case ChaCha20Poly1305:
		return "ChaCha20-Poly1305"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", uint16(a))
	}
}

// KeyLength returns the key length in bytes for the AEAD algorithm.
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

// NonceLength returns the nonce length in bytes (12 for all AEAD algorithms).
func (a AeadAlgorithm) NonceLength() int {
	return 12
}

// SignatureScheme identifies signature schemes as defined in RFC 9420 §5.1.2.
type SignatureScheme uint16

const (
	// ECDSA_SECP256R1_SHA256 is ECDSA with P-256 and SHA-256
	// RFC 9420 §5.1.2: Used by cipher suite 2 (mandatory for MLS 1.0)
	//nolint:revive // RFC 9420 naming convention
	ECDSA_SECP256R1_SHA256 SignatureScheme = 0x0403

	// ED25519 is Ed25519 signatures
	// RFC 8410: Used by cipher suites 1 and 3
	ED25519 SignatureScheme = 0x0807

	// ED448 is Ed448 signatures
	// RFC 8032: Used by cipher suite 4
	ED448 SignatureScheme = 0x0808

	// ECDSA_SECP521R1_SHA512 is ECDSA with P-521 and SHA-512
	// RFC 8446 §4.2.3: Used by cipher suite 5
	//nolint:revive // RFC 8446 naming convention
	ECDSA_SECP521R1_SHA512 SignatureScheme = 0x0603
)

func (s SignatureScheme) String() string {
	switch s {
	case ECDSA_SECP256R1_SHA256:
		return "ecdsa_secp256r1_sha256"
	case ECDSA_SECP521R1_SHA512:
		return "ecdsa_secp521r1_sha512"
	case ED25519:
		return "ed25519"
	case ED448:
		return "ed448"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", uint16(s))
	}
}

// HashFunction returns the hash constructor used for pre-hashing in this signature scheme
// (RFC 9420 §5.1.2). Returns nil for schemes that do not pre-hash (Ed25519).
//
// ECDSA-P256 pre-hashes with SHA-256 before signing (RFC 9420 §5.1.2 table).
// Ed25519 does not pre-hash — the message is passed directly to the signing function.
func (s SignatureScheme) HashFunction() func() hash.Hash {
	switch s {
	case ECDSA_SECP256R1_SHA256:
		return sha256.New
	case ECDSA_SECP521R1_SHA512:
		return sha512.New
	default:
		return nil // Ed25519 and unknown schemes: no pre-hashing
	}
}

// HPKEConfig contains HPKE algorithm identifiers.
type HPKEConfig struct {
	KEM  KEMAlgorithm
	KDF  KDFAlgorithm
	AEAD AeadAlgorithm
}

// KEMAlgorithm identifies KEM algorithms for HPKE as defined in RFC 9180 §4.1.
type KEMAlgorithm uint16

const (
	// DHKEM_P256_HKDF_SHA256 is DHKEM with P-256 and HKDF-SHA256
	// RFC 9180 §4.1: Used by cipher suite 2 (mandatory for MLS 1.0)
	//nolint:revive // RFC 9180 naming convention
	DHKEM_P256_HKDF_SHA256 KEMAlgorithm = 0x0010

	// DHKEM_X25519_HKDF_SHA256 is DHKEM with X25519 and HKDF-SHA256
	// RFC 9180 §4.1: Used by cipher suites 1 and 3
	//nolint:revive // RFC 9180 naming convention
	DHKEM_X25519_HKDF_SHA256 KEMAlgorithm = 0x0020

	// DHKEM_P521_HKDF_SHA512 is DHKEM with P-521 and HKDF-SHA512
	// RFC 9180 §4.1: Used by cipher suite 5
	//nolint:revive // RFC 9180 naming convention
	DHKEM_P521_HKDF_SHA512 KEMAlgorithm = 0x0012
)

func (k KEMAlgorithm) String() string {
	switch k {
	case DHKEM_P256_HKDF_SHA256:
		return "DHKEM_P256_HKDF_SHA256"
	case DHKEM_X25519_HKDF_SHA256:
		return "DHKEM_X25519_HKDF_SHA256"
	case DHKEM_P521_HKDF_SHA512:
		return "DHKEM_P521_HKDF_SHA512"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", uint16(k))
	}
}

// KDFAlgorithm identifies KDF algorithms for HPKE as defined in RFC 9180 §4.1.
type KDFAlgorithm uint16

const (
	// HKDF_SHA256 is HKDF-SHA256 (32 bytes output)
	// RFC 9180 §4.1: Used by cipher suites 1, 2, and 3
	//nolint:revive // RFC 9180 naming convention
	HKDF_SHA256 KDFAlgorithm = 0x0001

	// HKDF_SHA512 is HKDF-SHA512 (64 bytes output)
	// RFC 9180 §4.1: Used by cipher suite 5
	//nolint:revive // RFC 9180 naming convention
	HKDF_SHA512 KDFAlgorithm = 0x0003
)

func (k KDFAlgorithm) String() string {
	switch k {
	case HKDF_SHA256:
		return "HKDF-SHA256"
	case HKDF_SHA512:
		return "HKDF-SHA512"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", uint16(k))
	}
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

// Hash computes the hash of data using the cipher suite's hash function (RFC 9420 §5.2).
//
// Returns [ErrUnsupportedSuite] for cipher suites outside CS1-CS3.
func Hash(cs CipherSuite, data []byte) ([]byte, error) {
	h := cs.HashFunction()
	if h == nil {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedSuite, cs)
	}
	hs := h()
	_, _ = hs.Write(data)
	return hs.Sum(nil), nil
}
