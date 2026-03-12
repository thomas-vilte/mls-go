// Package ciphersuite implements HKDF operations according to RFC 5869.
package ciphersuite

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// HKDF implements HKDF-Extract-Expand per RFC 5869 using SHA-256.
//
// HKDF (HMAC-based Key Derivation Function) is a key derivation function
// that follows the "extract-then-expand" paradigm as defined in RFC 5869 §2.
// It is used extensively in MLS for:
//   - Key schedule (RFC 9420 §8)
//   - Secret tree derivation (RFC 9420 §8.4)
//   - HPKE key derivation (RFC 9180 §4.1)
//
// RFC 5869: https://www.rfc-editor.org/rfc/rfc5869.html
type HKDF struct{}

// NewHKDF creates a new HKDF instance with SHA-256.
func NewHKDF() *HKDF {
	return &HKDF{}
}

// Extract extracts a pseudorandom key (PRK) from input keying material (IKM).
//
// RFC 5869 §2.2:
//
//	PRK = HMAC-Hash(salt, IKM)
//
// Parameters:
//   - salt: optional salt value (if nil, uses zeros of hash length)
//   - ikm: Input Keying Material
//
// Returns:
//   - PRK: Pseudorandom Key (32 bytes for SHA-256)
//
// Security note: The salt should be at least HashLen bytes for optimal security.
// If salt is not available, passing nil is acceptable (uses zeros).
func (h *HKDF) Extract(salt, ikm []byte) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}

	hmacHash := hmac.New(sha256.New, salt)
	hmacHash.Write(ikm)
	return hmacHash.Sum(nil)
}

// Expand expands PRK to output keying material (OKM) of desired length.
//
// RFC 5869 §2.3:
//
//	OKM = T(1) | T(2) | T(3) | ... | T(N)
//	where T(0) = empty string
//	      T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
//	      T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
//	      ...
//
// Parameters:
//   - prk: Pseudorandom Key (from Extract)
//   - info: optional context (can be empty)
//   - length: desired length in bytes (max 255 * HashLength)
//
// Returns:
//   - OKM: Output Keying Material
//   - error: if length is too large (> 255 * HashLen per RFC 5869 §2.3)
//
// Security note: The info parameter provides context for key derivation.
// It should include protocol identifiers, version numbers, etc. to ensure
// domain separation.
func (h *HKDF) Expand(prk, info []byte, length int) ([]byte, error) {
	if length > 255*sha256.Size {
		return nil, fmt.Errorf("hkdf: output length too large: %d (max %d)", length, 255*sha256.Size)
	}

	// Go 1.24+: hkdf.Expand usa generics con hash.Hash
	okm, err := hkdf.Expand(sha256.New, prk, string(info), length)
	if err != nil {
		return nil, fmt.Errorf("hkdf expand: %w", err)
	}

	return okm, nil
}

// ExtractExpand combines Extract and Expand in a single operation.
// Useful when you don't need the intermediate PRK.
func (h *HKDF) ExtractExpand(salt, ikm, info []byte, length int) ([]byte, error) {
	prk := h.Extract(salt, ikm)
	return h.Expand(prk, info, length)
}

// hkdfExtract is a helper function for compatibility with existing code.
// Uses the standard crypto/hkdf implementation.
func hkdfExtract(salt, ikm []byte) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}

	hmacHash := hmac.New(sha256.New, salt)
	hmacHash.Write(ikm)
	return hmacHash.Sum(nil)
}

// hkdfExpand is a helper function for compatibility with existing code.
// Uses the standard crypto/hkdf implementation.
func hkdfExpand(prk, info []byte, length int) ([]byte, error) {
	if length > 255*sha256.Size {
		return nil, fmt.Errorf("hkdf: output length too large: %d", length)
	}

	// Go 1.24+: hkdf.Expand uses generics with hash.Hash
	okm, err := hkdf.Expand(sha256.New, prk, string(info), length)
	if err != nil {
		return nil, fmt.Errorf("hkdf expand: %w", err)
	}

	return okm, nil
}

// hmacSha256 computes HMAC-SHA256 using the standard library.
// This implementation replaces the manual version prone to errors.
func hmacSha256(key, message []byte) []byte {
	hmacHash := hmac.New(sha256.New, key)
	hmacHash.Write(message)
	return hmacHash.Sum(nil)
}
