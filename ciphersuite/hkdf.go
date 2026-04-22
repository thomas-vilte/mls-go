// Package ciphersuite implements HKDF operations according to RFC 5869.
package ciphersuite

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
)

// HKDF implements HKDF-Extract-Expand per RFC 5869, parameterized by hash function.
//
// HKDF (HMAC-based Key Derivation Function) is a key derivation function
// that follows the "extract-then-expand" paradigm as defined in RFC 5869 §2.
// It is used extensively in MLS for:
//   - Key schedule (RFC 9420 §8)
//   - Secret tree derivation (RFC 9420 §8.4)
//   - HPKE key derivation (RFC 9180 §4.1)
//
// RFC 5869: https://www.rfc-editor.org/rfc/rfc5869.html
type HKDF struct {
	hashNew func() hash.Hash
}

// NewHKDF creates a new HKDF instance with SHA-256 (default for CS1/CS2/CS3).
func NewHKDF() *HKDF {
	return &HKDF{hashNew: sha256.New}
}

// NewHKDFForCS creates an HKDF instance parameterized by the cipher suite's hash.
func NewHKDFForCS(cs CipherSuite) *HKDF {
	h := cs.HashFunction()
	if h == nil {
		h = sha256.New
	}
	return &HKDF{hashNew: h}
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
//   - PRK: Pseudorandom Key (HashLen bytes)
//
// Security note: The salt should be at least HashLen bytes for optimal security.
// If salt is not available, passing nil is acceptable (uses zeros).
func (h *HKDF) Extract(salt, ikm []byte) []byte {
	hashLen := h.hashNew().Size()
	if salt == nil {
		salt = make([]byte, hashLen)
	}

	hmacHash := hmac.New(h.hashNew, salt)
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
	maxLen := 255 * h.hashNew().Size()
	if length > maxLen {
		return nil, fmt.Errorf("hkdf: output length too large: %d (max %d)", length, maxLen)
	}

	okm, err := hkdf.Expand(h.hashNew, prk, string(info), length)
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

// hkdfExtractWithHash performs HKDF-Extract parameterized by a hash constructor.
func hkdfExtractWithHash(h func() hash.Hash, salt, ikm []byte) []byte {
	if salt == nil {
		salt = make([]byte, h().Size())
	}
	hmacHash := hmac.New(h, salt)
	hmacHash.Write(ikm)
	return hmacHash.Sum(nil)
}

// hkdfExpandWithHash performs HKDF-Expand parameterized by a hash constructor.
func hkdfExpandWithHash(h func() hash.Hash, prk, info []byte, length int) ([]byte, error) {
	maxLen := 255 * h().Size()
	if length > maxLen {
		return nil, fmt.Errorf("hkdf: output length too large: %d (max %d)", length, maxLen)
	}
	okm, err := hkdf.Expand(h, prk, string(info), length)
	if err != nil {
		return nil, fmt.Errorf("hkdf expand: %w", err)
	}
	return okm, nil
}

// hmacWithHash computes HMAC parameterized by a hash constructor.
func hmacWithHash(h func() hash.Hash, key, message []byte) []byte {
	hmacHash := hmac.New(h, key)
	hmacHash.Write(message)
	return hmacHash.Sum(nil)
}
