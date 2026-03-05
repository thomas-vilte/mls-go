// Package ciphersuite implements HKDF operations according to RFC 5869.
package ciphersuite

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// HKDF implements HKDF-Extract-Expand según RFC 5869 usando SHA-256.
//
// HKDF (HMAC-based Key Derivation Function) es una función de derivación de claves
// que sigue el paradigma "extract-then-expand". Se usa extensivamente en MLS
// para derivar secretos del key schedule.
//
// RFC 5869: https://www.rfc-editor.org/rfc/rfc5869.html
type HKDF struct{}

// NewHKDF crea una nueva instancia de HKDF con SHA-256.
func NewHKDF() *HKDF {
	return &HKDF{}
}

// Extract extrae una clave pseudorandom (PRK) desde una clave de entrada (IKM).
//
// RFC 5869 §2.2:
//
//	PRK = HMAC-Hash(salt, IKM)
//
// Parámetros:
//   - salt: valor sal opcional (si es nil, usa zeros del tamaño del hash)
//   - ikm: Input Keying Material
//
// Retorna:
//   - PRK: Pseudorandom Key (32 bytes para SHA-256)
func (h *HKDF) Extract(salt, ikm []byte) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}

	hmacHash := hmac.New(sha256.New, salt)
	hmacHash.Write(ikm)
	return hmacHash.Sum(nil)
}

// Expand expande PRK a material de clave (OKM) de longitud deseada.
//
// RFC 5869 §2.3:
//
//	OKM = T(1) | T(2) | T(3) | ... | T(N)
//	donde T(0) = empty string
//	      T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
//	      T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
//	      ...
//
// Parámetros:
//   - prk: Pseudorandom Key (de Extract)
//   - info: contexto opcional (puede ser empty)
//   - length: longitud deseada en bytes (máx 255 * HashLength)
//
// Retorna:
//   - OKM: Output Keying Material
//   - error: si length es demasiado grande
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

// ExtractExpand combina Extract y Expand en una sola operación.
// Útil cuando no necesitás el PRK intermedio.
func (h *HKDF) ExtractExpand(salt, ikm, info []byte, length int) ([]byte, error) {
	prk := h.Extract(salt, ikm)
	return h.Expand(prk, info, length)
}

// hkdfExtract es una función helper para compatibilidad con código existente.
// Usa la implementación estándar de crypto/hkdf.
func hkdfExtract(salt, ikm []byte) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}

	hmacHash := hmac.New(sha256.New, salt)
	hmacHash.Write(ikm)
	return hmacHash.Sum(nil)
}

// hkdfExpand es una función helper para compatibilidad con código existente.
// Usa la implementación estándar de crypto/hkdf.
func hkdfExpand(prk, info []byte, length int) ([]byte, error) {
	if length > 255*sha256.Size {
		return nil, fmt.Errorf("hkdf: output length too large: %d", length)
	}

	// Go 1.24+: hkdf.Expand usa generics con hash.Hash
	okm, err := hkdf.Expand(sha256.New, prk, string(info), length)
	if err != nil {
		return nil, fmt.Errorf("hkdf expand: %w", err)
	}

	return okm, nil
}

// hmacSha256 computa HMAC-SHA256 usando la standard lib.
// Esta implementación reemplaza la versión manual propensa a errores.
func hmacSha256(key, message []byte) []byte {
	hmacHash := hmac.New(sha256.New, key)
	hmacHash.Write(message)
	return hmacHash.Sum(nil)
}
