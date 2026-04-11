// Package ciphersuite defines errors returned by crypto operations.
package ciphersuite

import "errors"

// Sentinel errors for AEAD operations.
var (
	ErrAeadDecryption     = errors.New("ciphersuite: AEAD decryption failed")
	ErrInvalidKeyLength   = errors.New("ciphersuite: invalid key length")
	ErrInvalidNonceLength = errors.New("ciphersuite: invalid nonce length")
)

// Randomness errors.
var (
	// ErrInsufficientRandom indicates a system-level RNG failure.
	ErrInsufficientRandom = errors.New("ciphersuite: insufficient randomness")
)

// Signature errors.
var (
	ErrInvalidSignature  = errors.New("ciphersuite: invalid signature")
	ErrSigningError      = errors.New("ciphersuite: signature generation failed")
	ErrVerificationError = errors.New("ciphersuite: signature verification failed")
)

// Length errors.
var (
	ErrInvalidLength    = errors.New("ciphersuite: invalid length")
	ErrKdfLabelTooLarge = errors.New("ciphersuite: KDF label too large (max 65535)")
)

// Cipher suite errors.
var (
	// ErrUnsupportedSuite means the requested suite isn't implemented.
	// Supported: CS1 (X25519/AES), CS2 (P256/AES), CS3 (X25519/ChaCha).
	ErrUnsupportedSuite = errors.New("ciphersuite: unsupported cipher suite")
)
