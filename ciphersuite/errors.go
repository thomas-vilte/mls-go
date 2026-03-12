// Copyright 2024 MLS-Go Authors. All rights reserved.
// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE file.

// Package ciphersuite implements standard errors for cryptographic operations.
//
// These errors follow Go's sentinel error pattern and should be used with
// errors.Is() and errors.As() for error verification.
package ciphersuite

import "errors"

// AEAD errors
var (
	// ErrAeadDecryption occurs when AEAD decryption fails.
	// This can happen with wrong key, tampered ciphertext, or invalid nonce.
	ErrAeadDecryption = errors.New("ciphersuite: AEAD decryption failed")

	// ErrInvalidKeyLength occurs when a cryptographic key has invalid length.
	// Check the algorithm requirements for the expected key size.
	ErrInvalidKeyLength = errors.New("ciphersuite: invalid key length")

	// ErrInvalidNonceLength occurs when a nonce has invalid length.
	// AES-GCM and ChaCha20-Poly1305 require 12-byte nonces.
	ErrInvalidNonceLength = errors.New("ciphersuite: invalid nonce length")
)

// Randomness errors
var (
	// ErrInsufficientRandom occurs when cryptographic randomness generation fails.
	// This is a critical error that indicates a system-level problem.
	ErrInsufficientRandom = errors.New("ciphersuite: insufficient randomness")
)

// Signature errors
var (
	// ErrInvalidSignature occurs when signature verification fails.
	// This indicates either tampering or wrong key.
	ErrInvalidSignature = errors.New("ciphersuite: invalid signature")

	// ErrSigningError occurs when signature generation fails.
	// This is typically a cryptographic library error.
	ErrSigningError = errors.New("ciphersuite: signature generation failed")

	// ErrVerificationError occurs when signature verification fails.
	// See ErrInvalidSignature for details.
	ErrVerificationError = errors.New("ciphersuite: signature verification failed")
)

// Length errors
var (
	// ErrInvalidLength occurs when a provided length is invalid.
	// This can happen with output lengths that are too large or negative.
	ErrInvalidLength = errors.New("ciphersuite: invalid length")

	// ErrKdfLabelTooLarge occurs when a KDF label exceeds maximum size.
	// RFC 9420 §8 limits labels to 65535 bytes.
	ErrKdfLabelTooLarge = errors.New("ciphersuite: KDF label too large")
)

// Serialization errors
var (
	// ErrKdfSerializationError occurs when KDF label serialization fails.
	// This is typically an internal error.
	ErrKdfSerializationError = errors.New("ciphersuite: KDF serialization error")

	// ErrTLSSerializationError occurs when TLS serialization fails.
	// This indicates invalid data structure for TLS encoding.
	ErrTLSSerializationError = errors.New("ciphersuite: TLS serialization error")
)

// Crypto library errors
var (
	// ErrCryptoLibraryError occurs when an underlying crypto operation fails.
	// This is a generic wrapper for crypto library errors.
	ErrCryptoLibraryError = errors.New("ciphersuite: crypto library error")

	// ErrHKDFExpand occurs when HKDF-Expand operation fails.
	// This typically indicates output length too large.
	ErrHKDFExpand = errors.New("ciphersuite: HKDF expand failed")

	// ErrHKDFExtract occurs when HKDF-Extract operation fails.
	// This is typically an internal error.
	ErrHKDFExtract = errors.New("ciphersuite: HKDF extract failed")
)
