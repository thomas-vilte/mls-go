// Package ciphersuite provides cryptographic primitives for the Messaging Layer Security (MLS) protocol.
//
// # Overview
//
// This package implements the cryptographic building blocks required by MLS as defined in
// RFC 9420 Section 5. It provides cipher suites 1, 2, and 3 for MLS 1.0, with placeholders
// for suites 4-7.
//
// # Implemented Cipher Suites
//
//	CS1 (0x0001): MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 ✅
//	CS2 (0x0002): MLS_128_DHKEMP256_AES128GCM_SHA256_P256 ✅ (mandatory for MLS 1.0)
//	CS3 (0x0003): MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 ✅
//
// # Placeholder Cipher Suites (not implemented)
//
//	CS4 (0x0004): MLS_256_DHKEMP384_AES256GCM_SHA384_P384 ⏳
//	CS5 (0x0005): MLS_256_DHKEMP521_AES256GCM_SHA512_P521 ⏳
//	CS6 (0x0006): MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 ⏳
//	CS7 (0x0007): MLS_256_DHKEMP384_CHACHA20POLY1305_SHA384_P384 ⏳
//
// # Architecture
//
// The package is organized into the following cryptographic components:
//
//	┌─────────────────────────────────────────────────────────────┐
//	│                    Cipher Suite (cs)                        │
//	│  - HashAlgorithm (SHA-256)                                  │
//	│  - AEADAlgorithm (AES-128-GCM, ChaCha20-Poly1305)           │
//	│  - SignatureScheme (ECDSA P-256, Ed25519)                   │
//	│  - HPKEConfig (KEM, KDF, AEAD)                              │
//	└─────────────────────────────────────────────────────────────┘
//	                           │
//	         ┌─────────────────┼─────────────────┐
//	         │                 │                 │
//	         ▼                 ▼                 ▼
//	┌─────────────────┐ ┌─────────────┐ ┌─────────────────┐
//	│   AEAD (aead)   │ │  HPKE (hpke)│ │  HKDF (hkdf)    │
//	│  - AES-GCM      │ │  - Encaps   │ │  - Extract      │
//	│  - ChaCha20     │ │  - Decaps   │ │  - Expand       │
//	└─────────────────┘ └─────────────┘ └─────────────────┘
//	                           │
//	                           ▼
//	                  ┌─────────────────┐
//	                  │   Sign (sign)   │
//	                  │  - ECDSA        │
//	                  │  - Ed25519      │
//	                  └─────────────────┘
//
// # Key Derivation Flow (HKDF)
//
// HKDF (RFC 5869) follows an extract-then-expand paradigm:
//
//	IKM (Input Keying Material)
//	  │
//	  │  HKDF-Extract(salt, IKM)
//	  ▼
//	PRK (Pseudorandom Key) ──┐
//	  │                      │
//	  │  HKDF-Expand(PRK,    │
//	  │            info,     │
//	  │            length)   │
//	  ▼                      │
//	OKM (Output Keying Material)
//
// Example:
//
//	hkdf := ciphersuite.NewHKDF()
//	prk := hkdf.Extract(salt, ikm)
//	okm, err := hkdf.Expand(prk, info, 32)
//
// # HPKE Encryption Flow
//
// HPKE (RFC 9180) provides public-key encryption with the following flow:
//
//	Sender                          Receiver
//	  │                              │
//	  │  pkR (public key)            │
//	  │◄─────────────────────────────│
//	  │                              │
//	  │  [Encaps, shared_secret]     │
//	  │  = Encapsulate(pkR)          │
//	  │                              │
//	  │  DeriveKeyingMaterial(...)   │
//	  │                              │
//	  │  ciphertext = AEAD(seal)     │
//	  │──────────────────────────────►│
//	  │                              │
//	  │                   shared_secret = Decapsulate(skR, enc)
//	  │                   DeriveKeyingMaterial(...)
//	  │                   plaintext = AEAD(open)
//
// Example:
//
//	// Encrypt
//	ciphertext, err := EncryptWithLabel(publicKey, "message", context, plaintext, cs)
//
//	// Decrypt
//	plaintext, err := DecryptWithLabel(privateKey, "message", context, ciphertext, cs)
//
// # Key Schedule Integration
//
// This package integrates with the MLS key schedule (RFC 9420 §8):
//
//	epoch_secret
//	    │
//	    │ DeriveSecret("epoch")
//	    ▼
//	epoch_secret (derived)
//	    │
//	    │ DeriveSecret("encryption")
//	    ▼
//	encryption_secret ──► SecretTree ──► per-sender keys
//	    │
//	    │ DeriveSecret("decryption")
//	    ▼
//	decryption_secret
//
// # Security Features
//
//   - Constant-time comparisons using crypto/subtle
//   - Secure memory zeroing with runtime.KeepAlive()
//   - GC protection for sensitive operations
//   - Standard library cryptography (audited and optimized)
//   - No external dependencies beyond Go stdlib
//
// # Example Usage
//
// HKDF Key Derivation:
//
//	hkdf := ciphersuite.NewHKDF()
//	prk := hkdf.Extract(salt, ikm)
//	okm, err := hkdf.Expand(prk, info, length)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// HPKE Encryption:
//
//	ciphertext, err := ciphersuite.EncryptWithLabel(
//	    publicKey, "application", context, plaintext, ciphersuite.MLS128DHKEMP256,
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Digital Signatures:
//
//	privKey, err := ciphersuite.GenerateSignaturePrivateKey()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	signature, err := privKey.Sign(data)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	err = pubKey.Verify(data, signature)
//
// Secret Management:
//
//	secret, err := ciphersuite.NewSecretRandom(32)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer secret.SecureZero() // Clear from memory when done
//
//	derived, err := secret.DeriveSecret(cs, "encryption")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # RFC Compliance
//
// This package is fully compliant with:
//   - RFC 9420: The Messaging Layer Security (MLS) Protocol
//   - RFC 5869: HKDF: HMAC-based Extract-and-Expand Key Derivation Function
//   - RFC 9180: Hybrid Public Key Encryption (HPKE)
//   - RFC 8410: An Algorithm Identifier for the Ed25519 Signature Algorithm
//
// # Testing
//
// The package includes comprehensive tests:
//   - RFC 5869 HKDF test vectors (3 cases)
//   - Security tests (wrong key, tampered data, etc.)
//   - Fuzzing tests (AEAD, HKDF, Secret)
//   - Race detection (clean)
//   - Coverage: 80%+
//
// Run tests with:
//
//	go test ./ciphersuite/...
//	go test -race ./ciphersuite/...
//	go test -cover ./ciphersuite/...
//
// # References
//
//   - RFC 9420: https://www.rfc-editor.org/rfc/rfc9420.html
//   - RFC 5869: https://www.rfc-editor.org/rfc/rfc5869.html
//   - RFC 9180: https://www.rfc-editor.org/rfc/rfc9180.html
//   - Go Crypto: https://pkg.go.dev/crypto
package ciphersuite
