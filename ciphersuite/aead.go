// Package ciphersuite provides AEAD encryption/decryption functions.
package ciphersuite

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// AESEncrypt encrypts plaintext using AES-128-GCM (RFC 9420 §5.1).
//
// key must be 16 bytes (AES-128). nonce must be 12 bytes (GCM standard).
// Returns [ErrInvalidKeyLength] or [ErrInvalidNonceLength] for wrong sizes.
func AESEncrypt(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("%w: AES-128 requires 16 bytes, got %d", ErrInvalidKeyLength, len(key))
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("%w: AES-GCM requires 12 bytes, got %d", ErrInvalidNonceLength, len(nonce))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	// Seal appends the ciphertext to the destination
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nil
}

// AESDecrypt decrypts ciphertext using AES-128-GCM (RFC 9420 §5.1).
//
// key must be 16 bytes (AES-128). nonce must be 12 bytes (GCM standard).
// Returns [ErrInvalidKeyLength] or [ErrInvalidNonceLength] for wrong sizes.
// Returns [ErrAeadDecryption] if the ciphertext has been tampered with.
func AESDecrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("%w: AES-128 requires 16 bytes, got %d", ErrInvalidKeyLength, len(key))
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("%w: AES-GCM requires 12 bytes, got %d", ErrInvalidNonceLength, len(nonce))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	// Open decrypts the ciphertext in place
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAeadDecryption, err)
	}

	return plaintext, nil
}

// EncryptWithCipherSuite encrypts plaintext using the AEAD algorithm of the given cipher suite.
//
// Selects AES-128-GCM (CS1, CS2) or ChaCha20-Poly1305 (CS3) as defined in RFC 9420 §5.1.
//
// key must be cs.AeadKeyLength() bytes; nonce must be cs.AeadNonceLength() bytes (12).
// Returns [ErrInvalidKeyLength] or [ErrInvalidNonceLength] for wrong sizes.
func EncryptWithCipherSuite(key, nonce, plaintext, aad []byte, cs CipherSuite) ([]byte, error) {
	if keyLen := cs.AeadKeyLength(); keyLen == 0 {
		return nil, fmt.Errorf("unsupported cipher suite %d", cs)
	} else if len(key) != keyLen {
		return nil, fmt.Errorf("%w: cipher suite %d requires %d bytes, got %d", ErrInvalidKeyLength, cs, keyLen, len(key))
	}
	if nonceLen := cs.AeadNonceLength(); len(nonce) != nonceLen {
		return nil, fmt.Errorf("%w: requires %d bytes, got %d", ErrInvalidNonceLength, nonceLen, len(nonce))
	}
	switch cs.AeadAlgorithm() {
	case AES128GCM:
		return AESEncrypt(key, nonce, plaintext, aad)
	case ChaCha20Poly1305:
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidKeyLength, err)
		}
		return aead.Seal(nil, nonce, plaintext, aad), nil
	default:
		return nil, fmt.Errorf("unsupported AEAD algorithm for cipher suite %d", cs)
	}
}

// DecryptWithCipherSuite decrypts ciphertext using the AEAD algorithm of the given cipher suite.
//
// Selects AES-128-GCM (CS1, CS2) or ChaCha20-Poly1305 (CS3) as defined in RFC 9420 §5.1.
//
// key must be cs.AeadKeyLength() bytes; nonce must be cs.AeadNonceLength() bytes (12).
// Returns [ErrInvalidKeyLength] or [ErrInvalidNonceLength] for wrong sizes.
// Returns [ErrAeadDecryption] if the ciphertext has been tampered with or the key is wrong.
func DecryptWithCipherSuite(key, nonce, ciphertext, aad []byte, cs CipherSuite) ([]byte, error) {
	if keyLen := cs.AeadKeyLength(); keyLen == 0 {
		return nil, fmt.Errorf("unsupported cipher suite %d", cs)
	} else if len(key) != keyLen {
		return nil, fmt.Errorf("%w: cipher suite %d requires %d bytes, got %d", ErrInvalidKeyLength, cs, keyLen, len(key))
	}
	if nonceLen := cs.AeadNonceLength(); len(nonce) != nonceLen {
		return nil, fmt.Errorf("%w: requires %d bytes, got %d", ErrInvalidNonceLength, nonceLen, len(nonce))
	}
	switch cs.AeadAlgorithm() {
	case AES128GCM:
		return AESDecrypt(key, nonce, ciphertext, aad)
	case ChaCha20Poly1305:
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidKeyLength, err)
		}
		plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrAeadDecryption, err)
		}
		return plaintext, nil
	default:
		return nil, fmt.Errorf("unsupported AEAD algorithm for cipher suite %d", cs)
	}
}
