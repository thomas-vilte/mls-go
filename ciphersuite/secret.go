package ciphersuite

import (
	"crypto/rand"
	"errors"
	"fmt"
	"runtime"
)

// Secret represents a secret value with secure handling
type Secret struct {
	Value []byte
}

// NewSecret creates a Secret from bytes
func NewSecret(value []byte) *Secret {
	copyBytes := make([]byte, len(value))
	copy(copyBytes, value)
	return &Secret{Value: copyBytes}
}

// NewSecretRandom generates a random Secret of the specified length.
func NewSecretRandom(length int) (*Secret, error) {
	value := make([]byte, length)
	if _, err := rand.Read(value); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInsufficientRandom, err)
	}
	return &Secret{Value: value}, nil
}

// NewSecretRandomCS generates a random Secret with ciphersuite hash length.
func NewSecretRandomCS(ciphersuite CipherSuite) (*Secret, error) {
	return NewSecretRandom(ciphersuite.HashLength())
}

// ZeroSecret creates an all-zero Secret of given length.
func ZeroSecret(length int) *Secret {
	return &Secret{Value: make([]byte, length)}
}

// ZeroSecretCS creates an all-zero Secret with ciphersuite hash length.
func ZeroSecretCS(ciphersuite CipherSuite) *Secret {
	return ZeroSecret(ciphersuite.HashLength())
}

// FromSlice creates a Secret from a byte slice.
func (s *Secret) FromSlice(bytes []byte) *Secret {
	return NewSecret(bytes)
}

// AsSlice returns the secret value as a byte slice.
func (s *Secret) AsSlice() []byte {
	if s == nil {
		return nil
	}
	return s.Value
}

// Len returns the length of the secret.
func (s *Secret) Len() int {
	if s == nil || s.Value == nil {
		return 0
	}
	return len(s.Value)
}

// Clone creates a copy of the Secret.
func (s *Secret) Clone() *Secret {
	if s == nil || s.Value == nil {
		return &Secret{Value: nil}
	}
	return NewSecret(s.Value)
}

// HKDFExtract performs HKDF-Extract with this Secret as salt.
//
// CRITICAL: Uses runtime.KeepAlive() to prevent the GC from moving
// secrets before hkdfExtract completes, and to ensure SecureZero()
// is not optimized away by the compiler.
func (s *Secret) HKDFExtract(ikm *Secret) (*Secret, error) {
	if s == nil {
		return nil, fmt.Errorf("salt is nil")
	}
	if ikm == nil {
		ikm = ZeroSecret(len(s.Value))
	}

	prk := hkdfExtract(s.Value, ikm.Value)

	// CRITICAL: Keep alive until hkdfExtract completes
	runtime.KeepAlive(s)
	runtime.KeepAlive(ikm)

	// Zero out after use
	s.SecureZero()
	ikm.SecureZero()

	return NewSecret(prk), nil
}

// HKDFExpand performs HKDF-Expand with this Secret as PRK.
func (s *Secret) HKDFExpand(info []byte, length int) (*Secret, error) {
	if s == nil {
		return nil, fmt.Errorf("prk is nil")
	}
	if length <= 0 {
		return nil, ErrInvalidLength
	}

	okm, err := hkdfExpand(s.Value, info, length)
	if err != nil {
		return nil, fmt.Errorf("hkdf expand failed: %w", err)
	}
	if len(okm) == 0 {
		return nil, errors.New("ciphersuite: hkdf produced empty output")
	}

	// CRITICAL: Keep alive until hkdfExpand completes
	runtime.KeepAlive(s)

	return NewSecret(okm), nil
}

// DeriveSecret derives a new Secret with the given label as defined in RFC 9420 §8.
//
// Implements:
//
//	DeriveSecret(secret, label) = KDF-Expand-Label(secret, label, "", Hash.Length)
//
// This function is used in the MLS key schedule (RFC 9420 §8) to derive:
//   - encryption_secret
//   - decryption_secret
//   - exporter_secret
//   - epoch_authenticator
//
// See also: RFC 9420 §8.4 for secret tree derivation
func (s *Secret) DeriveSecret(ciphersuite CipherSuite, label string) (*Secret, error) {
	return s.KdfExpandLabel(label, []byte{}, ciphersuite.HashLength())
}

// KdfExpandLabel expands with a label as defined in RFC 9420 §8.
//
// Implements KDF-Expand-Label from RFC 9420 §8:
//
//	KDF-Expand-Label(secret, label, context, length) =
//	  KDF-Expand(secret, KdfLabel, length)
//
// Where KdfLabel is:
//
//	struct {
//	    uint16 length = Length;
//	    opaque label<V> = "MLS 1.0 " + Label;
//	    opaque context<V> = Context;
//	} KdfLabel;
//
// The "MLS 1.0 " prefix ensures domain separation as required by RFC 9420 §8.
func (s *Secret) KdfExpandLabel(label string, context []byte, length int) (*Secret, error) {
	if length > 65535 {
		return nil, ErrKdfLabelTooLarge
	}

	fullLabel := LabelPrefix + label
	info := SerializeKdfLabel(fullLabel, context, uint16(length))
	return s.HKDFExpand(info, length)
}

// Hmac computes HMAC with this Secret as key.
func (s *Secret) Hmac(message []byte) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("key is nil")
	}

	result := hmacSha256(s.Value, message)

	// CRITICAL: Keep alive until hmacSha256 completes
	runtime.KeepAlive(s)

	return result, nil
}

// Equal performs constant-time comparison.
func (s *Secret) Equal(other *Secret) bool {
	if s == nil || other == nil {
		return s == other
	}
	return EqualCT(s.Value, other.Value)
}

// SecureZero clears the secret value from memory.
//
// CRITICAL: Uses runtime.KeepAlive() to ensure the compiler
// does not optimize away this function (it might consider it has no side effects).
func (s *Secret) SecureZero() {
	if s != nil && s.Value != nil {
		for i := range s.Value {
			s.Value[i] = 0
		}
		// Ensure SecureZero is not optimized away
		runtime.KeepAlive(s)
	}
}
