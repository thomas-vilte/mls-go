// Package ciphersuite implements nonce reuse protection per RFC 9420 §9.1.
package ciphersuite

import (
	"crypto/rand"
	"fmt"
)

// ReuseGuardBytes is the size of the reuse guard in bytes (RFC 9420 §9.1).
const ReuseGuardBytes = 4

// ReuseGuard protects against nonce reuse as defined in RFC 9420 §9.1.
//
// When encrypting with AEAD, MLS XORs the nonce with a random 4-byte reuse guard
// to prevent nonce reuse even if the same secret and generation are used:
//
//	actual_nonce = nonce XOR (0x00...00 || reuse_guard)
//
// This is critical for security because AEAD nonce reuse compromises confidentiality.
//
// See also: RFC 9420 §9.1 for nonce reuse mitigation
type ReuseGuard struct {
	value [ReuseGuardBytes]byte
}

// NewReuseGuardRandom generates a random reuse guard.
func NewReuseGuardRandom() (*ReuseGuard, error) {
	var rg ReuseGuard
	if _, err := rand.Read(rg.value[:]); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInsufficientRandom, err)
	}
	return &rg, nil
}

// NewReuseGuardFromBytes creates a reuse guard from bytes.
func NewReuseGuardFromBytes(b []byte) (*ReuseGuard, error) {
	if len(b) != ReuseGuardBytes {
		return nil, fmt.Errorf("invalid reuse guard length: got %d, want %d", len(b), ReuseGuardBytes)
	}
	var rg ReuseGuard
	copy(rg.value[:], b)
	return &rg, nil
}

// AsSlice returns the guard value.
func (rg *ReuseGuard) AsSlice() []byte {
	return rg.value[:]
}
