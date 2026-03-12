// Package ciphersuite implements MAC operations per RFC 9420 §6.1.
package ciphersuite

// Mac represents a Message Authentication Code as defined in RFC 9420 §6.1.
//
// MACs are used in MLS for:
//   - Membership tags (RFC 9420 §6.1)
//   - External sender authentication (RFC 9420 §12.1)
//
// The MAC is computed using HMAC-SHA256:
//
//	MAC = HMAC(secret, message)
//
// See also: RFC 9420 §6.1 for MAC usage in MLS framing
type Mac struct {
	Value []byte
}

// NewMac creates a new MAC.
func NewMac(value []byte) *Mac {
	return &Mac{Value: value}
}

// AsSlice returns the MAC value.
func (m *Mac) AsSlice() []byte {
	return m.Value
}

// Equal performs constant-time comparison.
func (m *Mac) Equal(other *Mac) bool {
	return EqualCT(m.Value, other.Value)
}

// ComputeMac computes a MAC using HMAC-SHA256.
//
// MAC = HMAC(secret, message)
func ComputeMac(key *Secret, message []byte) (*Mac, error) {
	macValue, err := key.Hmac(message)
	if err != nil {
		return nil, err
	}
	return NewMac(macValue), nil
}
