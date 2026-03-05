package ciphersuite

// Mac represents a Message Authentication Code (RFC 9420 §6.1).
//
// opaque MAC<V>;
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
