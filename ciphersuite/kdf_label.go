// Package ciphersuite implements KDF label serialization per RFC 9420 §8.
package ciphersuite

import (
	"github.com/mls-go/internal/tls"
)

// KdfLabel represents a KDF label as defined in RFC 9420 §8.
//
// This structure is used in the MLS key schedule for labeled key derivation:
//
//	struct {
//	    uint16 length = Length;
//	    opaque label<V> = "MLS 1.0 " + Label;
//	    opaque context<V> = Context;
//	} KdfLabel;
//
// The "MLS 1.0 " prefix ensures domain separation across protocol versions
// as required by RFC 9420 §8.
type KdfLabel struct {
	Length  uint16
	Label   []byte
	Context []byte
}

// NewKdfLabel creates a new KDF label.
func NewKdfLabel(label string, context []byte, length uint16) *KdfLabel {
	return &KdfLabel{
		Length:  length,
		Label:   []byte(label),
		Context: context,
	}
}

// Marshal serializes the KdfLabel to TLS format.
func (kl *KdfLabel) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteUint16(kl.Length)
	w.WriteVLBytes(kl.Label)
	w.WriteVLBytes(kl.Context)
	return w.Bytes()
}

// SerializeKdfLabel serializes a KDF label with full label string.
func SerializeKdfLabel(label string, context []byte, length uint16) []byte {
	kl := NewKdfLabel(label, context, length)
	return kl.Marshal()
}
