// Package extensions - Last Resort Extension (RFC 9420 §11.2.5)
package extensions

import (
	"fmt"

	"github.com/mls-go/internal/tls"
)

// LastResortExtension marks a KeyPackage for "last resort" use.
//
// Per RFC 9420 §11.2.5, this extension marks KeyPackages that should only
// be used when no other KeyPackages are available.
//
// # Structure (RFC 9420 §11.2.5)
//
// ```text
// ┌─────────────────────────────────────────┐
// │    LastResortExtension                  │
// ├─────────────────────────────────────────┤
// │  (no data - marker only)                │
// └─────────────────────────────────────────┘
// ```
//
// # Location
//
// - KeyPackage: Yes
// - GroupInfo: No
// - GroupContext: No
//
// # Usage Flow
//
// ```text
// ┌─────────────────────────────────────────────────────────────┐
// │  1. Client generates normal KeyPackages                     │
// │  2. Client generates "last resort" KeyPackages              │
// │  3. Upload both to delivery service                         │
// │  4. DS uses normal KeyPackages first                        │
// │  5. If exhausted, uses "last resort" KeyPackages            │
// └─────────────────────────────────────────────────────────────┘
// ```
//
// # Example
//
// // Create last resort extension
// ext := NewLastResortExtension()
//
// // Validate (always succeeds - no data to validate)
//
//	if err := ext.Validate(); err != nil {
//	    return err
//	}
//
// // Convert to generic extension
// genericExt, err := ext.ToExtension()
//
//	if err != nil {
//	    return err
//	}
//
// # RFC Compliance
//
// RFC 9420 §11.2.5:
// "The LastResort extension is used to mark KeyPackages that should
// only be used as a last resort, when no other KeyPackages are available."
type LastResortExtension struct {
	// No data - presence of the extension indicates "last resort"
}

// NewLastResortExtension creates a LastResortExtension.
func NewLastResortExtension() *LastResortExtension {
	return &LastResortExtension{}
}

// Marshal serializes the extension to TLS format.
//
// Since LastResortExtension has no data, it marshals to empty bytes.
//
// ```text
// ┌─────────────────────────────────────────┐
// │  extension_data_length: varint = 0      │
// └─────────────────────────────────────────┘
// ```
func (l *LastResortExtension) Marshal() []byte {
	buf := tls.NewWriter()
	buf.WriteVLBytes([]byte{}) // Empty data
	return buf.Bytes()
}

// UnmarshalLastResortExtension parses a LastResortExtension from TLS.
//
// Reads empty extension data (no data to parse).
func UnmarshalLastResortExtension(_ []byte) (*LastResortExtension, error) {
	return NewLastResortExtension(), nil
}

// Validate validates the extension.
//
// LastResortExtension is always valid (has no data).
func (l *LastResortExtension) Validate() error {
	return nil
}

// Equal compares two LastResortExtension instances.
//
// All LastResortExtension instances are equal (no data).
func (l *LastResortExtension) Equal(_ *LastResortExtension) bool {
	return true
}

// ToExtension converts to a generic Extension.
func (l *LastResortExtension) ToExtension() (*Extension, error) {
	data := l.Marshal()
	return &Extension{
		Type: ExtensionTypeLastResort,
		Data: data,
	}, nil
}

// FromLastResortExtension creates a LastResortExtension from a generic Extension.
//
// Returns error if Type is not ExtensionTypeLastResort.
func FromLastResortExtension(ext *Extension) (*LastResortExtension, error) {
	if ext.Type != ExtensionTypeLastResort {
		return nil, fmt.Errorf("wrong extension type: %d", ext.Type)
	}
	return UnmarshalLastResortExtension(ext.Data)
}

// String returns a human-readable representation.
func (l *LastResortExtension) String() string {
	return "LastResortExtension"
}

// Len returns the length of the extension data (always 0).
func (l *LastResortExtension) Len() int {
	return 0
}
