// Package extensions - Application ID Extension (RFC 9420 §5.3.3)
package extensions

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/thomas-vilte/mls-go/internal/tls"
)

// ApplicationIDExtension adds an application-specific identifier to a KeyPackage.
//
// Per RFC 9420 §5.3.3, this extension identifies the application or service
// using the MLS client. Useful when multiple apps share MLS infrastructure.
//
// # Structure (RFC 9420 §5.3.3)
//
// ```text
// ┌─────────────────────────────────────────┐
// │    ApplicationIDExtension               │
// ├─────────────────────────────────────────┤
// │  application_id: opaque<V>              │
// └─────────────────────────────────────────┘
// ```
//
// # Location
//
// - KeyPackage: Yes
// - LeafNode: Yes
// - GroupInfo: No
// - GroupContext: No
//
// # Common Formats
//
// - UTF-8 string: "com.example.chat", "discord-voice"
// - Reverse DNS: "com.company.app" (recommended)
// - Arbitrary bytes: app-specific binary identifiers
//
// # Example
//
// // Create from bytes
// ext := NewApplicationIDExtension([]byte("my-app-identifier"))
//
// // Create from string
// ext := NewApplicationIDExtensionFromString("com.example.chat")
//
// // Validate
//
//	if err := ext.Validate(); err != nil {
//	    return err
//	}
//
// // Serialize
// data := ext.Marshal()
//
// # RFC Compliance
//
// RFC 9420 §5.3.3:
// "The ApplicationId extension allows applications to add an explicit,
// application-defined identifier to a KeyPackage."
type ApplicationIDExtension struct {
	ApplicationID []byte // Application identifier (opaque<V>)
}

// NewApplicationIDExtension creates an ApplicationIDExtension.
//
// The application_id can be any byte sequence up to 65535 bytes.
// Recommended format: reverse DNS ("com.example.app").
func NewApplicationIDExtension(appID []byte) *ApplicationIDExtension {
	return &ApplicationIDExtension{
		ApplicationID: appID,
	}
}

// Marshal serializes the extension to TLS format.
//
// ```text
// ┌─────────────────────────────────────────┐
// │  application_id_length: varint          │
// ├─────────────────────────────────────────┤
// │  application_id: opaque[]               │
// └─────────────────────────────────────────┘
// ```
func (a *ApplicationIDExtension) Marshal() []byte {
	buf := tls.NewWriter()
	buf.WriteVLBytes(a.ApplicationID)
	return buf.Bytes()
}

// UnmarshalApplicationIDExtension parses an ApplicationIDExtension from TLS.
//
// Reads application_id as variable-length bytes per RFC 9420 §5.3.3.
func UnmarshalApplicationIDExtension(data []byte) (*ApplicationIDExtension, error) {
	buf := tls.NewReader(data)
	appID, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading application_id: %w", err)
	}
	return &ApplicationIDExtension{
		ApplicationID: appID,
	}, nil
}

// Validate validates the extension per RFC 9420 §5.3.3.
//
// # Validation Rules
//
// - ApplicationID must not be nil
// - ApplicationID must not be empty
// - ApplicationID <= 65535 bytes (varint limit)
func (a *ApplicationIDExtension) Validate() error {
	if a.ApplicationID == nil {
		return errors.New("application_id cannot be nil")
	}
	if len(a.ApplicationID) == 0 {
		return errors.New("application_id cannot be empty")
	}
	if len(a.ApplicationID) > 65535 {
		return fmt.Errorf("application_id too long: %d bytes (max 65535)", len(a.ApplicationID))
	}
	return nil
}

// Equal compares two ApplicationIDExtension instances.
func (a *ApplicationIDExtension) Equal(other *ApplicationIDExtension) bool {
	if a == nil || other == nil {
		return a == other
	}
	return bytes.Equal(a.ApplicationID, other.ApplicationID)
}

// ToExtension converts to a generic Extension.
//
// Useful for adding to an Extensions collection.
func (a *ApplicationIDExtension) ToExtension() (*Extension, error) {
	data := a.Marshal()
	return &Extension{
		Type: ExtensionTypeApplicationID,
		Data: data,
	}, nil
}

// FromApplicationIDExtension creates an ApplicationIDExtension from a generic Extension.
//
// Returns error if Type is not ExtensionTypeApplicationID.
func FromApplicationIDExtension(ext *Extension) (*ApplicationIDExtension, error) {
	if ext.Type != ExtensionTypeApplicationID {
		return nil, fmt.Errorf("wrong extension type: %d", ext.Type)
	}
	return UnmarshalApplicationIDExtension(ext.Data)
}

// String returns the ApplicationID as a human-readable string.
//
// Attempts UTF-8 decoding. Falls back to hex if invalid UTF-8.
func (a *ApplicationIDExtension) String() string {
	if a == nil || a.ApplicationID == nil {
		return ""
	}
	if validUTF8(a.ApplicationID) {
		return string(a.ApplicationID)
	}
	return hex.EncodeToString(a.ApplicationID)
}

// Len returns the length of the ApplicationID in bytes.
func (a *ApplicationIDExtension) Len() int {
	if a == nil {
		return 0
	}
	return len(a.ApplicationID)
}

// Helper function to check valid UTF-8
func validUTF8(b []byte) bool {
	for i := 0; i < len(b); {
		c := b[i]
		if c < 0x80 {
			i++
			continue
		}
		n := utf8Len(c)
		if n == 0 || i+n > len(b) {
			return false
		}
		for j := 1; j < n; j++ {
			if b[i+j]&0xC0 != 0x80 {
				return false
			}
		}
		i += n
	}
	return true
}

func utf8Len(c byte) int {
	if c&0xE0 == 0xC0 {
		return 2
	}
	if c&0xF0 == 0xE0 {
		return 3
	}
	if c&0xF8 == 0xF0 {
		return 4
	}
	return 0
}
