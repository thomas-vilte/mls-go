// Package extensions - External Pub Extension (RFC 9420 §11.2.4)
package extensions

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/thomas-vilte/mls-go/internal/tls"
)

// ExternalPubExtension contains an HPKE public key for External Commit.
//
// Per RFC 9420 §11.2.4, this extension appears in GroupInfo and provides
// the HPKE public key that new members use to encrypt their External Commit.
//
// # Structure (RFC 9420 §11.2.4)
//
// ```text
// ┌─────────────────────────────────────────┐
// │    ExternalPubExtension                 │
// ├─────────────────────────────────────────┤
// │  external_pub: HPKEPublicKey            │
// └─────────────────────────────────────────┘
// ```
//
// # Location
//
// - GroupInfo: Yes
// - KeyPackage: No
// - GroupContext: No
//
// # External Commit Flow
//
// ```text
// ┌─────────────────────────────────────────────────────────────┐
// │  1. New member obtains GroupInfo with ExternalPub           │
// │  2. Extracts external_pub from extension                    │
// │  3. Uses HPKE to encrypt Commit with external_pub           │
// │  4. Sends External Commit to group                        │
// │  5. Group processes Commit and welcomes new member          │
// └─────────────────────────────────────────────────────────────┘
// ```
//
// # HPKE Public Key Format
//
// Encoded as opaque<V> per RFC 9180. Format depends on KEM:
//
// - DHKEM P-256: 65 bytes (0x04 || X || Y)
// - DHKEM X25519: 32 bytes
//
// # Example
//
// // Create with HPKE public key
// publicKey := []byte{0x04, ...}  // 65 bytes for P-256
// ext := NewExternalPubExtension(publicKey)
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
// RFC 9420 §11.2.4:
// "The ExternalPub extension is used in GroupInfo to provide the
// information necessary for a new member to join the group via an
// External Commit."
type ExternalPubExtension struct {
	ExternalPub []byte // Encoded HPKE public key (opaque<V>)
}

// NewExternalPubExtension creates an ExternalPubExtension.
//
// The HPKE public key must be encoded per RFC 9180.
func NewExternalPubExtension(publicKey []byte) *ExternalPubExtension {
	return &ExternalPubExtension{
		ExternalPub: publicKey,
	}
}

// Marshal serializes the extension to TLS format.
//
// ```text
// ┌─────────────────────────────────────────┐
// │  external_pub_length: varint            │
// ├─────────────────────────────────────────┤
// │  external_pub: opaque[]                 │
// └─────────────────────────────────────────┘
// ```
func (e *ExternalPubExtension) Marshal() []byte {
	buf := tls.NewWriter()
	buf.WriteVLBytes(e.ExternalPub)
	return buf.Bytes()
}

// UnmarshalExternalPubExtension parses an ExternalPubExtension from TLS.
//
// Reads external_pub as variable-length bytes.
func UnmarshalExternalPubExtension(data []byte) (*ExternalPubExtension, error) {
	buf := tls.NewReader(data)
	pubKey, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading external_pub: %w", err)
	}
	return &ExternalPubExtension{
		ExternalPub: pubKey,
	}, nil
}

// Validate validates the extension.
//
// # Validation Rules
//
// - ExternalPub must not be nil
// - ExternalPub must not be empty
// - P-256 keys: 65 bytes, must start with 0x04
func (e *ExternalPubExtension) Validate() error {
	if e.ExternalPub == nil {
		return errors.New("external_pub cannot be nil")
	}
	if len(e.ExternalPub) == 0 {
		return errors.New("external_pub cannot be empty")
	}
	// Basic format check: P-256 keys start with 0x04
	if len(e.ExternalPub) == 65 && e.ExternalPub[0] != 0x04 {
		return errors.New("invalid P-256 public key format: must start with 0x04")
	}
	return nil
}

// Equal compares two ExternalPubExtension instances.
func (e *ExternalPubExtension) Equal(other *ExternalPubExtension) bool {
	if e == nil || other == nil {
		return e == other
	}
	return bytes.Equal(e.ExternalPub, other.ExternalPub)
}

// ToExtension converts to a generic Extension.
func (e *ExternalPubExtension) ToExtension() (*Extension, error) {
	data := e.Marshal()
	return &Extension{
		Type: ExtensionTypeExternalPub,
		Data: data,
	}, nil
}

// FromExternalPubExtension creates an ExternalPubExtension from a generic Extension.
//
// Returns error if Type is not ExtensionTypeExternalPub.
func FromExternalPubExtension(ext *Extension) (*ExternalPubExtension, error) {
	if ext.Type != ExtensionTypeExternalPub {
		return nil, fmt.Errorf("wrong extension type: %d", ext.Type)
	}
	return UnmarshalExternalPubExtension(ext.Data)
}

// String returns a human-readable representation.
//
// Shows first few bytes in hex format.
func (e *ExternalPubExtension) String() string {
	if e == nil || e.ExternalPub == nil {
		return "ExternalPub(nil)"
	}
	if len(e.ExternalPub) < 3 {
		return fmt.Sprintf("ExternalPub(%x)", e.ExternalPub)
	}
	return fmt.Sprintf("ExternalPub(%x...)", e.ExternalPub[:3])
}

// Len returns the length of the ExternalPub in bytes.
func (e *ExternalPubExtension) Len() int {
	if e == nil {
		return 0
	}
	return len(e.ExternalPub)
}

// IsP256 checks if the public key is a P-256 key.
//
// P-256 keys are 65 bytes and start with 0x04 (uncompressed point).
func (e *ExternalPubExtension) IsP256() bool {
	return len(e.ExternalPub) == 65 && e.ExternalPub[0] == 0x04
}

// IsX25519 checks if the public key is an X25519 key.
//
// X25519 keys are 32 bytes.
func (e *ExternalPubExtension) IsX25519() bool {
	return len(e.ExternalPub) == 32
}
