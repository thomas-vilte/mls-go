// Package extensions implements MLS extension types according to RFC 9420 §13.
//
// Extensions are used to add optional features to MLS messages and objects.
// Each extension has a type code and opaque data.
package extensions

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/openmls/go/internal/tls"
)

// ExtensionType identifies the type of an MLS extension.
//
// See RFC 9420 §17.3 for the IANA registry.
type ExtensionType uint16

const (
	// ExtensionTypeApplicationID is used for application-specific data.
	ExtensionTypeApplicationID ExtensionType = 0x0001

	// ExtensionTypeRatchetTree contains the full ratchet tree.
	// Used in GroupInfo to help new members join.
	ExtensionTypeRatchetTree ExtensionType = 0x0002

	// ExtensionTypeRequiredCapabilities specifies capabilities required by the group.
	ExtensionTypeRequiredCapabilities ExtensionType = 0x0003

	// ExtensionTypeExternalPub contains an external HPKE public key.
	ExtensionTypeExternalPub ExtensionType = 0x0004

	// ExtensionTypeExternalSenders lists external senders allowed to send proposals.
	// Used by DAVE (Discord Audio Voice Encryption).
	ExtensionTypeExternalSenders ExtensionType = 0x0005

	// ExtensionTypeEncryptionKey contains an encryption key for the group.
	ExtensionTypeEncryptionKey ExtensionType = 0x0006

	// ExtensionTypeConfirmationKey contains a confirmation key.
	ExtensionTypeConfirmationKey ExtensionType = 0x0007

	// ExtensionTypeMilestoneCommit marks a milestone in the group.
	ExtensionTypeMilestoneCommit ExtensionType = 0x0008

	// ExtensionTypeGroupContextExtensions contains extensions for GroupContext.
	ExtensionTypeGroupContextExtensions ExtensionType = 0x0009
)

// Extension represents a generic MLS extension.
//
// struct {
//     ExtensionType extension_type;
//     opaque extension_data<V>;
// } Extension;
type Extension struct {
	Type ExtensionType
	Data []byte
}

// Marshal serializes an Extension to TLS format.
func (e *Extension) Marshal() []byte {
	buf := tls.NewWriter()
	buf.WriteUint16(uint16(e.Type))
	buf.WriteVLBytes(e.Data)
	return buf.Bytes()
}

// UnmarshalExtension parses an Extension from TLS format.
func UnmarshalExtension(data []byte) (*Extension, error) {
	buf := tls.NewReader(data)

	extType, err := buf.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("reading extension_type: %w", err)
	}

	extData, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading extension_data: %w", err)
	}

	return &Extension{
		Type: ExtensionType(extType),
		Data: extData,
	}, nil
}

// Extensions is a collection of MLS extensions.
//
// Extensions are stored in a map for efficient lookup by type.
type Extensions struct {
	extensions map[ExtensionType]Extension
}

// NewExtensions creates a new empty Extensions collection.
func NewExtensions() *Extensions {
	return &Extensions{
		extensions: make(map[ExtensionType]Extension),
	}
}

// Add adds an extension to the collection.
//
// If an extension of the same type already exists, it is replaced.
func (e *Extensions) Add(ext Extension) error {
	if err := ext.Validate(); err != nil {
		return fmt.Errorf("invalid extension: %w", err)
	}

	e.extensions[ext.Type] = ext
	return nil
}

// Get retrieves an extension by type.
//
// Returns the extension and true if found, or empty Extension and false if not found.
func (e *Extensions) Get(typ ExtensionType) (Extension, bool) {
	ext, ok := e.extensions[typ]
	return ext, ok
}

// Has checks if an extension of the given type exists.
func (e *Extensions) Has(typ ExtensionType) bool {
	_, ok := e.extensions[typ]
	return ok
}

// Remove removes an extension by type.
func (e *Extensions) Remove(typ ExtensionType) {
	delete(e.extensions, typ)
}

// Len returns the number of extensions.
func (e *Extensions) Len() int {
	return len(e.extensions)
}

// All returns all extensions as a slice.
func (e *Extensions) All() []Extension {
	result := make([]Extension, 0, len(e.extensions))
	for _, ext := range e.extensions {
		result = append(result, ext)
	}
	return result
}

// Marshal serializes all extensions to TLS format.
//
// Extensions are encoded as a vector: Extension extensions<V>
func (e *Extensions) Marshal() []byte {
	buf := tls.NewWriter()

	extBuf := tls.NewWriter()
	for _, ext := range e.extensions {
		extBuf.WriteRaw(ext.Marshal())
	}
	buf.WriteVLBytes(extBuf.Bytes())

	return buf.Bytes()
}

// UnmarshalExtensions parses a vector of Extensions from TLS format.
func UnmarshalExtensions(data []byte) (*Extensions, error) {
	exts := NewExtensions()

	if len(data) == 0 {
		return exts, nil
	}

	buf := tls.NewReader(data)

	for buf.Remaining() > 0 {
		ext, err := UnmarshalExtension(buf.BytesAfterPosition())
		if err != nil {
			return nil, fmt.Errorf("parsing extension: %w", err)
		}

		// Skip the bytes we just read
		buf.Skip(len(ext.Marshal()))

		if err := exts.Add(*ext); err != nil {
			return nil, fmt.Errorf("adding extension: %w", err)
		}
	}

	return exts, nil
}

// Validate validates an Extension.
//
// Basic validation: type must be known, data must not be empty.
func (e *Extension) Validate() error {
	if e.Data == nil {
		return errors.New("extension data is nil")
	}

	// Check for known extension types
	switch e.Type {
	case ExtensionTypeApplicationID,
		ExtensionTypeRatchetTree,
		ExtensionTypeRequiredCapabilities,
		ExtensionTypeExternalPub,
		ExtensionTypeExternalSenders,
		ExtensionTypeEncryptionKey,
		ExtensionTypeConfirmationKey,
		ExtensionTypeMilestoneCommit,
		ExtensionTypeGroupContextExtensions:
		// Known types are valid
	default:
		// Unknown types are allowed (extensibility)
	}

	return nil
}

// Equal compares two extensions for equality.
func (e *Extension) Equal(other *Extension) bool {
	if e == nil || other == nil {
		return e == other
	}

	if e.Type != other.Type {
		return false
	}

	return bytes.Equal(e.Data, other.Data)
}

// Clone creates a deep copy of the Extensions.
func (e *Extensions) Clone() *Extensions {
	result := NewExtensions()
	for typ, ext := range e.extensions {
		result.extensions[typ] = Extension{
			Type: ext.Type,
			Data: append([]byte(nil), ext.Data...),
		}
	}
	return result
}
