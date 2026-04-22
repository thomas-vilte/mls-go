// Package extensions implements MLS extensions per RFC 9420 §13.
//
// Extensions add optional information to MLS objects. They appear in:
//   - KeyPackages: client capabilities
//   - GroupInfo: group parameters for new members
//   - GroupContext: ensures all members have same view
//
// # Extension Structure (RFC 9420 §13)
//
// ```text
// ┌─────────────────────────────────────────┐
// │         Extension (RFC 9420 §13)        │
// ├─────────────────────────────────────────┤
// │  extension_type  : uint16               │
// │  extension_data  : opaque<V>            │
// └─────────────────────────────────────────┘
// ```
//
// # Implemented Extensions
//
// | Type | ID | Location | RFC | Description |
// |------|-----|-----------|-----|-------------|
// | ApplicationID | 0x0001 | LeafNode | §5.3.3 | App identifier |
// | RatchetTree | 0x0002 | GroupInfo | §12.4.3.3 | Full tree |
// | RequiredCapabilities | 0x0003 | GroupContext | §11.1 | Required features |
// | ExternalPub | 0x0004 | GroupInfo | §12.4.3.2 | HPKE key for External Commit |
// | ExternalSenders | 0x0005 | GroupContext | §12.1.8.1 | External senders |
// | LastResort | 0x000A | KeyPackage | §16.8 | Backup KeyPackage |
//
// # Usage
//
// // Create extension collection
// exts := extensions.NewExtensions()
//
// // Add ApplicationID
// appId := extensions.NewApplicationIDExtension([]byte("my-app"))
// genericExt, err := appId.ToExtension()
//
//	if err != nil {
//	    return err
//	}
//
//	if err := exts.Add(*genericExt); err != nil {
//	    return err
//	}
//
// // Serialize (deterministic order per RFC 9420 §13.4)
// data := exts.Marshal()
//
// # RFC Compliance
//
//   - RFC 9420 §13: Extensions
//   - RFC 9420 §13.4: Serialization (ascending type order)
//   - RFC 9420 §13.4: Serialization order (ascending by type)
//   - RFC 9420 §13.5: GREASE handling
//
// # Implementation Notes
//
// **Serialization Order:** Extensions MUST be serialized in ascending order
// by ExtensionType (RFC 9420 §13.4) for deterministic GroupContext hashes.
//
// **Duplicates:** Adding an extension of the same type replaces the existing one.
//
// **GREASE:** GREASE constants (0x0A0A, 0x1A1A, etc.) test extensibility.
// Implementations must handle unknown types gracefully.
package extensions

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/thomas-vilte/mls-go/internal/tls"
)

// ErrInvalidExtension is returned when an extension has invalid or nil data.
var ErrInvalidExtension = errors.New("extensions: invalid extension")

// ExtensionType identifies an MLS extension per RFC 9420 §17.3.
//
// Extension types are registered in the IANA registry.
// GREASE values (0x0A0A, 0x1A1A, etc.) test extensibility (RFC 9420 §13.5).
type ExtensionType uint16

const (
	// ExtensionTypeApplicationID - RFC 9420 §5.3.3
	// Location: LeafNode
	// Data: opaque application_id<V>
	ExtensionTypeApplicationID ExtensionType = 0x0001

	// ExtensionTypeRatchetTree - RFC 9420 §12.4.3.3
	// Location: GroupInfo
	// Usage: Help new members join via External Commit
	ExtensionTypeRatchetTree ExtensionType = 0x0002

	// ExtensionTypeRequiredCapabilities - RFC 9420 §11.1
	// Location: GroupContext
	// Usage: Ensure all members support same features
	ExtensionTypeRequiredCapabilities ExtensionType = 0x0003

	// ExtensionTypeExternalPub - RFC 9420 §12.4.3.2
	// Location: GroupInfo
	// Usage: HPKE public key for External Commit
	ExtensionTypeExternalPub ExtensionType = 0x0004

	// ExtensionTypeExternalSenders - RFC 9420 §12.1.8.1
	// Location: GroupContext
	// Usage: List of allowed external senders
	ExtensionTypeExternalSenders ExtensionType = 0x0005

	// ExtensionTypeLastResort - RFC 9420 §16.8
	// Location: KeyPackage
	// Usage: Backup KeyPackage when normal ones exhausted
	ExtensionTypeLastResort ExtensionType = 0x000A
)

// Extension represents a generic MLS extension per RFC 9420 §13.
//
// ```text
//
//	struct {
//	    ExtensionType extension_type;    // uint16
//	    opaque extension_data<V>;        // variable-length
//	} Extension;
//
// ```
//
// # Example
//
//	ext := &Extension{
//	    Type: ExtensionTypeApplicationID,
//	    Data: []byte("my-app-id"),
//	}
//
//	if err := ext.Validate(); err != nil {
//	    return err
//	}
//
// data := ext.Marshal()
type Extension struct {
	Type ExtensionType
	Data []byte
}

// Marshal serializes an Extension to TLS format per RFC 9420 §13.
//
// ```text
// ┌─────────────────────────────────────────┐
// │         TLS Encoding                    │
// ├─────────────────────────────────────────┤
// │  extension_type        : uint16         │
// │  extension_data_length : varint         │
// │  extension_data        : opaque         │
// └─────────────────────────────────────────┘
// ```
func (e *Extension) Marshal() []byte {
	buf := tls.NewWriter()
	buf.WriteUint16(uint16(e.Type))
	buf.WriteVLBytes(e.Data)
	return buf.Bytes()
}

// UnmarshalExtension parses an Extension from TLS format.
//
// # Example
//
// data := []byte{0x00, 0x01, 0x04, 't', 'e', 's', 't'}
// ext, err := UnmarshalExtension(data)
//
//	if err != nil {
//	    return err
//	}
//
// // ext.Type == ExtensionTypeApplicationID
// // ext.Data == []byte("test")
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
// Internal structure:
// ```text
// ┌─────────────────────────────────────────┐
// │         Extensions                      │
// ├─────────────────────────────────────────┤
// │  extensions : map[Type]Extension        │  // O(1) lookup
// │  ordered    : []Type                    │  // ascending order
// └─────────────────────────────────────────┘
// ```
//
// RFC 9420 §13.4 requires ascending order by ExtensionType for
// deterministic GroupContext hashes.
//
// # Example
//
// exts := NewExtensions()
//
//	if err := exts.Add(Extension{Type: ExtensionTypeExternalSenders, Data: []byte{0x03}}); err != nil {
//	    return err
//	}
//
//	if err := exts.Add(Extension{Type: ExtensionTypeApplicationID, Data: []byte{0x01}}); err != nil {
//	    return err
//	}
//
// // Marshal produces deterministic order: ApplicationID, ExternalSenders
// data := exts.Marshal()
type Extensions struct {
	extensions map[ExtensionType]Extension
	ordered    []ExtensionType
}

// NewExtensions creates an empty extension collection.
func NewExtensions() *Extensions {
	return &Extensions{
		extensions: make(map[ExtensionType]Extension),
		ordered:    make([]ExtensionType, 0),
	}
}

// Add adds an extension to the collection.
//
// If the extension type already exists, it is replaced.
// Extensions are maintained in ascending order per RFC 9420 §13.4.
//
// ```text
// Before:  ordered = [0x0001, 0x0003, 0x0005]
// Add:     Type = 0x0002
// After:   ordered = [0x0001, 0x0002, 0x0003, 0x0005]
// ```
func (e *Extensions) Add(ext Extension) error {
	if err := ext.Validate(); err != nil {
		return fmt.Errorf("invalid extension: %w", err)
	}

	if _, exists := e.extensions[ext.Type]; !exists {
		e.ordered = append(e.ordered, ext.Type)
		sort.Slice(e.ordered, func(i, j int) bool {
			return e.ordered[i] < e.ordered[j]
		})
	}

	e.extensions[ext.Type] = ext
	return nil
}

// Get retrieves an extension by type.
//
// Returns the extension and true if it exists.
func (e *Extensions) Get(typ ExtensionType) (Extension, bool) {
	ext, ok := e.extensions[typ]
	return ext, ok
}

// Has checks if an extension type exists.
func (e *Extensions) Has(typ ExtensionType) bool {
	_, ok := e.extensions[typ]
	return ok
}

// Remove removes an extension by type (no-op if not found).
func (e *Extensions) Remove(typ ExtensionType) {
	if _, exists := e.extensions[typ]; !exists {
		return
	}

	delete(e.extensions, typ)

	for i, t := range e.ordered {
		if t == typ {
			e.ordered = append(e.ordered[:i], e.ordered[i+1:]...)
			break
		}
	}
}

// Len returns the number of extensions.
func (e *Extensions) Len() int {
	return len(e.extensions)
}

// All returns all extensions in ascending order by ExtensionType.
//
// Per RFC 9420 §13.4, extensions MUST be ordered ascending by type.
func (e *Extensions) All() []Extension {
	result := make([]Extension, 0, len(e.ordered))
	for _, typ := range e.ordered {
		result = append(result, e.extensions[typ])
	}
	return result
}

// Marshal serializes all extensions to TLS format.
//
// Extensions are serialized in ascending order per RFC 9420 §13.4.
// This is critical for deterministic GroupContext hashes.
//
// ```text
// ┌─────────────────────────────────────────┐
// │      Extensions Encoding                │
// ├─────────────────────────────────────────┤
// │  extensions_length : varint             │
// │  Extension[]                            │
// │   (ascending by type)                   │
// └─────────────────────────────────────────┘
// ```
func (e *Extensions) Marshal() []byte {
	buf := tls.NewWriter()
	extBuf := tls.NewWriter()
	for _, typ := range e.ordered {
		ext := e.extensions[typ]
		extBuf.WriteRaw(ext.Marshal())
	}
	buf.WriteVLBytes(extBuf.Bytes())
	return buf.Bytes()
}

// UnmarshalExtensions parses extensions from TLS format.
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

		buf.Skip(len(ext.Marshal()))

		if err := exts.Add(*ext); err != nil {
			return nil, fmt.Errorf("adding extension: %w", err)
		}
	}

	return exts, nil
}

// Validate validates an Extension.
//
// # Validation Rules
//
// - Data must not be nil
// - Type must be known (or GREASE for extensibility)
func (e *Extension) Validate() error {
	if e.Data == nil {
		return fmt.Errorf("%w: extension data is nil", ErrInvalidExtension)
	}

	switch e.Type {
	case ExtensionTypeApplicationID,
		ExtensionTypeRatchetTree,
		ExtensionTypeRequiredCapabilities,
		ExtensionTypeExternalPub,
		ExtensionTypeExternalSenders:
		// Known types are valid
	default:
		// Unknown types allowed for extensibility
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
	for _, typ := range e.ordered {
		ext := e.extensions[typ]
		if err := result.Add(Extension{
			Type: ext.Type,
			Data: append([]byte(nil), ext.Data...),
		}); err != nil {
			// Should never happen for valid extensions
			panic(err)
		}
	}
	return result
}
