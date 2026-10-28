// Package extensions - Required Capabilities Extension (RFC 9420 §11.1)
package extensions

import (
	"errors"
	"fmt"
	"slices"

	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/internal/tls"
)

// RequiredCapabilitiesExtension specifies capabilities required for group members.
//
// This extension is used in GroupContext to ensure all members support the required
// features before joining the group.
//
// # Structure (RFC 9420 §11.1)
//
//	struct {
//	    ExtensionType extension_types<V>;
//	    ProposalType proposal_types<V>;
//	    CredentialType credential_types<V>;
//	} RequiredCapabilities;
//
// The protocol version and the cipher suite of the group need no entry: RFC 9420 §11.1 requires every
// member to support them anyway.
//
// # Location
//
// - **KeyPackage**: No
// - **GroupInfo**: No
// - **GroupContext**: Yes
//
// # Purpose
//
// RequiredCapabilities ensures all group members support:
//   - Mandatory extensions
//   - Supported proposal types
//   - Accepted credential types
//
// # Example
//
// // Create extension
// req := NewRequiredCapabilities()
// req.AddExtension(ExtensionTypeExternalSenders)
//
// // Validate
//
//	if err := req.Validate(); err != nil {
//	    return err
//	}
//
// // Serialize
// data := req.Marshal()
//
// // Deserialize
// req2, err := UnmarshalRequiredCapabilities(data)
type RequiredCapabilitiesExtension struct {
	// ProtocolVersions and CipherSuites are not part of the RFC 9420 §11.1 encoding. Marshal does not
	// write them, UnmarshalRequiredCapabilities leaves them empty, and the protocol enforces them for
	// every member. They are kept in memory for compatibility only.
	ProtocolVersions []uint16                     // Protocol versions (not encoded)
	CipherSuites     []uint16                     // Cipher suites (not encoded)
	Extensions       []ExtensionType              // extension_types: extensions that must be supported
	Proposals        []uint16                     // proposal_types: proposal types that must be supported
	Credentials      []credentials.CredentialType // credential_types: credential types that must be supported
}

// NewRequiredCapabilities creates a new RequiredCapabilities extension.
func NewRequiredCapabilities() *RequiredCapabilitiesExtension {
	return &RequiredCapabilitiesExtension{
		ProtocolVersions: make([]uint16, 0),
		CipherSuites:     make([]uint16, 0),
		Extensions:       make([]ExtensionType, 0),
		Proposals:        make([]uint16, 0),
		Credentials:      make([]credentials.CredentialType, 0),
	}
}

// AddProtocolVersion adds a required protocol version.
func (r *RequiredCapabilitiesExtension) AddProtocolVersion(version uint16) {
	r.ProtocolVersions = append(r.ProtocolVersions, version)
}

// AddCipherSuite adds a required cipher suite.
func (r *RequiredCapabilitiesExtension) AddCipherSuite(cs uint16) {
	r.CipherSuites = append(r.CipherSuites, cs)
}

// AddExtension adds a required extension type.
func (r *RequiredCapabilitiesExtension) AddExtension(ext ExtensionType) {
	r.Extensions = append(r.Extensions, ext)
}

// AddProposal adds a required proposal type.
func (r *RequiredCapabilitiesExtension) AddProposal(proposal uint16) {
	r.Proposals = append(r.Proposals, proposal)
}

// AddCredential adds a required credential type.
func (r *RequiredCapabilitiesExtension) AddCredential(cred credentials.CredentialType) {
	r.Credentials = append(r.Credentials, cred)
}

// Marshal serializes the RequiredCapabilities extension to TLS format.
//
// # Encoding (RFC 9420 §11.1)
//
// ```text
// ┌─────────────────────────────────────────────────────────────┐
// │         RequiredCapabilities Encoding                       │
// ├─────────────────────────────────────────────────────────────┤
// │  extension_types<V>      : opaque<V>  (uint16 entries)      │
// │  proposal_types<V>       : opaque<V>  (uint16 entries)      │
// │  credential_types<V>     : opaque<V>  (uint16 entries)      │
// └─────────────────────────────────────────────────────────────┘
// ```
//
// ProtocolVersions and CipherSuites have no vector in this encoding and are not written.
func (r *RequiredCapabilitiesExtension) Marshal() []byte {
	buf := tls.NewWriter()

	// extensions_types<V>
	extBuf := tls.NewWriter()
	for _, ext := range r.Extensions {
		extBuf.WriteUint16(uint16(ext))
	}
	buf.WriteVLBytes(extBuf.Bytes())

	// proposals_types<V>
	propBuf := tls.NewWriter()
	for _, p := range r.Proposals {
		propBuf.WriteUint16(p)
	}
	buf.WriteVLBytes(propBuf.Bytes())

	// credentials_types<V>
	credBuf := tls.NewWriter()
	for _, c := range r.Credentials {
		credBuf.WriteUint16(uint16(c))
	}
	buf.WriteVLBytes(credBuf.Bytes())

	return buf.Bytes()
}

// UnmarshalRequiredCapabilities parses a RequiredCapabilities extension from TLS format (RFC 9420 §11.1).
//
// # Decoding
//
// Reads the three vectors extension_types, proposal_types and credential_types. The data must hold
// exactly these vectors: a truncated vector or bytes after the last one are errors. Every
// member's protocol version and cipher suite are required by the protocol itself, so the decoded
// ProtocolVersions and CipherSuites are always empty.
//
// # Example
//
// data := []byte{...}  // serialized data
// req, err := UnmarshalRequiredCapabilities(data)
//
//	if err != nil {
//	    return err
//	}
//
// // req.Extensions contains the required extension types
func UnmarshalRequiredCapabilities(data []byte) (*RequiredCapabilitiesExtension, error) {
	buf := tls.NewReader(data)

	// extensions_types<V>
	extBytes, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading extensions: %w", err)
	}

	extValues, err := readUint16Vector(extBytes, "extension_type")
	if err != nil {
		return nil, err
	}
	var extensions []ExtensionType
	for _, ext := range extValues {
		extensions = append(extensions, ExtensionType(ext))
	}

	// proposal_types<V>
	propBytes, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading proposal_types: %w", err)
	}
	proposals, err := readUint16Vector(propBytes, "proposal_type")
	if err != nil {
		return nil, err
	}

	// credential_types<V>
	credBytes, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading credential_types: %w", err)
	}
	credValues, err := readUint16Vector(credBytes, "credential_type")
	if err != nil {
		return nil, err
	}
	var creds []credentials.CredentialType
	for _, c := range credValues {
		creds = append(creds, credentials.CredentialType(c))
	}

	// Bytes after credential_types<V> are not part of RequiredCapabilities (RFC 9420 §2.1).
	if buf.Remaining() != 0 {
		return nil, fmt.Errorf("trailing bytes after RequiredCapabilities: %d", buf.Remaining())
	}

	return &RequiredCapabilitiesExtension{
		Extensions:  extensions,
		Proposals:   proposals,
		Credentials: creds,
	}, nil
}

// Validate validates the vectors that Marshal encodes.
//
// # Validation Rules:
//
//   - Every vector may be empty: RFC 9420 §11.1 requires no vector to be present.
//   - The value 0x0000 is reserved for extension types (§17.3), proposal types (§17.4) and
//     credential types (§17.5), so it is invalid in those vectors.
//
// ProtocolVersions and CipherSuites are not encoded, so they are not validated here.
func (r *RequiredCapabilitiesExtension) Validate() error {
	if slices.Contains(r.Extensions, 0) {
		return errors.New("invalid extension type 0 (reserved, RFC 9420 §17.3)")
	}
	if slices.Contains(r.Proposals, 0) {
		return errors.New("invalid proposal type 0 (reserved, RFC 9420 §17.4)")
	}
	if slices.Contains(r.Credentials, 0) {
		return errors.New("invalid credential type 0 (reserved, RFC 9420 §17.5)")
	}
	return nil
}

// HasProtocolVersion checks if a protocol version is required.
func (r *RequiredCapabilitiesExtension) HasProtocolVersion(version uint16) bool {
	return slices.Contains(r.ProtocolVersions, version)
}

// HasCipherSuite checks if a cipher suite is required.
func (r *RequiredCapabilitiesExtension) HasCipherSuite(cs uint16) bool {
	return slices.Contains(r.CipherSuites, cs)
}

// HasExtension checks if an extension type is required.
func (r *RequiredCapabilitiesExtension) HasExtension(ext ExtensionType) bool {
	return slices.Contains(r.Extensions, ext)
}

// Equal compares two RequiredCapabilities extensions for equality.
func (r *RequiredCapabilitiesExtension) Equal(other *RequiredCapabilitiesExtension) bool {
	if r == nil || other == nil {
		return r == other
	}

	if !uint16SliceEqual(r.ProtocolVersions, other.ProtocolVersions) {
		return false
	}

	if !uint16SliceEqual(r.CipherSuites, other.CipherSuites) {
		return false
	}

	if !extensionTypeSliceEqual(r.Extensions, other.Extensions) {
		return false
	}

	if !uint16SliceEqual(r.Proposals, other.Proposals) {
		return false
	}

	if !credentialTypeSliceEqual(r.Credentials, other.Credentials) {
		return false
	}

	return true
}

// IsEmpty returns true if the extension has no required capabilities.
func (r *RequiredCapabilitiesExtension) IsEmpty() bool {
	return len(r.ProtocolVersions) == 0 &&
		len(r.CipherSuites) == 0 &&
		len(r.Extensions) == 0 &&
		len(r.Proposals) == 0 &&
		len(r.Credentials) == 0
}

// SupportsAll checks if this extension supports all capabilities from another.
// Returns true if all capabilities in other are present in this.
func (r *RequiredCapabilitiesExtension) SupportsAll(other *RequiredCapabilitiesExtension) bool {
	if other == nil {
		return true
	}

	// Check protocol versions
	for _, v := range other.ProtocolVersions {
		if !r.HasProtocolVersion(v) {
			return false
		}
	}

	// Check cipher suites
	for _, cs := range other.CipherSuites {
		if !r.HasCipherSuite(cs) {
			return false
		}
	}

	// Check extensions
	for _, ext := range other.Extensions {
		if !r.HasExtension(ext) {
			return false
		}
	}

	// Check proposals
	for _, p := range other.Proposals {
		found := slices.Contains(r.Proposals, p)
		if !found {
			return false
		}
	}

	// Check credentials
	for _, c := range other.Credentials {
		found := slices.Contains(r.Credentials, c)
		if !found {
			return false
		}
	}

	return true
}

// HasCredential checks if a credential type is required.
func (r *RequiredCapabilitiesExtension) HasCredential(cred credentials.CredentialType) bool {
	return slices.Contains(r.Credentials, cred)
}

// Helper functions for slice comparison

func uint16SliceEqual(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func extensionTypeSliceEqual(a, b []ExtensionType) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func credentialTypeSliceEqual(a, b []credentials.CredentialType) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// readUint16Vector decodes the body of a vector of uint16 entries. A trailing partial entry is an error.
func readUint16Vector(data []byte, what string) ([]uint16, error) {
	r := tls.NewReader(data)
	var values []uint16
	for r.Remaining() > 0 {
		v, err := r.ReadUint16()
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", what, err)
		}
		values = append(values, v)
	}
	return values, nil
}
