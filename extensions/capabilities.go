// Package extensions - Required Capabilities Extension (RFC 9420 §11.1)
package extensions

import (
	"errors"
	"fmt"

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
// ```text
//
//	struct {
//	    ProtocolVersion protocol_versions<V>;
//	    CipherSuite cipher_suites<V>;
//	    ExtensionType extensions<V>;
//	    ProposalType proposals<V>;
//	    CredentialType credentials<V>;
//	} RequiredCapabilities;
//
// ```
//
// # Location
//
// - **KeyPackage**: No ❌
// - **GroupInfo**: No ❌
// - **GroupContext**: Yes ✅
//
// # Purpose
//
// RequiredCapabilities ensures all group members support:
//   - Specific protocol versions
//   - Required cipher suites
//   - Mandatory extensions
//   - Supported proposal types
//   - Accepted credential types
//
// # Example
//
// // Create extension
// req := NewRequiredCapabilities()
// req.AddProtocolVersion(0x01)      // MLS 1.0
// req.AddCipherSuite(0x0002)         // MLS_128_DHKEMP256...
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
	ProtocolVersions []uint16                     // Protocol versions required
	CipherSuites     []uint16                     // Cipher suites required
	Extensions       []ExtensionType              // Extensions that must be supported
	Proposals        []uint16                     // Proposal types that must be supported
	Credentials      []credentials.CredentialType // Credential types required
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
// │  protocol_versions<V>    : opaque<V>                        │
// │  cipher_suites<V>        : opaque<V>                        │
// │  extensions<V>           : opaque<V>                        │
// │  proposals<V>            : opaque<V>                        │
// │  credentials<V>          : opaque<V>                        │
// └─────────────────────────────────────────────────────────────┘
// ```
func (r *RequiredCapabilitiesExtension) Marshal() []byte {
	buf := tls.NewWriter()

	// protocol_versions<V>
	verBuf := tls.NewWriter()
	for _, v := range r.ProtocolVersions {
		verBuf.WriteUint16(v)
	}
	buf.WriteVLBytes(verBuf.Bytes())

	// cipher_suites<V>
	csBuf := tls.NewWriter()
	for _, cs := range r.CipherSuites {
		csBuf.WriteUint16(cs)
	}
	buf.WriteVLBytes(csBuf.Bytes())

	// extensions<V>
	extBuf := tls.NewWriter()
	for _, ext := range r.Extensions {
		extBuf.WriteUint16(uint16(ext))
	}
	buf.WriteVLBytes(extBuf.Bytes())

	// proposals<V>
	propBuf := tls.NewWriter()
	for _, p := range r.Proposals {
		propBuf.WriteUint16(p)
	}
	buf.WriteVLBytes(propBuf.Bytes())

	// credentials<V>
	credBuf := tls.NewWriter()
	for _, c := range r.Credentials {
		credBuf.WriteUint16(uint16(c))
	}
	buf.WriteVLBytes(credBuf.Bytes())

	return buf.Bytes()
}

// UnmarshalRequiredCapabilities parses a RequiredCapabilities extension from TLS format.
//
// # Decoding
//
// Reads five vectors: protocol_versions, cipher_suites, extensions, proposals, credentials.
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
// // req.ProtocolVersions contains parsed versions
func UnmarshalRequiredCapabilities(data []byte) (*RequiredCapabilitiesExtension, error) {
	buf := tls.NewReader(data)

	// protocol_versions<V>
	verBytes, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading protocol_versions: %w", err)
	}

	verBuf := tls.NewReader(verBytes)
	var protocolVersions []uint16
	for verBuf.Remaining() > 0 {
		v, err := verBuf.ReadUint16()
		if err != nil {
			return nil, fmt.Errorf("reading protocol_version: %w", err)
		}
		protocolVersions = append(protocolVersions, v)
	}

	// cipher_suites<V>
	csBytes, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading cipher_suites: %w", err)
	}

	csBuf := tls.NewReader(csBytes)
	var cipherSuites []uint16
	for csBuf.Remaining() > 0 {
		cs, err := csBuf.ReadUint16()
		if err != nil {
			return nil, fmt.Errorf("reading cipher_suite: %w", err)
		}
		cipherSuites = append(cipherSuites, cs)
	}

	// extensions<V>
	extBytes, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading extensions: %w", err)
	}

	extBuf := tls.NewReader(extBytes)
	var extensions []ExtensionType
	for extBuf.Remaining() > 0 {
		ext, err := extBuf.ReadUint16()
		if err != nil {
			return nil, fmt.Errorf("reading extension_type: %w", err)
		}
		extensions = append(extensions, ExtensionType(ext))
	}

	// proposals<V> — optional trailing field; older implementations may omit it.
	var proposals []uint16
	if buf.Remaining() > 0 {
		propBytes, err := buf.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading proposals: %w", err)
		}
		propBuf := tls.NewReader(propBytes)
		for propBuf.Remaining() > 0 {
			p, err := propBuf.ReadUint16()
			if err != nil {
				return nil, fmt.Errorf("reading proposal_type: %w", err)
			}
			proposals = append(proposals, p)
		}
	}

	// credentials<V> — optional trailing field; older implementations may omit it.
	var creds []credentials.CredentialType
	if buf.Remaining() > 0 {
		credBytes, err := buf.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading credentials: %w", err)
		}
		credBuf := tls.NewReader(credBytes)
		for credBuf.Remaining() > 0 {
			c, err := credBuf.ReadUint16()
			if err != nil {
				return nil, fmt.Errorf("reading credential_type: %w", err)
			}
			creds = append(creds, credentials.CredentialType(c))
		}
	}

	return &RequiredCapabilitiesExtension{
		ProtocolVersions: protocolVersions,
		CipherSuites:     cipherSuites,
		Extensions:       extensions,
		Proposals:        proposals,
		Credentials:      creds,
	}, nil
}

// Validate validates the RequiredCapabilities extension.
//
// # Validation Rules
//
// - protocol_versions must not be empty
// - cipher_suites must not be empty
// - Protocol version 0 is invalid
// - Cipher suite 0 is invalid
func (r *RequiredCapabilitiesExtension) Validate() error {
	if len(r.ProtocolVersions) == 0 {
		return errors.New("protocol_versions cannot be empty")
	}

	if len(r.CipherSuites) == 0 {
		return errors.New("cipher_suites cannot be empty")
	}

	// Validate protocol versions
	for _, v := range r.ProtocolVersions {
		if v == 0 {
			return errors.New("invalid protocol version 0")
		}
	}

	// Validate cipher suites
	for _, cs := range r.CipherSuites {
		if cs == 0 {
			return errors.New("invalid cipher suite 0")
		}
	}

	return nil
}

// HasProtocolVersion checks if a protocol version is required.
func (r *RequiredCapabilitiesExtension) HasProtocolVersion(version uint16) bool {
	for _, v := range r.ProtocolVersions {
		if v == version {
			return true
		}
	}
	return false
}

// HasCipherSuite checks if a cipher suite is required.
func (r *RequiredCapabilitiesExtension) HasCipherSuite(cs uint16) bool {
	for _, c := range r.CipherSuites {
		if c == cs {
			return true
		}
	}
	return false
}

// HasExtension checks if an extension type is required.
func (r *RequiredCapabilitiesExtension) HasExtension(ext ExtensionType) bool {
	for _, e := range r.Extensions {
		if e == ext {
			return true
		}
	}
	return false
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
		found := false
		for _, rp := range r.Proposals {
			if rp == p {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check credentials
	for _, c := range other.Credentials {
		found := false
		for _, rc := range r.Credentials {
			if rc == c {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// HasCredential checks if a credential type is required.
func (r *RequiredCapabilitiesExtension) HasCredential(cred credentials.CredentialType) bool {
	for _, c := range r.Credentials {
		if c == cred {
			return true
		}
	}
	return false
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
