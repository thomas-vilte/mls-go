// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE file.

package extensions_test

import (
	"testing"

	"github.com/mls-go/credentials"
	"github.com/mls-go/extensions"
)

// TestRequiredCapabilitiesExtension_Create tests creation.
func TestRequiredCapabilitiesExtension_Create(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	if req == nil {
		t.Fatal("NewRequiredCapabilities returned nil")
	}
	if len(req.ProtocolVersions) != 0 {
		t.Errorf("ProtocolVersions len = %d, want 0", len(req.ProtocolVersions))
	}
	if len(req.CipherSuites) != 0 {
		t.Errorf("CipherSuites len = %d, want 0", len(req.CipherSuites))
	}
	if len(req.Extensions) != 0 {
		t.Errorf("Extensions len = %d, want 0", len(req.Extensions))
	}
	if len(req.Proposals) != 0 {
		t.Errorf("Proposals len = %d, want 0", len(req.Proposals))
	}
	if len(req.Credentials) != 0 {
		t.Errorf("Credentials len = %d, want 0", len(req.Credentials))
	}
}

// TestRequiredCapabilitiesExtension_AddProtocolVersion tests adding protocol version.
func TestRequiredCapabilitiesExtension_AddProtocolVersion(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	req.AddProtocolVersion(0x01)
	req.AddProtocolVersion(0x02)

	if len(req.ProtocolVersions) != 2 {
		t.Errorf("ProtocolVersions len = %d, want 2", len(req.ProtocolVersions))
	}
}

// TestRequiredCapabilitiesExtension_AddCipherSuite tests adding cipher suite.
func TestRequiredCapabilitiesExtension_AddCipherSuite(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	req.AddCipherSuite(0x0002)
	req.AddCipherSuite(0x0003)

	if len(req.CipherSuites) != 2 {
		t.Errorf("CipherSuites len = %d, want 2", len(req.CipherSuites))
	}
}

// TestRequiredCapabilitiesExtension_AddExtension tests adding extension type.
func TestRequiredCapabilitiesExtension_AddExtension(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	req.AddExtension(extensions.ExtensionTypeApplicationID)
	req.AddExtension(extensions.ExtensionTypeExternalPub)

	if len(req.Extensions) != 2 {
		t.Errorf("Extensions len = %d, want 2", len(req.Extensions))
	}
}

// TestRequiredCapabilitiesExtension_AddProposal tests adding proposal type.
func TestRequiredCapabilitiesExtension_AddProposal(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	req.AddProposal(0x0001)
	req.AddProposal(0x0002)

	if len(req.Proposals) != 2 {
		t.Errorf("Proposals len = %d, want 2", len(req.Proposals))
	}
}

// TestRequiredCapabilitiesExtension_AddCredential tests adding credential type.
func TestRequiredCapabilitiesExtension_AddCredential(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	req.AddCredential(credentials.BasicCredential)
	req.AddCredential(credentials.X509Credential)

	if len(req.Credentials) != 2 {
		t.Errorf("Credentials len = %d, want 2", len(req.Credentials))
	}
}

// TestRequiredCapabilitiesExtension_MarshalUnmarshal tests serialization round-trip.
func TestRequiredCapabilitiesExtension_MarshalUnmarshal(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	req.AddProtocolVersion(0x01)
	req.AddCipherSuite(0x0002)
	req.AddExtension(extensions.ExtensionTypeApplicationID)

	data := req.Marshal()
	req2, err := extensions.UnmarshalRequiredCapabilities(data)
	if err != nil {
		t.Fatalf("UnmarshalRequiredCapabilities failed: %v", err)
	}

	if !req.Equal(req2) {
		t.Error("Unmarshaled extension not equal to original")
	}
}

// TestRequiredCapabilitiesExtension_Validate tests validation.
func TestRequiredCapabilitiesExtension_Validate(t *testing.T) {
	// Empty should fail
	req1 := extensions.NewRequiredCapabilities()
	if err := req1.Validate(); err == nil {
		t.Error("Validate() should fail for empty extension")
	}

	// With protocol version and cipher suite should pass
	req2 := extensions.NewRequiredCapabilities()
	req2.AddProtocolVersion(0x01)
	req2.AddCipherSuite(0x0002)
	if err := req2.Validate(); err != nil {
		t.Errorf("Validate() error = %v, want nil", err)
	}
}

// TestRequiredCapabilitiesExtension_Equal tests equality comparison.
func TestRequiredCapabilitiesExtension_Equal(t *testing.T) {
	req1 := extensions.NewRequiredCapabilities()
	req1.AddProtocolVersion(0x01)
	req1.AddCipherSuite(0x0002)

	req2 := extensions.NewRequiredCapabilities()
	req2.AddProtocolVersion(0x01)
	req2.AddCipherSuite(0x0002)

	if !req1.Equal(req2) {
		t.Error("Equal extensions not equal")
	}

	req3 := extensions.NewRequiredCapabilities()
	req3.AddProtocolVersion(0x02)
	if req1.Equal(req3) {
		t.Error("Different extensions equal")
	}
}

// TestRequiredCapabilitiesExtension_SupportsAll tests capability checking.
func TestRequiredCapabilitiesExtension_SupportsAll(t *testing.T) {
	req1 := extensions.NewRequiredCapabilities()
	req1.AddProtocolVersion(0x01)
	req1.AddProtocolVersion(0x02)
	req1.AddCipherSuite(0x0002)

	req2 := extensions.NewRequiredCapabilities()
	req2.AddProtocolVersion(0x01)

	if !req1.SupportsAll(req2) {
		t.Error("req1 should support all of req2")
	}

	req3 := extensions.NewRequiredCapabilities()
	req3.AddProtocolVersion(0x03)
	if req1.SupportsAll(req3) {
		t.Error("req1 should not support all of req3")
	}
}

// TestRequiredCapabilitiesExtension_IsEmpty tests empty check.
func TestRequiredCapabilitiesExtension_IsEmpty(t *testing.T) {
	req1 := extensions.NewRequiredCapabilities()
	if !req1.IsEmpty() {
		t.Error("New extension should be empty")
	}

	req2 := extensions.NewRequiredCapabilities()
	req2.AddProtocolVersion(0x01)
	if req2.IsEmpty() {
		t.Error("Extension with data should not be empty")
	}
}

// TestRequiredCapabilitiesExtension_HasProtocolVersion tests protocol version check.
func TestRequiredCapabilitiesExtension_HasProtocolVersion(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	req.AddProtocolVersion(0x01)
	req.AddProtocolVersion(0x02)

	if !req.HasProtocolVersion(0x01) {
		t.Error("HasProtocolVersion(0x01) should return true")
	}
	if req.HasProtocolVersion(0x03) {
		t.Error("HasProtocolVersion(0x03) should return false")
	}
}

// TestRequiredCapabilitiesExtension_HasCipherSuite tests cipher suite check.
func TestRequiredCapabilitiesExtension_HasCipherSuite(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	req.AddCipherSuite(0x0002)
	req.AddCipherSuite(0x0003)

	if !req.HasCipherSuite(0x0002) {
		t.Error("HasCipherSuite(0x0002) should return true")
	}
	if req.HasCipherSuite(0x0001) {
		t.Error("HasCipherSuite(0x0001) should return false")
	}
}

// TestRequiredCapabilitiesExtension_HasExtension tests extension type check.
func TestRequiredCapabilitiesExtension_HasExtension(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	req.AddExtension(extensions.ExtensionTypeApplicationID)

	if !req.HasExtension(extensions.ExtensionTypeApplicationID) {
		t.Error("HasExtension(ApplicationID) should return true")
	}
	if req.HasExtension(extensions.ExtensionTypeExternalPub) {
		t.Error("HasExtension(ExternalPub) should return false")
	}
}

// TestUnmarshalRequiredCapabilities_Invalid tests invalid unmarshal.
func TestUnmarshalRequiredCapabilities_Invalid(t *testing.T) {
	// Truncated data
	_, err := extensions.UnmarshalRequiredCapabilities([]byte{0x05})
	if err == nil {
		t.Error("UnmarshalRequiredCapabilities should fail on truncated data")
	}
}
