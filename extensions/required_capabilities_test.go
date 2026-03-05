package extensions_test

import (
	"testing"

	"github.com/openmls/go/credentials"
	"github.com/openmls/go/extensions"
)

// TestRequiredCapabilitiesExtension_Create prueba creación.
func TestRequiredCapabilitiesExtension_Create(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	if req == nil {
		t.Fatal("NewRequiredCapabilities returned nil")
	}

	// Empty capabilities should fail validation (need at least protocol version and cipher suite)
	if err := req.Validate(); err == nil {
		t.Error("Validate() should fail on empty capabilities")
	}
}

// TestRequiredCapabilitiesExtension_AddProtocolVersion prueba agregado.
func TestRequiredCapabilitiesExtension_AddProtocolVersion(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	req.AddProtocolVersion(0x01)
	req.AddProtocolVersion(0x02)

	if !req.HasProtocolVersion(0x01) {
		t.Error("HasProtocolVersion(0x01) returned false")
	}
	if req.HasProtocolVersion(0x03) {
		t.Error("HasProtocolVersion(0x03) returned true")
	}
}

// TestRequiredCapabilitiesExtension_AddCipherSuite prueba agregado.
func TestRequiredCapabilitiesExtension_AddCipherSuite(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	req.AddCipherSuite(0x0002)

	if !req.HasCipherSuite(0x0002) {
		t.Error("HasCipherSuite(0x0002) returned false")
	}
}

// TestRequiredCapabilitiesExtension_AddExtension prueba agregado.
func TestRequiredCapabilitiesExtension_AddExtension(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	req.AddExtension(extensions.ExtensionTypeApplicationID)

	if !req.HasExtension(extensions.ExtensionTypeApplicationID) {
		t.Error("HasExtension returned false")
	}
}

// TestRequiredCapabilitiesExtension_AddProposal prueba agregado.
func TestRequiredCapabilitiesExtension_AddProposal(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	req.AddProposal(0x0001)

	if len(req.Proposals) != 1 {
		t.Errorf("Proposals length = %d, want 1", len(req.Proposals))
	}
}

// TestRequiredCapabilitiesExtension_AddCredential prueba agregado.
func TestRequiredCapabilitiesExtension_AddCredential(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	req.AddCredential(credentials.BasicCredential)

	if !req.HasCredential(credentials.BasicCredential) {
		t.Error("HasCredential returned false")
	}
}

// TestRequiredCapabilitiesExtension_MarshalUnmarshal prueba serialización.
func TestRequiredCapabilitiesExtension_MarshalUnmarshal(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	req.AddProtocolVersion(0x01)
	req.AddCipherSuite(0x0002)

	data := req.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal returned empty data")
	}

	req2, err := extensions.UnmarshalRequiredCapabilities(data)
	if err != nil {
		t.Fatalf("UnmarshalRequiredCapabilities failed: %v", err)
	}

	if !req.Equal(req2) {
		t.Error("Unmarshaled not equal to original")
	}
}

// TestRequiredCapabilitiesExtension_Validate prueba validación.
func TestRequiredCapabilitiesExtension_Validate(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	
	// Empty should fail
	err := req.Validate()
	if err == nil {
		t.Error("Validate() should fail on empty capabilities")
	}

	// Add required fields
	req.AddProtocolVersion(0x01)
	req.AddCipherSuite(0x0002)
	
	err = req.Validate()
	if err != nil {
		t.Errorf("Validate() failed: %v", err)
	}
}

// TestRequiredCapabilitiesExtension_Equal prueba comparación.
func TestRequiredCapabilitiesExtension_Equal(t *testing.T) {
	req1 := extensions.NewRequiredCapabilities()
	req1.AddProtocolVersion(0x01)
	
	req2 := extensions.NewRequiredCapabilities()
	req2.AddProtocolVersion(0x01)
	
	req3 := extensions.NewRequiredCapabilities()
	req3.AddProtocolVersion(0x02)

	if !req1.Equal(req2) {
		t.Error("Equal capabilities not equal")
	}
	if req1.Equal(req3) {
		t.Error("Different capabilities equal")
	}
	if req1.Equal(nil) {
		t.Error("Capability equal to nil")
	}
}

// TestRequiredCapabilitiesExtension_SupportsAll prueba verificación.
func TestRequiredCapabilitiesExtension_SupportsAll(t *testing.T) {
	req1 := extensions.NewRequiredCapabilities()
	req1.AddProtocolVersion(0x01)
	req1.AddCipherSuite(0x0002)

	req2 := extensions.NewRequiredCapabilities()
	req2.AddProtocolVersion(0x01)

	// req1 soporta todo lo de req2
	if !req1.SupportsAll(req2) {
		t.Error("SupportsAll() returned false")
	}

	// req2 NO soporta todo lo de req1
	if req2.SupportsAll(req1) {
		t.Error("SupportsAll() returned true")
	}
}

// TestRequiredCapabilitiesExtension_IsEmpty prueba verificación.
func TestRequiredCapabilitiesExtension_IsEmpty(t *testing.T) {
	req1 := extensions.NewRequiredCapabilities()
	if !req1.IsEmpty() {
		t.Error("IsEmpty() returned false for empty capabilities")
	}

	req2 := extensions.NewRequiredCapabilities()
	req2.AddProtocolVersion(0x01)
	if req2.IsEmpty() {
		t.Error("IsEmpty() returned true for non-empty capabilities")
	}
}

// TestRequiredCapabilitiesExtension_HasProtocolVersion prueba búsqueda.
func TestRequiredCapabilitiesExtension_HasProtocolVersion(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	req.AddProtocolVersion(0x01)
	req.AddProtocolVersion(0x02)

	if !req.HasProtocolVersion(0x01) {
		t.Error("HasProtocolVersion(0x01) returned false")
	}
	if !req.HasProtocolVersion(0x02) {
		t.Error("HasProtocolVersion(0x02) returned false")
	}
	if req.HasProtocolVersion(0x03) {
		t.Error("HasProtocolVersion(0x03) returned true")
	}
}

// TestRequiredCapabilitiesExtension_HasCipherSuite prueba búsqueda.
func TestRequiredCapabilitiesExtension_HasCipherSuite(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	req.AddCipherSuite(0x0002)
	req.AddCipherSuite(0x0003)

	if !req.HasCipherSuite(0x0002) {
		t.Error("HasCipherSuite(0x0002) returned false")
	}
	if req.HasCipherSuite(0x0001) {
		t.Error("HasCipherSuite(0x0001) returned true")
	}
}

// TestRequiredCapabilitiesExtension_HasExtension prueba búsqueda.
func TestRequiredCapabilitiesExtension_HasExtension(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	req.AddExtension(extensions.ExtensionTypeApplicationID)

	if !req.HasExtension(extensions.ExtensionTypeApplicationID) {
		t.Error("HasExtension returned false")
	}
}

// TestUnmarshalRequiredCapabilities_Invalid prueba unmarshal inválido.
func TestUnmarshalRequiredCapabilities_Invalid(t *testing.T) {
	// Datos truncados
	_, err := extensions.UnmarshalRequiredCapabilities([]byte{0x05, 0x00})
	if err == nil {
		t.Error("UnmarshalRequiredCapabilities should fail on truncated data")
	}
}
