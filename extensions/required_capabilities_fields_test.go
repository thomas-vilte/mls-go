package extensions_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/thomas-vilte/mls-go/extensions"
)

// TestRequiredCapabilitiesRoundTripsExtensionAndProposal checks that an encoding with extension type 0x0005 and
// proposal type 0x0002 decodes to exactly those values and encodes back to the same bytes (RFC 9420 §11.1).
func TestRequiredCapabilitiesRoundTripsExtensionAndProposal(t *testing.T) {
	data := bytes.Join([][]byte{encodeUint16Vector(0x0005), encodeUint16Vector(0x0002), encodeUint16Vector()}, nil)

	req, err := extensions.UnmarshalRequiredCapabilities(data)
	if err != nil {
		t.Fatalf("UnmarshalRequiredCapabilities(RFC layout) = %v", err)
	}
	if len(req.Extensions) != 1 || req.Extensions[0] != 0x0005 {
		t.Errorf("Extensions = %v, want [0x0005]", req.Extensions)
	}
	if len(req.Proposals) != 1 || req.Proposals[0] != 0x0002 {
		t.Errorf("Proposals = %v, want [0x0002]", req.Proposals)
	}
	if len(req.Credentials) != 0 {
		t.Errorf("Credentials = %v, want none", req.Credentials)
	}
	if got := req.Marshal(); !bytes.Equal(got, data) {
		t.Errorf("Marshal() = % x, want % x", got, data)
	}
}

// TestRequiredCapabilitiesStructHasOnlyRFCVectors checks that the struct carries exactly the three vectors of
// RFC 9420 §11.1. The protocol version and the cipher suite are protocol defaults, not RequiredCapabilities fields.
func TestRequiredCapabilitiesStructHasOnlyRFCVectors(t *testing.T) {
	typ := reflect.TypeOf(extensions.RequiredCapabilitiesExtension{})
	var fields []string
	for i := 0; i < typ.NumField(); i++ {
		fields = append(fields, typ.Field(i).Name)
	}
	want := []string{"Extensions", "Proposals", "Credentials"}
	if !reflect.DeepEqual(fields, want) {
		t.Errorf("RequiredCapabilitiesExtension fields = %v, want %v (RFC 9420 §11.1)", fields, want)
	}
}
