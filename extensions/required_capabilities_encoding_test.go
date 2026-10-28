package extensions_test

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/extensions"
	"github.com/thomas-vilte/mls-go/internal/tls"
)

// encodeUint16Vector encodes one vector of uint16 entries, with its MLS length prefix.
func encodeUint16Vector(values ...uint16) []byte {
	body := tls.NewWriter()
	for _, v := range values {
		body.WriteUint16(v)
	}
	w := tls.NewWriter()
	w.WriteVLBytes(body.Bytes())
	return w.Bytes()
}

// TestRequiredCapabilitiesDecodesRFCVectors checks that the three RFC 9420 §11.1 vectors land in Extensions,
// Proposals and Credentials, and that nothing is read into ProtocolVersions or CipherSuites.
func TestRequiredCapabilitiesDecodesRFCVectors(t *testing.T) {
	data := bytes.Join([][]byte{encodeUint16Vector(0x0001, 0x0002), encodeUint16Vector(0x0003), encodeUint16Vector(0x0001)}, nil)
	req, err := extensions.UnmarshalRequiredCapabilities(data)
	if err != nil {
		t.Fatalf("UnmarshalRequiredCapabilities(RFC layout): %v", err)
	}
	if len(req.Extensions) != 2 || req.Extensions[0] != 0x0001 || req.Extensions[1] != 0x0002 {
		t.Errorf("Extensions = %v, want [1 2]", req.Extensions)
	}
	if len(req.Proposals) != 1 || req.Proposals[0] != 0x0003 {
		t.Errorf("Proposals = %v, want [3]", req.Proposals)
	}
	if len(req.Credentials) != 1 || req.Credentials[0] != credentials.BasicCredential {
		t.Errorf("Credentials = %v, want [BasicCredential]", req.Credentials)
	}
	if len(req.ProtocolVersions) != 0 || len(req.CipherSuites) != 0 {
		t.Errorf("ProtocolVersions = %v, CipherSuites = %v, want none (not encoded)", req.ProtocolVersions, req.CipherSuites)
	}
}

// TestRequiredCapabilitiesMarshalWritesThreeVectors checks the exact encoding. Protocol versions and cipher
// suites have no vector, so they are not written.
func TestRequiredCapabilitiesMarshalWritesThreeVectors(t *testing.T) {
	req := extensions.NewRequiredCapabilities()
	req.AddProtocolVersion(0x0001)
	req.AddCipherSuite(0x0002)
	req.AddExtension(extensions.ExtensionType(0x0001))
	req.AddProposal(0x0002)
	req.AddCredential(credentials.BasicCredential)

	want := bytes.Join([][]byte{encodeUint16Vector(0x0001), encodeUint16Vector(0x0002), encodeUint16Vector(0x0001)}, nil)
	if got := req.Marshal(); !bytes.Equal(got, want) {
		t.Errorf("Marshal() = % x, want % x", got, want)
	}
}

// TestRequiredCapabilitiesRejectsMalformedInput checks that bytes after the last vector, a vector with an odd
// body length and a missing vector are errors.
func TestRequiredCapabilitiesRejectsMalformedInput(t *testing.T) {
	valid := bytes.Join([][]byte{encodeUint16Vector(0x0001), encodeUint16Vector(), encodeUint16Vector()}, nil)
	if _, err := extensions.UnmarshalRequiredCapabilities(valid); err != nil {
		t.Fatalf("control: UnmarshalRequiredCapabilities(valid) = %v", err)
	}
	if _, err := extensions.UnmarshalRequiredCapabilities(append(append([]byte{}, valid...), 0x00)); err == nil {
		t.Error("trailing byte after credential_types accepted")
	}
	truncated := bytes.Join([][]byte{{0x03, 0x00, 0x01, 0x02}, encodeUint16Vector(), encodeUint16Vector()}, nil)
	if _, err := extensions.UnmarshalRequiredCapabilities(truncated); err == nil {
		t.Error("extension_types with an odd body length accepted")
	}
	if _, err := extensions.UnmarshalRequiredCapabilities(encodeUint16Vector(0x0001)); err == nil {
		t.Error("data with missing vectors accepted")
	}
}
