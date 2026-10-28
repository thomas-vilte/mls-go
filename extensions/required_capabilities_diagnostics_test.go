//go:build diagnostics

package extensions

import (
	"testing"

	"github.com/thomas-vilte/mls-go/internal/tls"
)

// Additional diagnostics for the RequiredCapabilities encoding.

// TestRequiredCapabilitiesDecodesRFCLayout checks that the three vectors of RFC 9420 §11.1 (extension_types,
// proposal_types, credential_types) are decoded into their own fields.
func TestRequiredCapabilitiesDecodesRFCLayout(t *testing.T) {
	ext := tls.NewWriter()
	ext.WriteUint16(0x0001)
	prop := tls.NewWriter()
	prop.WriteUint16(0x0002)
	cred := tls.NewWriter()
	cred.WriteUint16(0x0001)

	w := tls.NewWriter()
	w.WriteVLBytes(ext.Bytes())
	w.WriteVLBytes(prop.Bytes())
	w.WriteVLBytes(cred.Bytes())

	r, err := UnmarshalRequiredCapabilities(w.Bytes())
	if err != nil {
		t.Fatalf("UnmarshalRequiredCapabilities(RFC 3-vector layout) = %v", err)
	}
	if len(r.ProtocolVersions) != 0 || len(r.CipherSuites) != 0 ||
		len(r.Extensions) != 1 || len(r.Proposals) != 1 || len(r.Credentials) != 1 {
		t.Errorf("RFC 9420 §11.1 RequiredCapabilities decoded as versions=%v cipher_suites=%v extensions=%v proposals=%v credentials=%v; want extensions=[1] proposals=[2] credentials=[1]",
			r.ProtocolVersions, r.CipherSuites, r.Extensions, r.Proposals, r.Credentials)
	}
}
