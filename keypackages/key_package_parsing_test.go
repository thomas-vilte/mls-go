package keypackages

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/internal/tls"
)

// newParsingTestKeyPackage returns a generated KeyPackage and its encoding.
func newParsingTestKeyPackage(t *testing.T) (kp *KeyPackage, raw []byte) {
	t.Helper()
	cred, _, err := credentials.GenerateCredentialWithKeyForCS([]byte("parse"), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("GenerateCredentialWithKeyForCS: %v", err)
	}
	kp, _, err = Generate(cred, ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	raw = kp.Marshal()
	return kp, raw
}

// TestKeyPackageRejectsMalformedExtensionEntry checks that an Extensions<V> entry that does not decode fails
// the parse instead of being dropped from the list.
func TestKeyPackageRejectsMalformedExtensionEntry(t *testing.T) {
	_, raw := newParsingTestKeyPackage(t)
	if _, err := UnmarshalKeyPackage(raw); err != nil {
		t.Fatalf("control: UnmarshalKeyPackage(valid) = %v", err)
	}
	r := tls.NewReader(raw)
	if _, err := r.ReadUint16(); err != nil {
		t.Fatalf("protocol_version: %v", err)
	}
	if _, err := r.ReadUint16(); err != nil {
		t.Fatalf("cipher_suite: %v", err)
	}
	if _, err := r.ReadVLBytes(); err != nil {
		t.Fatalf("init_key: %v", err)
	}
	if _, err := unmarshalLeafNodeFromReader(r); err != nil {
		t.Fatalf("leaf_node: %v", err)
	}
	extStart := r.Position()
	if _, err := r.ReadVLBytes(); err != nil {
		t.Fatalf("extensions: %v", err)
	}
	extEnd := r.Position()

	// Extensions<V> of 2 bytes: extension_type 0x0001 without extension_data.
	mutated := bytes.Join([][]byte{raw[:extStart], {0x02, 0x00, 0x01}, raw[extEnd:]}, nil)
	if _, err := UnmarshalKeyPackage(mutated); err == nil {
		t.Error("UnmarshalKeyPackage accepted an Extensions<V> entry without extension_data")
	}
}

// TestUnmarshalLeafNodeRejectsTrailingBytes checks that UnmarshalLeafNode reads exactly one LeafNode.
func TestUnmarshalLeafNodeRejectsTrailingBytes(t *testing.T) {
	kp, _ := newParsingTestKeyPackage(t)
	ln := kp.LeafNode.Marshal()
	if _, err := UnmarshalLeafNode(ln); err != nil {
		t.Fatalf("control: UnmarshalLeafNode(valid) = %v", err)
	}
	if _, err := UnmarshalLeafNode(append(append([]byte{}, ln...), 0xDE, 0xAD)); err == nil {
		t.Error("UnmarshalLeafNode accepted 2 trailing bytes")
	}
}

// TestCapabilitiesRejectTruncatedVector checks that a protocol_versions<V> with an odd body length is an error
// and not a shorter list.
func TestCapabilitiesRejectTruncatedVector(t *testing.T) {
	encode := func(versions []byte) *tls.Reader {
		w := tls.NewWriter()
		w.WriteVLBytes(versions)
		w.WriteVLBytes(nil) // cipher_suites
		w.WriteVLBytes(nil) // extensions
		w.WriteVLBytes(nil) // proposals
		w.WriteVLBytes(nil) // credentials
		return tls.NewReader(w.Bytes())
	}
	if _, err := UnmarshalCapabilities(encode(nil)); err != nil {
		t.Fatalf("control: UnmarshalCapabilities(empty vectors) = %v", err)
	}
	if _, err := UnmarshalCapabilities(encode([]byte{0x00, 0x01, 0x00})); err == nil {
		t.Error("UnmarshalCapabilities accepted a protocol_versions body with a truncated entry")
	}
}
