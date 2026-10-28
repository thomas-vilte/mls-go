//go:build diagnostics

package keypackages

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/internal/tls"
)

// Additional diagnostics for the KeyPackage and LeafNode parsers.

func newDiagnosticKeyPackage(t *testing.T) (*KeyPackage, []byte) {
	t.Helper()
	cred, _, err := credentials.GenerateCredentialWithKeyForCS([]byte("parse"), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("GenerateCredentialWithKeyForCS: %v", err)
	}
	kp, _, err := Generate(cred, ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return kp, kp.Marshal()
}

// TestKeyPackageWithTrailingBytesRejected checks that a valid KeyPackage followed by bytes is refused.
func TestKeyPackageWithTrailingBytesRejected(t *testing.T) {
	_, raw := newDiagnosticKeyPackage(t)
	if _, err := UnmarshalKeyPackage(raw); err != nil {
		t.Fatalf("control: UnmarshalKeyPackage(valid) = %v", err)
	}
	if _, err := UnmarshalKeyPackage(append(append([]byte{}, raw...), raw...)); err == nil {
		t.Errorf("UnmarshalKeyPackage accepted a second KeyPackage appended to the first")
	}
}

// TestKeyPackageMalformedExtensionsRejected checks that an Extensions<V> entry that does not decode (type
// 0x0001 with no length) is refused instead of being dropped.
func TestKeyPackageMalformedExtensionsRejected(t *testing.T) {
	_, raw := newDiagnosticKeyPackage(t)
	r := tls.NewReader(raw)
	if _, err := r.ReadUint16(); err != nil {
		t.Fatalf("version: %v", err)
	}
	if _, err := r.ReadUint16(); err != nil {
		t.Fatalf("cipher suite: %v", err)
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

	// Extensions<V> of 2 bytes: type 0x0001 and no length for extension_data.
	mutated := bytes.Join([][]byte{raw[:extStart], {0x02, 0x00, 0x01}, raw[extEnd:]}, nil)
	if _, err := UnmarshalKeyPackage(mutated); err == nil {
		t.Errorf("UnmarshalKeyPackage accepted an Extensions<V> whose entry does not decode; the entry was dropped without error")
	}
}

// TestLeafNodeTopLevelParserRejectsTrailingBytes checks that the top-level LeafNode parser refuses bytes after
// the structure.
func TestLeafNodeTopLevelParserRejectsTrailingBytes(t *testing.T) {
	kp, _ := newDiagnosticKeyPackage(t)
	ln := kp.LeafNode.Marshal()
	if _, err := UnmarshalLeafNode(ln); err != nil {
		t.Fatalf("control: UnmarshalLeafNode(valid) = %v", err)
	}
	if _, err := UnmarshalLeafNode(append(append([]byte{}, ln...), 0xDE, 0xAD, 0xBE, 0xEF)); err == nil {
		t.Errorf("UnmarshalLeafNode accepted 4 trailing bytes")
	}
}
