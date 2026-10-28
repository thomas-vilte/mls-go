//go:build diagnostics

package treesync

import (
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/internal/tls"
)

// Additional diagnostics for the ratchet tree parser.

// encodeDiagnosticTree encodes a tree of two leaves: a blank leaf, a parent with no enc_key or parent_hash
// and the given unmerged_leaves, and a blank leaf.
func encodeDiagnosticTree(unmerged []byte) []byte {
	w := tls.NewWriter()
	w.WriteUint32(2)
	w.WriteUint8(nodeTypeLeaf)
	w.WriteVLBytes(nil)
	w.WriteUint8(nodeTypeParent)
	w.WriteVLBytes(nil)
	w.WriteVLBytes(nil)
	w.WriteVLBytes(unmerged)
	w.WriteUint8(nodeTypeLeaf)
	w.WriteVLBytes(nil)
	return w.Bytes()
}

// TestTreeRejectsTruncatedUnmergedLeaves checks that unmerged_leaves with a valid uint32 parses and that a
// 6-byte list (not a multiple of 4) is refused instead of losing its last bytes.
func TestTreeRejectsTruncatedUnmergedLeaves(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMX25519
	if _, err := UnmarshalTree(encodeDiagnosticTree([]byte{0, 0, 0, 1}), cs); err != nil {
		t.Fatalf("control: UnmarshalTree(valid unmerged) = %v", err)
	}
	if _, err := UnmarshalTree(encodeDiagnosticTree([]byte{0, 0, 0, 1, 0xDE, 0xAD}), cs); err == nil {
		t.Errorf("UnmarshalTree accepted unmerged_leaves of 6 bytes; the last 2 bytes were dropped without error")
	}
}
