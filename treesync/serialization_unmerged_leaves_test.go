package treesync

import (
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/internal/tls"
)

// encodeUnmergedLeavesTree encodes a two-leaf tree whose parent node carries the given unmerged_leaves bytes.
func encodeUnmergedLeavesTree(unmerged []byte) []byte {
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

// TestUnmarshalTreeRejectsPartialUnmergedLeaf checks that a trailing partial entry in unmerged_leaves fails the
// parse instead of shortening the list.
func TestUnmarshalTreeRejectsPartialUnmergedLeaf(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMX25519
	if _, err := UnmarshalTree(encodeUnmergedLeavesTree([]byte{0, 0, 0, 1}), cs); err != nil {
		t.Fatalf("control: UnmarshalTree(valid unmerged_leaves) = %v", err)
	}
	if _, err := UnmarshalTree(encodeUnmergedLeavesTree([]byte{0, 0, 0, 1, 0xDE, 0xAD}), cs); err == nil {
		t.Error("UnmarshalTree accepted unmerged_leaves with a partial trailing entry")
	}
}
