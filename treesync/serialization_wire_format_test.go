package treesync

import (
	"runtime"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/internal/tls"
)

// rfcExtensionBytes wraps a serialized nodes<V> vector in the ratchet_tree extension
// framing (a single variable-length field).
func rfcExtensionBytes(nodes []byte) []byte {
	w := tls.NewWriter()
	w.WriteVLBytes(nodes)
	return w.Bytes()
}

// TestUnmarshalTreeExtensionTrailingBlanksAllocation checks that trailing blank
// nodes are rejected without allocating a Node for each input byte.
func TestUnmarshalTreeExtensionTrailingBlanksAllocation(t *testing.T) {
	in := rfcExtensionBytes(make([]byte, 1<<20)) // 1 MiB of blank (presence = 0) nodes

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := UnmarshalTreeFromExtension(in, ciphersuite.MLS128DHKEMP256)
	runtime.ReadMemStats(&after)

	if err == nil {
		t.Fatal("UnmarshalTreeFromExtension(1 MiB of blank nodes) accepted; want the trailing-blank error")
	}
	// The vector itself is copied once by ReadVLBytes, so about 1 MiB is expected.
	// The old amplification was about 375 bytes per input byte, so a limit of four
	// times the input still separates the two behaviours clearly.
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 4*uint64(len(in)) {
		t.Fatalf("UnmarshalTreeFromExtension allocated %d bytes for a %d byte blank input; want at most 4x the input",
			alloc, len(in))
	}
}

// TestUnmarshalTreeExtensionKeepsBlankPositions checks that blank nodes before a
// present node retain their positions.
func TestUnmarshalTreeExtensionKeepsBlankPositions(t *testing.T) {
	t.Parallel()
	leaf := createTestLeafExt(t, "leaf")

	nodes := tls.NewWriter()
	nodes.WriteUint8(0) // blank
	nodes.WriteUint8(0) // blank
	nodes.WriteUint8(1) // present leaf
	nodes.WriteUint8(nodeTypeLeaf)
	nodes.WriteRaw(leaf.Marshal())

	tree, err := UnmarshalTreeFromExtension(rfcExtensionBytes(nodes.Bytes()), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("UnmarshalTreeFromExtension: %v", err)
	}
	if len(tree.Nodes) != 3 {
		t.Fatalf("len(Nodes) = %d, want 3", len(tree.Nodes))
	}
	if tree.Nodes[0].State != NodeStateEmpty || tree.Nodes[1].State != NodeStateEmpty {
		t.Fatalf("blank positions: states = %v, %v; want empty, empty", tree.Nodes[0].State, tree.Nodes[1].State)
	}
	if tree.Nodes[2].State != NodeStatePresent || tree.Nodes[2].LeafData == nil {
		t.Fatalf("node 2 = state %v, leaf data nil = %v; want a present leaf", tree.Nodes[2].State, tree.Nodes[2].LeafData == nil)
	}
	if tree.NumLeaves != 2 {
		t.Fatalf("NumLeaves = %d, want 2", tree.NumLeaves)
	}
}
