//go:build diagnostics

package treesync

import (
	"encoding/binary"
	"runtime"
	"testing"
	"time"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/internal/tls"
)

// Additional diagnostics for tree parsing and allocation behavior.

func treeInputWithLeafCount(numLeaves uint32, body int) []byte {
	buf := make([]byte, 4+body)
	binary.BigEndian.PutUint32(buf, numLeaves)
	return buf // body bytes are zero: nodeTypeEmpty, i.e. one byte per node
}

// TestUnmarshalTreeExtremeLeafCounts rejects extreme leaf counts quickly
// without panicking or overflowing the node count.
func TestUnmarshalTreeExtremeLeafCounts(t *testing.T) {
	for _, nl := range []uint32{1 << 30, 1 << 31, 0x7FFFFFFF, 0x80000001, 0xFFFFFFFF} {
		in := treeInputWithLeafCount(nl, 0)
		start := time.Now()
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("UnmarshalTree(num_leaves=%#x) panicked: %v", nl, r)
				}
			}()
			_, err = UnmarshalTree(in, ciphersuite.MLS128DHKEMP256)
		}()
		if err == nil {
			t.Errorf("UnmarshalTree(num_leaves=%#x, empty body) accepted", nl)
		}
		if d := time.Since(start); d > 100*time.Millisecond {
			t.Errorf("UnmarshalTree(num_leaves=%#x) took %v", nl, d)
		}
	}
}

// TestUnmarshalTreeAllocationRatio logs allocated memory per input byte.
func TestUnmarshalTreeAllocationRatio(t *testing.T) {
	for _, bodyLen := range []int{1 << 16, 1 << 20} {
		numLeaves := uint32((bodyLen + 1) / 2)
		in := treeInputWithLeafCount(numLeaves, bodyLen)

		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		tree, err := UnmarshalTree(in, ciphersuite.MLS128DHKEMP256)
		runtime.ReadMemStats(&after)
		if err != nil {
			t.Fatalf("UnmarshalTree(valid, %d bytes): %v", len(in), err)
		}
		alloc := after.TotalAlloc - before.TotalAlloc
		t.Logf("input=%d bytes, num_leaves=%d, nodes=%d, allocated=%d bytes, ratio=%.1f bytes allocated per input byte",
			len(in), numLeaves, len(tree.Nodes), alloc, float64(alloc)/float64(len(in)))
		runtime.KeepAlive(tree)
	}
}

// TestUnmarshalTreeTrailingBytes logs how trailing input bytes are handled.
func TestUnmarshalTreeTrailingBytes(t *testing.T) {
	in := treeInputWithLeafCount(1, 1) // one node (empty), no trailing bytes expected
	in = append(in, 0xAA, 0xBB, 0xCC)
	tree, err := UnmarshalTree(in, ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Logf("UnmarshalTree with trailing bytes: err = %v", err)
		return
	}
	t.Logf("UnmarshalTree accepts %d trailing bytes (nodes=%d)", 3, len(tree.Nodes))
}

// TestUnmarshalTreeExtensionRejectsTruncatedInput checks that malformed
// extension inputs are rejected with bounded allocation.
func TestUnmarshalTreeExtensionRejectsTruncatedInput(t *testing.T) {
	for _, in := range [][]byte{
		{0x40, 0x00, 0x00, 0x00},
		{0x00, 0x00, 0x00, 0x40},
		{0xFF, 0xFF, 0xFF, 0xFF},
		{0x80, 0x00, 0x00, 0x00},
	} {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("UnmarshalTreeFromExtension(%x) panicked: %v", in, r)
				}
			}()
			_, err = UnmarshalTreeFromExtension(in, ciphersuite.MLS128DHKEMP256)
		}()
		runtime.ReadMemStats(&after)
		if err == nil {
			t.Errorf("UnmarshalTreeFromExtension(%x) accepted", in)
		}
		if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 1<<20 {
			t.Errorf("UnmarshalTreeFromExtension(%x) allocated %d bytes", in, alloc)
		}
	}
}

// TestUnmarshalTreeExtensionAllocationRatio logs allocation for a large
// extension containing empty nodes.
func TestUnmarshalTreeExtensionAllocationRatio(t *testing.T) {
	const n = 1 << 20
	w := tls.NewWriter()
	w.WriteVLBytes(make([]byte, n))
	in := w.Bytes()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := UnmarshalTreeFromExtension(in, ciphersuite.MLS128DHKEMP256)
	runtime.ReadMemStats(&after)
	alloc := after.TotalAlloc - before.TotalAlloc
	t.Logf("RFC extension path: input=%d bytes, err=%v, allocated=%d bytes, ratio=%.1f",
		len(in), err, alloc, float64(alloc)/float64(len(in)))
}
