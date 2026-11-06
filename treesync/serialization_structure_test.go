package treesync

import (
	"encoding/binary"
	"runtime"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// malformedTreeInput returns a UnmarshalTree input whose num_leaves implies bodyLen nodes, followed
// by bodyLen bytes. Zero bytes are empty nodes. bodyLen must be odd so that 2*num_leaves-1 == bodyLen
// and every byte is a node type.
func malformedTreeInput(bodyLen int) []byte {
	buf := make([]byte, 4+bodyLen)
	binary.BigEndian.PutUint32(buf, uint32((bodyLen+1)/2))
	return buf
}

// TestMalformedTreeBodyAllocatesNoNodes checks that UnmarshalTree rejects a malformed body without
// allocating a Node per implied node. The node slice takes about 72 bytes per node, so a 1 MiB body with one
// unknown node type used to cost about 75 MB before it was rejected. The structure of the whole body is now
// checked before the slice is allocated.
func TestMalformedTreeBodyAllocatesNoNodes(t *testing.T) {
	const bodyLen = 1<<20 - 1 // odd, so the body is exactly 2*num_leaves-1 nodes

	// Control: a well-formed body of the same size still parses.
	if _, err := UnmarshalTree(malformedTreeInput(bodyLen), ciphersuite.MLS128DHKEMP256); err != nil {
		t.Fatalf("UnmarshalTree(valid %d byte body): %v", bodyLen, err)
	}

	cases := []struct {
		name string
		bad  func(in []byte)
	}{
		{"unknown node type at the first node", func(in []byte) { in[4] = 0xFF }},
		{"unknown node type at the last node", func(in []byte) { in[len(in)-1] = 0xFF }},
	}
	for _, tc := range cases {
		in := malformedTreeInput(bodyLen)
		tc.bad(in)

		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, err := UnmarshalTree(in, ciphersuite.MLS128DHKEMP256)
		runtime.ReadMemStats(&after)

		if err == nil {
			t.Fatalf("%s: UnmarshalTree accepted a malformed body", tc.name)
		}
		if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 1<<20 {
			t.Errorf("%s: UnmarshalTree allocated %d bytes for a %d byte body; want at most 1 MiB",
				tc.name, alloc, len(in))
		}
	}
}
