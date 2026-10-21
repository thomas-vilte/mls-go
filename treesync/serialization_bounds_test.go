package treesync

import (
	"runtime"
	"testing"
	"time"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// TestUnmarshalTreeRejectsImpossibleNodeCount checks that both parser entry points
// reject leaf counts that exceed the available input without excessive allocation.
func TestUnmarshalTreeRejectsImpossibleNodeCount(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	data := []byte{0x40, 0x00, 0x00, 0x00}

	entries := []struct {
		name  string
		parse func([]byte, ciphersuite.CipherSuite) (*RatchetTree, error)
	}{
		{"UnmarshalTree", UnmarshalTree},
		{"UnmarshalTreeFromExtension", UnmarshalTreeFromExtension},
	}

	// Not parallel: TotalAlloc is process-wide and would include other tests' allocations.
	for _, e := range entries {
		t.Run(e.name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			start := time.Now()
			tree, err := e.parse(data, cs)
			elapsed := time.Since(start)
			runtime.ReadMemStats(&after)

			if err == nil {
				t.Fatalf("parse of 4-byte input with num_leaves=1<<30 succeeded with %d nodes", len(tree.Nodes))
			}
			if elapsed > 100*time.Millisecond {
				t.Fatalf("parse took %v, want < 100ms", elapsed)
			}
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<20 {
				t.Fatalf("parse allocated %d bytes for a 4-byte input, want < 1 MiB", allocated)
			}
		})
	}
}

// TestUnmarshalTreeNodeCountValidation checks exact-fit input, truncated node data,
// and round trips through the internal tree format.
func TestUnmarshalTreeNodeCountValidation(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256

	// num_leaves = 2 -> 3 nodes, all empty: 4-byte header followed by exactly 3 bytes.
	exact := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
	tree, err := UnmarshalTree(exact, cs)
	if err != nil {
		t.Fatalf("UnmarshalTree(exact fit): %v", err)
	}
	if tree.NumLeaves != 2 || len(tree.Nodes) != 3 {
		t.Fatalf("got NumLeaves=%d len(Nodes)=%d, want 2 and 3", tree.NumLeaves, len(tree.Nodes))
	}

	if _, err := UnmarshalTree(exact[:len(exact)-1], cs); err == nil {
		t.Fatal("UnmarshalTree with one node byte missing succeeded")
	}

	// Round trip through the internal format for several tree sizes, including
	// non-power-of-2 sizes produced by TruncateTrailingBlanks.
	for _, n := range []uint32{1, 2, 3, 5, 8} {
		src := NewRatchetTree(n, cs)
		src.Nodes[0].State = NodeStatePresent
		if len(src.Nodes) > 1 {
			src.Nodes[1].State = NodeStatePresent
		}

		got, err := UnmarshalTree(src.MarshalTree(), cs)
		if err != nil {
			t.Fatalf("round trip num_leaves=%d: %v", n, err)
		}
		if got.NumLeaves != n || len(got.Nodes) != len(src.Nodes) {
			t.Fatalf("round trip num_leaves=%d: got NumLeaves=%d len(Nodes)=%d",
				n, got.NumLeaves, len(got.Nodes))
		}
		for i := range src.Nodes {
			if got.Nodes[i].State != src.Nodes[i].State {
				t.Fatalf("round trip num_leaves=%d: node %d state %v, want %v",
					n, i, got.Nodes[i].State, src.Nodes[i].State)
			}
		}
	}
}
