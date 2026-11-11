package group

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// TestPassiveClientRandomVectors checks that a passive client follows the official passive-client-random
// vector (mlswg/mls-implementations, test-vectors/passive-client-random.json). It shares the schema of
// passive-client-handling-commit.json, so it reuses the same runner.
func TestPassiveClientRandomVectors(t *testing.T) {
	data, err := os.ReadFile("../testdata/mls-interop-testvectors/test-vectors/passive-client-random.json")
	if err != nil {
		t.Fatalf("reading test vectors: %v", err)
	}

	var vecs []passiveClientCommitVector
	if err := json.Unmarshal(data, &vecs); err != nil {
		t.Fatalf("unmarshaling test vectors: %v", err)
	}

	tested := 0
	for i, v := range vecs {
		cs := ciphersuite.CipherSuite(v.CipherSuite)
		if !cs.IsSupported() {
			continue
		}
		t.Run(fmt.Sprintf("vector-%d", i), func(t *testing.T) {
			runPassiveClientCommitVector(t, &v)
		})
		tested++
	}
	if tested == 0 {
		t.Fatal("no supported cipher suite vectors found")
	}
}
