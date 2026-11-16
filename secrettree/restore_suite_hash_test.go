package secrettree

import (
	"bytes"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// TestUnmarshalFullKeepsSuiteHash checks that a CS5 tree restored with UnmarshalFull derives the same keys as the
// original, both for a leaf that was already cached (restored ratchet keys) and for a new leaf (restored
// encryption_secret). Restoring the secrets with the SHA-256 default of ciphersuite.NewSecret gave different keys.
func TestUnmarshalFullKeepsSuiteHash(t *testing.T) {
	cs := ciphersuite.MLS256DHKEMP521AES256GCM
	encSecret, err := ciphersuite.NewSecretRandomCS(cs)
	if err != nil {
		t.Fatalf("NewSecretRandomCS: %v", err)
	}
	tree, err := NewTree(encSecret, 4, cs)
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}

	appKey := func(tr *Tree, index uint32) []byte {
		t.Helper()
		leaf, err := tr.LeafForIndex(index)
		if err != nil {
			t.Fatalf("LeafForIndex(%d): %v", index, err)
		}
		key, err := leaf.ApplicationKey(0)
		if err != nil {
			t.Fatalf("ApplicationKey(%d): %v", index, err)
		}
		return key
	}
	// Leaf 1 is cached when the tree is saved. Leaf 2 is derived after the restore.
	want1 := appKey(tree, 1)
	want2 := appKey(tree, 2)

	restored, err := UnmarshalFull(tree.MarshalFull(), cs)
	if err != nil {
		t.Fatalf("UnmarshalFull: %v", err)
	}
	if got := appKey(restored, 1); !bytes.Equal(got, want1) {
		t.Errorf("cached leaf 1: key differs after UnmarshalFull (cs=%v)", cs)
	}
	if got := appKey(restored, 2); !bytes.Equal(got, want2) {
		t.Errorf("derived leaf 2: key differs after UnmarshalFull (cs=%v)", cs)
	}
}

// TestUnmarshalRejectsUnsupportedSuite checks that a cipher suite that is not implemented is rejected, instead of
// restoring the tree with SHA-256 without an error.
func TestUnmarshalRejectsUnsupportedSuite(t *testing.T) {
	const unsupported = ciphersuite.MLS256DHKEMX448AES256GCM

	cs := ciphersuite.MLS256DHKEMP521AES256GCM
	encSecret, err := ciphersuite.NewSecretRandomCS(cs)
	if err != nil {
		t.Fatalf("NewSecretRandomCS: %v", err)
	}
	tree, err := NewTree(encSecret, 2, cs)
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}

	if _, err := UnmarshalFull(tree.MarshalFull(), unsupported); !errors.Is(err, ciphersuite.ErrUnsupportedSuite) {
		t.Errorf("UnmarshalFull(cs=%v): err = %v, want ErrUnsupportedSuite", unsupported, err)
	}
	if _, err := Unmarshal(tree.Marshal(), unsupported); !errors.Is(err, ciphersuite.ErrUnsupportedSuite) {
		t.Errorf("Unmarshal(cs=%v): err = %v, want ErrUnsupportedSuite", unsupported, err)
	}
}
