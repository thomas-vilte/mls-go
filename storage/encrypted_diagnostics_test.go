//go:build diagnostics

package storage

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	"github.com/thomas-vilte/mls-go/group"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

// Additional diagnostics for the group binding of EncryptedStore.

// diagnosticStoreKey returns the fixed key of the diagnostic stores.
func diagnosticStoreKey() []byte { return bytes.Repeat([]byte{0x6B}, 32) }

// sealDiagnosticLegacyBlob seals state as nonce || AES-GCM(state) without AAD, the format EncryptedStore wrote
// before the group binding.
func sealDiagnosticLegacyBlob(t *testing.T, key, state []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return append(nonce, gcm.Seal(nil, nonce, state, nil)...)
}

// TestEncryptedStoreLegacyBlobHasNoGroupBinding documents that a legacy blob copied into the entry of another
// group loads by default, until the group is saved again. The Client refuses a state whose group ID does not
// match, and WithRejectLegacyBlobs refuses legacy blobs in the store.
func TestEncryptedStoreLegacyBlobHasNoGroupBinding(t *testing.T) {
	ctx := context.Background()
	key := diagnosticStoreKey()
	inner := memorystore.NewStore()
	store, err := NewEncryptedStore(inner, key)
	if err != nil {
		t.Fatalf("NewEncryptedStore: %v", err)
	}
	gidA := group.NewGroupID([]byte("group-A"))
	stateB := []byte("state of group B")
	if err := inner.SaveGroupState(ctx, gidA, sealDiagnosticLegacyBlob(t, key, stateB)); err != nil {
		t.Fatalf("inner.SaveGroupState: %v", err)
	}
	got, err := store.LoadGroupState(ctx, gidA)
	if err != nil || !bytes.Equal(got, stateB) {
		t.Fatalf("LoadGroupState(A) with a legacy blob = %q, %v; want the legacy state", got, err)
	}
	t.Logf("a legacy blob has no group binding and loads under any group until it is saved again; WithRejectLegacyBlobs refuses it")
}

// TestEncryptedStoreRejectsCurrentBlobCopiedAcrossGroups checks that a current blob of B copied into the entry
// of A is refused, also with its header stripped.
func TestEncryptedStoreRejectsCurrentBlobCopiedAcrossGroups(t *testing.T) {
	ctx := context.Background()
	key := diagnosticStoreKey()
	inner := memorystore.NewStore()
	store, err := NewEncryptedStore(inner, key)
	if err != nil {
		t.Fatalf("NewEncryptedStore: %v", err)
	}
	gidA := group.NewGroupID([]byte("group-A"))
	gidB := group.NewGroupID([]byte("group-B"))
	if err := store.SaveGroupState(ctx, gidB, []byte("state B")); err != nil {
		t.Fatalf("SaveGroupState(B): %v", err)
	}
	blobB, err := inner.LoadGroupState(ctx, gidB)
	if err != nil {
		t.Fatalf("inner.LoadGroupState(B): %v", err)
	}

	if err := inner.SaveGroupState(ctx, gidA, blobB); err != nil {
		t.Fatalf("inner.SaveGroupState(copy): %v", err)
	}
	if got, err := store.LoadGroupState(ctx, gidA); err == nil {
		t.Errorf("LoadGroupState(A) accepted B's current-format blob and returned %q", got)
	}

	// Without the 5 header bytes, the rest looks like a legacy blob of B.
	if err := inner.SaveGroupState(ctx, gidA, blobB[5:]); err != nil {
		t.Fatalf("inner.SaveGroupState(stripped): %v", err)
	}
	if got, err := store.LoadGroupState(ctx, gidA); err == nil {
		t.Errorf("LoadGroupState(A) accepted B's blob with the header stripped and returned %q", got)
	}
}

// TestEncryptedStoreRejectsMalformedBlobsWithoutPanic checks that truncated blobs or blobs with a repeated
// header are refused without a panic, and that a nil group ID is refused too.
func TestEncryptedStoreRejectsMalformedBlobsWithoutPanic(t *testing.T) {
	ctx := context.Background()
	inner := memorystore.NewStore()
	store, err := NewEncryptedStore(inner, diagnosticStoreKey())
	if err != nil {
		t.Fatalf("NewEncryptedStore: %v", err)
	}
	gid := group.NewGroupID([]byte("group-M"))
	inputs := [][]byte{
		nil,
		{},
		[]byte("MLS"),
		[]byte("MLSE"),
		[]byte("MLSE\x01"),
		[]byte("MLSE\x01short"),
		bytes.Repeat([]byte("MLSE\x01"), 4),
	}
	for i, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic on malformed blob %d: %v", i, r)
				}
			}()
			_ = inner.SaveGroupState(ctx, gid, in)
			if got, err := store.LoadGroupState(ctx, gid); err == nil {
				t.Errorf("malformed blob %d accepted, returned %q", i, got)
			}
		}()
	}
	if err := store.SaveGroupState(ctx, nil, []byte("x")); err == nil {
		t.Errorf("SaveGroupState(nil group ID) accepted")
	}
	if _, err := store.LoadGroupState(ctx, nil); err == nil {
		t.Errorf("LoadGroupState(nil group ID) accepted")
	}
}
