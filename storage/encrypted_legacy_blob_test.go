package storage

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/group"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

// TestEncryptedStoreLoadsLegacyBlobsByDefault checks that a legacy blob (nonce || ciphertext without AAD) loads
// by default, so that groups stored by v1.6.0 keep working.
func TestEncryptedStoreLoadsLegacyBlobsByDefault(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x3C}, 32)
	inner := memorystore.NewStore()
	store, err := NewEncryptedStore(inner, key)
	if err != nil {
		t.Fatalf("NewEncryptedStore: %v", err)
	}
	gid := group.NewGroupID([]byte("group-L"))
	state := []byte("legacy state of group L")
	if err := inner.SaveGroupState(ctx, gid, sealLegacyGroupState(t, key, bytes.Repeat([]byte{0x02}, 12), state)); err != nil {
		t.Fatalf("saving legacy blob: %v", err)
	}
	got, err := store.LoadGroupState(ctx, gid)
	if err != nil || !bytes.Equal(got, state) {
		t.Fatalf("default store: loading legacy blob = %q, %v; want %q", got, err, state)
	}
}

// TestEncryptedStoreRejectLegacyBlobsRefusesLegacyAndForeignBlobs checks that WithRejectLegacyBlobs refuses a
// legacy blob, and that a current blob loads for its own group but not under the key of another group.
func TestEncryptedStoreRejectLegacyBlobsRefusesLegacyAndForeignBlobs(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x3C}, 32)
	inner := memorystore.NewStore()
	store, err := NewEncryptedStore(inner, key, WithRejectLegacyBlobs())
	if err != nil {
		t.Fatalf("NewEncryptedStore(WithRejectLegacyBlobs): %v", err)
	}
	gidA := group.NewGroupID([]byte("group-A"))
	gidB := group.NewGroupID([]byte("group-B"))

	// A legacy blob of A is refused.
	legacy := sealLegacyGroupState(t, key, bytes.Repeat([]byte{0x02}, 12), []byte("state A"))
	if err := inner.SaveGroupState(ctx, gidA, legacy); err != nil {
		t.Fatalf("saving legacy blob: %v", err)
	}
	if got, err := store.LoadGroupState(ctx, gidA); !errors.Is(err, ErrInvalidCiphertext) {
		t.Errorf("legacy blob loaded with WithRejectLegacyBlobs: got %q, err %v; want ErrInvalidCiphertext", got, err)
	}

	// A current-format blob loads for its own group ...
	stateB := []byte("state B")
	if err := store.SaveGroupState(ctx, gidB, stateB); err != nil {
		t.Fatalf("SaveGroupState(B): %v", err)
	}
	if got, err := store.LoadGroupState(ctx, gidB); err != nil || !bytes.Equal(got, stateB) {
		t.Fatalf("current blob of B: loading = %q, %v; want %q", got, err, stateB)
	}
	// ... and is refused under the key of another group.
	blobB, err := inner.LoadGroupState(ctx, gidB)
	if err != nil {
		t.Fatalf("inner.LoadGroupState(B): %v", err)
	}
	if err := inner.SaveGroupState(ctx, gidA, blobB); err != nil {
		t.Fatalf("copying blob of B over A: %v", err)
	}
	if got, err := store.LoadGroupState(ctx, gidA); !errors.Is(err, ErrInvalidCiphertext) {
		t.Errorf("blob of B loaded as A: got %q, err %v; want ErrInvalidCiphertext", got, err)
	}
}
