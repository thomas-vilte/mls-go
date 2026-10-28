package storage

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/group"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

// TestEncryptedStoreBindsStateToGroupID checks that an encrypted group state is bound to its group ID.
// An attacker with write access to the inner store copies the blob of group B over
// the entry of group A; loading A must fail instead of returning B's state.
// Controls: a normal save/load round-trip, a legacy blob (nonce || ciphertext without
// AAD) that must still load, and a legacy blob whose nonce starts with the new header.
func TestEncryptedStoreBindsStateToGroupID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x5A}, 32)
	inner := memorystore.NewStore()
	store, err := NewEncryptedStore(inner, key)
	if err != nil {
		t.Fatalf("creating encrypted store: %v", err)
	}
	groupA := group.NewGroupID([]byte("group-A"))
	groupB := group.NewGroupID([]byte("group-B"))
	stateA := []byte("state of group A")
	stateB := []byte("state of group B")

	// Control: normal save and load for two groups.
	if err := store.SaveGroupState(ctx, groupA, stateA); err != nil {
		t.Fatalf("saving group A: %v", err)
	}
	if err := store.SaveGroupState(ctx, groupB, stateB); err != nil {
		t.Fatalf("saving group B: %v", err)
	}
	if got, err := store.LoadGroupState(ctx, groupA); err != nil || !bytes.Equal(got, stateA) {
		t.Fatalf("control: loading group A = %q, %v; want %q", got, err, stateA)
	}
	if got, err := store.LoadGroupState(ctx, groupB); err != nil || !bytes.Equal(got, stateB) {
		t.Fatalf("control: loading group B = %q, %v; want %q", got, err, stateB)
	}

	// Attack: the blob of group B is copied over the entry of group A in the inner store.
	blobB, err := inner.LoadGroupState(ctx, groupB)
	if err != nil {
		t.Fatalf("loading raw blob of group B: %v", err)
	}
	if err := inner.SaveGroupState(ctx, groupA, blobB); err != nil {
		t.Fatalf("copying blob of group B over group A: %v", err)
	}
	if got, err := store.LoadGroupState(ctx, groupA); !errors.Is(err, ErrInvalidCiphertext) {
		t.Errorf("blob of group B loaded as group A: got %q, err %v; want ErrInvalidCiphertext", got, err)
	}

	// Legacy: a blob written before the group binding (nonce || AES-256-GCM(state), no AAD) must still load.
	legacy := sealLegacyGroupState(t, key, bytes.Repeat([]byte{0x01}, 12), stateA)
	if err := inner.SaveGroupState(ctx, groupA, legacy); err != nil {
		t.Fatalf("saving legacy blob: %v", err)
	}
	if got, err := store.LoadGroupState(ctx, groupA); err != nil || !bytes.Equal(got, stateA) {
		t.Fatalf("legacy: loading blob without AAD = %q, %v; want %q", got, err, stateA)
	}

	// Legacy blob whose nonce starts with the new header bytes "MLSE\x01": the current
	// format fails authentication and the loader must fall back to the legacy format.
	prefixedNonce := []byte("MLSE\x01\x02\x03\x04\x05\x06\x07\x08")
	legacyPrefixed := sealLegacyGroupState(t, key, prefixedNonce, stateB)
	if err := inner.SaveGroupState(ctx, groupA, legacyPrefixed); err != nil {
		t.Fatalf("saving legacy blob with prefixed nonce: %v", err)
	}
	if got, err := store.LoadGroupState(ctx, groupA); err != nil || !bytes.Equal(got, stateB) {
		t.Fatalf("legacy prefixed nonce: loading = %q, %v; want %q", got, err, stateB)
	}

	// Control: a nil group ID is rejected by the inner store and must not panic in the AAD code.
	if err := store.SaveGroupState(ctx, nil, stateA); !errors.Is(err, memorystore.ErrNilGroupID) {
		t.Errorf("saving with nil group ID: err %v; want ErrNilGroupID", err)
	}
	if _, err := store.LoadGroupState(ctx, nil); !errors.Is(err, memorystore.ErrNilGroupID) {
		t.Errorf("loading with nil group ID: err %v; want ErrNilGroupID", err)
	}
}

// sealLegacyGroupState reproduces the legacy format, without group binding: nonce || AES-256-GCM(state) with
// empty additional data.
func sealLegacyGroupState(t *testing.T, key, nonce, state []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("creating AES cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("creating GCM AEAD: %v", err)
	}
	blob := append([]byte(nil), nonce...)
	return append(blob, aead.Seal(nil, nonce, state, nil)...)
}
