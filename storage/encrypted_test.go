package storage

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/group"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

func TestNewEncryptedStoreValidation(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	if _, err := NewEncryptedStore(nil, key); !errors.Is(err, ErrNilInnerStore) {
		t.Fatalf("expected ErrNilInnerStore, got %v", err)
	}
	if _, err := NewEncryptedStore(memorystore.NewStore(), []byte("short")); !errors.Is(err, ErrInvalidEncryptionKey) {
		t.Fatalf("expected ErrInvalidEncryptionKey, got %v", err)
	}
}

func TestEncryptedStoreRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	inner := memorystore.NewStore()
	key := bytes.Repeat([]byte{0x11}, 32)
	store, err := NewEncryptedStore(inner, key)
	if err != nil {
		t.Fatalf("creating encrypted store: %v", err)
	}
	groupID, err := group.NewGroupIDRandom()
	if err != nil {
		t.Fatalf("creating group ID: %v", err)
	}
	plaintext := []byte("secret group state")
	if err := store.SaveGroupState(ctx, groupID, plaintext); err != nil {
		t.Fatalf("saving encrypted group state: %v", err)
	}
	raw, err := inner.LoadGroupState(ctx, groupID)
	if err != nil {
		t.Fatalf("loading raw inner state: %v", err)
	}
	if bytes.Equal(raw, plaintext) {
		t.Fatal("inner store should not contain plaintext state")
	}
	got, err := store.LoadGroupState(ctx, groupID)
	if err != nil {
		t.Fatalf("loading decrypted state: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted state = %q, want %q", got, plaintext)
	}
}

func TestEncryptedStoreTamperDetection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	inner := memorystore.NewStore()
	key := bytes.Repeat([]byte{0x22}, 32)
	store, err := NewEncryptedStore(inner, key)
	if err != nil {
		t.Fatalf("creating encrypted store: %v", err)
	}
	groupID, err := group.NewGroupIDRandom()
	if err != nil {
		t.Fatalf("creating group ID: %v", err)
	}
	if err := store.SaveGroupState(ctx, groupID, []byte("secret")); err != nil {
		t.Fatalf("saving encrypted group state: %v", err)
	}
	raw, err := inner.LoadGroupState(ctx, groupID)
	if err != nil {
		t.Fatalf("loading raw inner state: %v", err)
	}
	raw[len(raw)-1] ^= 0xFF
	if err := inner.SaveGroupState(ctx, groupID, raw); err != nil {
		t.Fatalf("tampering raw inner state: %v", err)
	}
	if _, err := store.LoadGroupState(ctx, groupID); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("expected ErrInvalidCiphertext, got %v", err)
	}
}

func TestEncryptedStoreRejectsShortCiphertext(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	inner := memorystore.NewStore()
	key := bytes.Repeat([]byte{0x33}, 32)
	store, err := NewEncryptedStore(inner, key)
	if err != nil {
		t.Fatalf("creating encrypted store: %v", err)
	}
	groupID, err := group.NewGroupIDRandom()
	if err != nil {
		t.Fatalf("creating group ID: %v", err)
	}
	if err := inner.SaveGroupState(ctx, groupID, []byte{0x01, 0x02}); err != nil {
		t.Fatalf("saving short blob: %v", err)
	}
	if _, err := store.LoadGroupState(ctx, groupID); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("expected ErrInvalidCiphertext, got %v", err)
	}
}

func TestEncryptedStoreDeleteAndContext(t *testing.T) {
	t.Parallel()
	inner := memorystore.NewStore()
	key := bytes.Repeat([]byte{0x44}, 32)
	store, err := NewEncryptedStore(inner, key)
	if err != nil {
		t.Fatalf("creating encrypted store: %v", err)
	}
	groupID, err := group.NewGroupIDRandom()
	if err != nil {
		t.Fatalf("creating group ID: %v", err)
	}
	ctx := context.Background()
	if err := store.SaveGroupState(ctx, groupID, []byte("secret")); err != nil {
		t.Fatalf("saving encrypted group state: %v", err)
	}
	if err := store.DeleteGroupState(ctx, groupID); err != nil {
		t.Fatalf("deleting encrypted group state: %v", err)
	}
	if _, err := inner.LoadGroupState(ctx, groupID); !errors.Is(err, memorystore.ErrGroupStateNotFound) {
		t.Fatalf("expected inner store deletion, got %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.SaveGroupState(canceled, groupID, []byte("secret")); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled on save, got %v", err)
	}
	if _, err := store.LoadGroupState(canceled, groupID); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled on load, got %v", err)
	}
	if err := store.DeleteGroupState(canceled, groupID); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled on delete, got %v", err)
	}
}
