package file

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/keypackages"
)

func TestNewStoreRequiresDirectory(t *testing.T) {
	t.Parallel()
	if _, err := NewStore(""); !errors.Is(err, ErrEmptyDir) {
		t.Fatalf("expected ErrEmptyDir, got %v", err)
	}
}

func TestStoreGroupStateRoundTrip(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	cred, _, err := credentials.GenerateCredentialWithKeyForCS([]byte("alice"), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating credential: %v", err)
	}
	kp, kpPriv, err := keypackages.Generate(cred, ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating key package: %v", err)
	}
	groupID, err := group.NewGroupIDRandom()
	if err != nil {
		t.Fatalf("generating group ID: %v", err)
	}
	g, err := group.NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kp, kpPriv)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}
	state, err := g.MarshalState()
	if err != nil {
		t.Fatalf("marshaling group state: %v", err)
	}
	if err := store.SaveGroupState(ctx, groupID, state); err != nil {
		t.Fatalf("saving group state: %v", err)
	}
	loadedState, err := store.LoadGroupState(ctx, groupID)
	if err != nil {
		t.Fatalf("loading group state: %v", err)
	}
	restored, err := group.UnmarshalGroupState(loadedState)
	if err != nil {
		t.Fatalf("unmarshaling group state: %v", err)
	}
	if got, want := string(restored.GroupID().AsSlice()), string(g.GroupID().AsSlice()); got != want {
		t.Fatalf("unexpected group ID: got %x want %x", got, want)
	}
	if restored.Epoch() != g.Epoch() {
		t.Fatalf("unexpected epoch: got %d want %d", restored.Epoch(), g.Epoch())
	}
	if restored.CipherSuite() != g.CipherSuite() {
		t.Fatalf("unexpected cipher suite: got %v want %v", restored.CipherSuite(), g.CipherSuite())
	}
	statePath, err := store.groupStatePath(groupID)
	if err != nil {
		t.Fatalf("resolving state path: %v", err)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("expected group state file on disk: %v", err)
	}
}

func TestStoreSignatureKeyRoundTrip(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	groupID, err := group.NewGroupIDRandom()
	if err != nil {
		t.Fatalf("generating group ID: %v", err)
	}
	sigKey, err := ciphersuite.GenerateSignaturePrivateKeyForCS(ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating signature key: %v", err)
	}
	if err := store.StoreSignatureKey(ctx, groupID, sigKey); err != nil {
		t.Fatalf("storing signature key: %v", err)
	}
	loadedKey, err := store.LoadSignatureKey(ctx, groupID)
	if err != nil {
		t.Fatalf("loading signature key: %v", err)
	}
	if !bytes.Equal(loadedKey.PublicKey().AsSlice(), sigKey.PublicKey().AsSlice()) {
		t.Fatalf("unexpected public key: got %x want %x", loadedKey.PublicKey().AsSlice(), sigKey.PublicKey().AsSlice())
	}
}

func TestStoreLeafEncryptionKeyRoundTrip(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	groupID, err := group.NewGroupIDRandom()
	if err != nil {
		t.Fatalf("generating group ID: %v", err)
	}
	leafIndex := group.NewLeafNodeIndex(7)
	leafKeyBytes := []byte("leaf-secret-key-material")
	if err := store.StoreLeafEncryptionKey(ctx, groupID, leafIndex, leafKeyBytes); err != nil {
		t.Fatalf("storing leaf encryption key: %v", err)
	}
	loadedKey, err := store.LoadLeafEncryptionKey(ctx, groupID, leafIndex)
	if err != nil {
		t.Fatalf("loading leaf encryption key: %v", err)
	}
	if !bytes.Equal(loadedKey, leafKeyBytes) {
		t.Fatalf("unexpected leaf key: got %x want %x", loadedKey, leafKeyBytes)
	}
	leafPath, err := store.leafKeyPath(groupID, leafIndex)
	if err != nil {
		t.Fatalf("resolving leaf path: %v", err)
	}
	if _, err := os.Stat(leafPath); err != nil {
		t.Fatalf("expected leaf key file on disk: %v", err)
	}
}

func TestStoreReturnsCopies(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	groupID, err := group.NewGroupIDRandom()
	if err != nil {
		t.Fatalf("generating group ID: %v", err)
	}
	state := []byte("group-state")
	if err := store.SaveGroupState(ctx, groupID, state); err != nil {
		t.Fatalf("saving group state: %v", err)
	}
	loadedState, err := store.LoadGroupState(ctx, groupID)
	if err != nil {
		t.Fatalf("loading group state: %v", err)
	}
	loadedState[0] = 'X'
	loadedStateAgain, err := store.LoadGroupState(ctx, groupID)
	if err != nil {
		t.Fatalf("loading group state again: %v", err)
	}
	if string(loadedStateAgain) != "group-state" {
		t.Fatalf("store returned aliased state: got %q", loadedStateAgain)
	}
	leafIndex := group.NewLeafNodeIndex(1)
	leafKeyBytes := []byte("leaf-key")
	if err := store.StoreLeafEncryptionKey(ctx, groupID, leafIndex, leafKeyBytes); err != nil {
		t.Fatalf("storing leaf key: %v", err)
	}
	loadedLeafKey, err := store.LoadLeafEncryptionKey(ctx, groupID, leafIndex)
	if err != nil {
		t.Fatalf("loading leaf key: %v", err)
	}
	loadedLeafKey[0] = 'X'
	loadedLeafKeyAgain, err := store.LoadLeafEncryptionKey(ctx, groupID, leafIndex)
	if err != nil {
		t.Fatalf("loading leaf key again: %v", err)
	}
	if string(loadedLeafKeyAgain) != "leaf-key" {
		t.Fatalf("store returned aliased leaf key: got %q", loadedLeafKeyAgain)
	}
}

func TestStoreNotFoundErrors(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	groupID, err := group.NewGroupIDRandom()
	if err != nil {
		t.Fatalf("generating group ID: %v", err)
	}
	if _, err := store.LoadGroupState(ctx, groupID); !errors.Is(err, ErrGroupStateNotFound) {
		t.Fatalf("expected ErrGroupStateNotFound, got %v", err)
	}
	if _, err := store.LoadSignatureKey(ctx, groupID); !errors.Is(err, ErrSignatureKeyNotFound) {
		t.Fatalf("expected ErrSignatureKeyNotFound, got %v", err)
	}
	if _, err := store.LoadLeafEncryptionKey(ctx, groupID, group.NewLeafNodeIndex(0)); !errors.Is(err, ErrLeafKeyNotFound) {
		t.Fatalf("expected ErrLeafKeyNotFound, got %v", err)
	}
}

func TestStoreDeleteGroupState(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	groupID, err := group.NewGroupIDRandom()
	if err != nil {
		t.Fatalf("generating group ID: %v", err)
	}
	if err := store.SaveGroupState(ctx, groupID, []byte("state")); err != nil {
		t.Fatalf("saving group state: %v", err)
	}
	if err := store.DeleteGroupState(ctx, groupID); err != nil {
		t.Fatalf("deleting group state: %v", err)
	}
	if _, err := store.LoadGroupState(ctx, groupID); !errors.Is(err, ErrGroupStateNotFound) {
		t.Fatalf("expected ErrGroupStateNotFound after delete, got %v", err)
	}
}

func TestStoreHonorsCanceledContext(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	groupID, err := group.NewGroupIDRandom()
	if err != nil {
		t.Fatalf("generating group ID: %v", err)
	}
	if err := store.SaveGroupState(ctx, groupID, []byte("state")); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if _, err := store.LoadGroupState(ctx, groupID); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if err := store.DeleteGroupState(ctx, groupID); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	sigKey, err := ciphersuite.GenerateSignaturePrivateKeyForCS(ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating signature key: %v", err)
	}
	if err := store.StoreSignatureKey(ctx, groupID, sigKey); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if _, err := store.LoadSignatureKey(ctx, groupID); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if err := store.StoreLeafEncryptionKey(ctx, groupID, group.NewLeafNodeIndex(0), []byte("key")); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if _, err := store.LoadLeafEncryptionKey(ctx, groupID, group.NewLeafNodeIndex(0)); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "store")
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("creating store: %v", err)
	}
	return store
}
