package mls

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/thomas-vilte/mls-go/group"
	filestore "github.com/thomas-vilte/mls-go/storage/file"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

// TestStoreNotFoundErrorsMatchGroupSentinel checks that the not-found errors of the memory and file stores
// match group.ErrGroupStateNotFound, which the Client uses to tell a free group ID from a store failure.
// The mlstest store is checked in its own package.
func TestStoreNotFoundErrorsMatchGroupSentinel(t *testing.T) {
	ctx := context.Background()
	fs, err := filestore.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("filestore.NewStore: %v", err)
	}
	stores := []struct {
		name  string
		store group.GroupStorage
	}{
		{"memory", memorystore.NewStore()},
		{"file", fs},
	}
	missing := group.NewGroupID([]byte("missing-group"))
	for _, s := range stores {
		_, err := s.store.LoadGroupState(ctx, missing)
		if !errors.Is(err, group.ErrGroupStateNotFound) {
			t.Errorf("%s: LoadGroupState(missing group) = %v, want an error matching group.ErrGroupStateNotFound", s.name, err)
		}
	}
}

// opaqueNotFoundStore reports a missing group with its own error instead of group.ErrGroupStateNotFound.
type opaqueNotFoundStore struct {
	*memorystore.Store
}

func (s opaqueNotFoundStore) LoadGroupState(ctx context.Context, groupID *group.ID) ([]byte, error) {
	state, err := s.Store.LoadGroupState(ctx, groupID)
	if errors.Is(err, group.ErrGroupStateNotFound) {
		return nil, errors.New("opaque store: nothing here")
	}
	return state, err
}

// emptyStateStore reports a missing group as no state and no error.
type emptyStateStore struct {
	*memorystore.Store
}

func (s emptyStateStore) LoadGroupState(ctx context.Context, groupID *group.ID) ([]byte, error) {
	state, err := s.Store.LoadGroupState(ctx, groupID)
	if errors.Is(err, group.ErrGroupStateNotFound) {
		return nil, nil
	}
	return state, err
}

// TestStoreWithoutNotFoundContractFailsClosed checks that a store that does not report a missing group with
// group.ErrGroupStateNotFound cannot show that a group ID is free, so CreateGroup fails with the store-contract
// error instead of risking an overwrite, and not with a misleading ErrGroupExists.
func TestStoreWithoutNotFoundContractFailsClosed(t *testing.T) {
	cases := []struct {
		name  string
		store group.GroupStorage
		keys  group.KeyStore
	}{
		{"other error", opaqueNotFoundStore{memorystore.NewStore()}, memorystore.NewStore()},
		{"no state and no error", emptyStateStore{memorystore.NewStore()}, memorystore.NewStore()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newGroupIDTestClient(t, "alice", WithStorage(tc.store, tc.keys))
			_, err := c.CreateGroup(context.Background())
			if err == nil {
				t.Fatal("CreateGroup succeeded with a store that does not follow the not-found contract")
			}
			if errors.Is(err, ErrGroupExists) || !strings.Contains(err.Error(), "group.ErrGroupStateNotFound") {
				t.Fatalf("CreateGroup = %v, want the store-contract error", err)
			}
		})
	}
}
