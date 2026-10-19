package mls

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

// groupLoadHookStore runs onLoad once, inside LoadGroupState. A read of a group that
// has no registered entry loads it through LoadGroupState without holding c.mu,
// so the hook can register an entry or close the Client at that point.
type groupLoadHookStore struct {
	*memorystore.Store
	onLoad func()
}

func (s *groupLoadHookStore) LoadGroupState(ctx context.Context, groupID *group.ID) ([]byte, error) {
	if f := s.onLoad; f != nil {
		s.onLoad = nil
		f()
	}
	return s.Store.LoadGroupState(ctx, groupID)
}

// randomClientGroupID returns a fresh random group ID, modelling a caller that
// picks arbitrary identifiers.
func randomClientGroupID(t *testing.T) []byte {
	t.Helper()

	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return id
}

// clientGroupEntryCount returns the number of group entries registered on c.
func clientGroupEntryCount(c *Client) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.groupEntries)
}

func TestClientEpochDoesNotRegisterUnknownGroups(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	cs := ciphersuite.MLS128DHKEMP256

	c, err := NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close(c): %v", err)
		}
	})

	for i := 0; i < 1000; i++ {
		if _, err := c.Epoch(ctx, randomClientGroupID(t)); !errors.Is(err, ErrGroupNotFound) {
			t.Fatalf("Epoch with unknown ID %d: err = %v, want ErrGroupNotFound", i, err)
		}
	}
	if n := clientGroupEntryCount(c); n != 0 {
		t.Fatalf("len(groupEntries) = %d after 1000 reads of unknown groups, want 0", n)
	}

	// Control: an existing group still returns its epoch and is registered.
	groupID, err := c.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	epoch, err := c.Epoch(ctx, groupID)
	if err != nil {
		t.Fatalf("Epoch on existing group: %v", err)
	}
	if epoch != 0 {
		t.Fatalf("Epoch on new group = %d, want 0", epoch)
	}
	if n := clientGroupEntryCount(c); n != 1 {
		t.Fatalf("len(groupEntries) = %d after CreateGroup and Epoch, want 1", n)
	}
}

func TestClientReadOperationsDoNotRegisterUnknownGroups(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	cs := ciphersuite.MLS128DHKEMP256

	c, err := NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close(c): %v", err)
		}
	})

	ops := map[string]func(groupID []byte) error{
		"Epoch": func(id []byte) error {
			_, err := c.Epoch(ctx, id)
			return err
		},
		"OwnLeafIndex": func(id []byte) error {
			_, err := c.OwnLeafIndex(ctx, id)
			return err
		},
		"ListMembers": func(id []byte) error {
			_, err := c.ListMembers(ctx, id)
			return err
		},
		"Export": func(id []byte) error {
			_, err := c.Export(ctx, id, "test", nil, 32)
			return err
		},
		"EpochAuthenticator": func(id []byte) error {
			_, err := c.EpochAuthenticator(ctx, id)
			return err
		},
		"ResumptionPSK": func(id []byte) error {
			_, _, err := c.ResumptionPSK(ctx, id)
			return err
		},
		"GroupInfo": func(id []byte) error {
			_, err := c.GroupInfo(ctx, id)
			return err
		},
	}
	for name, op := range ops {
		for i := 0; i < 10; i++ {
			if err := op(randomClientGroupID(t)); !errors.Is(err, ErrGroupNotFound) {
				t.Fatalf("%s with unknown ID: err = %v, want ErrGroupNotFound", name, err)
			}
		}
		if err := op(nil); !errors.Is(err, ErrEmptyGroupID) {
			t.Fatalf("%s with empty ID: err = %v, want ErrEmptyGroupID", name, err)
		}
	}
	if n := clientGroupEntryCount(c); n != 0 {
		t.Fatalf("len(groupEntries) = %d after read-only calls on unknown groups, want 0", n)
	}
}

func TestClientReadStoredGroupRegistersEntry(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	cs := ciphersuite.MLS128DHKEMP256
	store := memorystore.NewStore()

	first, err := NewClient([]byte("alice"), cs, WithStorage(store, store))
	if err != nil {
		t.Fatalf("NewClient(first): %v", err)
	}
	t.Cleanup(func() {
		if err := first.Close(); err != nil {
			t.Errorf("Close(first): %v", err)
		}
	})
	groupID, err := first.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	// A second Client on the same storage starts with no entries, as after a restart.
	second, err := NewClient([]byte("alice"), cs, WithStorage(store, store), WithCacheStrategy(CacheAlways))
	if err != nil {
		t.Fatalf("NewClient(second): %v", err)
	}
	t.Cleanup(func() {
		if err := second.Close(); err != nil {
			t.Errorf("Close(second): %v", err)
		}
	})
	if n := clientGroupEntryCount(second); n != 0 {
		t.Fatalf("len(groupEntries) = %d before any read, want 0", n)
	}
	epoch, err := second.Epoch(ctx, groupID)
	if err != nil {
		t.Fatalf("Epoch after restart: %v", err)
	}
	if epoch != 0 {
		t.Fatalf("Epoch after restart = %d, want 0", epoch)
	}
	if n := clientGroupEntryCount(second); n != 1 {
		t.Fatalf("len(groupEntries) = %d after Epoch on a stored group, want 1", n)
	}
	members, err := second.ListMembers(ctx, groupID)
	if err != nil {
		t.Fatalf("ListMembers after restart: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("ListMembers after restart: %d members, want 1", len(members))
	}
	if n := clientGroupEntryCount(second); n != 1 {
		t.Fatalf("len(groupEntries) = %d after ListMembers, want 1", n)
	}
}

func TestClientReadReusesEntryRegisteredDuringLoad(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	cs := ciphersuite.MLS128DHKEMP256
	store := &groupLoadHookStore{Store: memorystore.NewStore()}

	first, err := NewClient([]byte("alice"), cs, WithStorage(store, store))
	if err != nil {
		t.Fatalf("NewClient(first): %v", err)
	}
	t.Cleanup(func() {
		if err := first.Close(); err != nil {
			t.Errorf("Close(first): %v", err)
		}
	})
	groupID, err := first.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	second, err := NewClient([]byte("alice"), cs, WithStorage(store, store))
	if err != nil {
		t.Fatalf("NewClient(second): %v", err)
	}
	t.Cleanup(func() {
		if err := second.Close(); err != nil {
			t.Errorf("Close(second): %v", err)
		}
	})

	cacheKey := groupCacheKeyBytes(groupID)
	var registered *groupEntry
	store.onLoad = func() {
		// Another operation registers an entry for the group while the read loads it.
		second.mu.Lock()
		registered = second.groupEntries[cacheKey]
		if registered == nil {
			registered = &groupEntry{}
			second.groupEntries[cacheKey] = registered
		}
		second.mu.Unlock()
	}
	epoch, err := second.Epoch(ctx, groupID)
	if err != nil {
		t.Fatalf("Epoch: %v", err)
	}
	if epoch != 0 {
		t.Fatalf("Epoch = %d, want 0", epoch)
	}
	if registered == nil {
		t.Fatal("hook did not run during the load")
	}
	second.mu.Lock()
	current := second.groupEntries[cacheKey]
	second.mu.Unlock()
	if current != registered {
		t.Fatal("Epoch replaced the entry that was registered while the group was loaded")
	}
	if n := clientGroupEntryCount(second); n != 1 {
		t.Fatalf("len(groupEntries) = %d, want 1", n)
	}
}

func TestClientReadFailsWhenClosedDuringLoad(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	cs := ciphersuite.MLS128DHKEMP256
	store := &groupLoadHookStore{Store: memorystore.NewStore()}

	first, err := NewClient([]byte("alice"), cs, WithStorage(store, store))
	if err != nil {
		t.Fatalf("NewClient(first): %v", err)
	}
	t.Cleanup(func() {
		if err := first.Close(); err != nil {
			t.Errorf("Close(first): %v", err)
		}
	})
	groupID, err := first.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	second, err := NewClient([]byte("alice"), cs, WithStorage(store, store))
	if err != nil {
		t.Fatalf("NewClient(second): %v", err)
	}
	t.Cleanup(func() {
		if err := second.Close(); err != nil {
			t.Errorf("Close(second): %v", err)
		}
	})

	var closeErr error
	store.onLoad = func() { closeErr = second.Close() }
	epoch, err := second.Epoch(ctx, groupID)
	if closeErr != nil {
		t.Fatalf("Close: %v", closeErr)
	}
	// A read that finishes after Close must not succeed on the closed Client. This is
	// the contract that Branch documents for the same race (see lockGroup).
	if !errors.Is(err, ErrClientClosed) {
		t.Fatalf("Epoch while Close runs: err = %v, want ErrClientClosed", err)
	}
	if epoch != 0 {
		t.Fatalf("Epoch while Close runs = %d, want 0", epoch)
	}
	if n := clientGroupEntryCount(second); n != 0 {
		t.Fatalf("len(groupEntries) = %d after Close, want 0", n)
	}
}
