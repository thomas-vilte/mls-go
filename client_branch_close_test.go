package mls

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

func TestClientBranchConcurrentClose(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	cs := ciphersuite.MLS128DHKEMP256

	// Close is terminal, so each round needs a new client.
	const rounds = 300
	for round := 0; round < rounds; round++ {
		c, err := NewClient([]byte(fmt.Sprintf("alice-%d", round)), cs)
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		groupID, err := c.CreateGroup(ctx)
		if err != nil {
			t.Fatalf("CreateGroup: %v", err)
		}

		start := make(chan struct{})
		errs := make(chan error, 2)

		var wg sync.WaitGroup
		wg.Go(func() {
			defer func() {
				if r := recover(); r != nil {
					errs <- fmt.Errorf("Branch panicked: %v", r)
				}
			}()
			<-start
			if _, _, _, err := c.Branch(ctx, groupID, nil); err != nil && !errors.Is(err, ErrClientClosed) {
				errs <- fmt.Errorf("Branch: %w", err)
			}
		})
		wg.Go(func() {
			<-start
			if err := c.Close(); err != nil {
				errs <- fmt.Errorf("Close: %w", err)
			}
		})

		close(start)
		wg.Wait()
		close(errs)

		for err := range errs {
			t.Fatalf("round %d: %v", round, err)
		}
		if _, _, _, err := c.Branch(ctx, groupID, nil); !errors.Is(err, ErrClientClosed) {
			t.Fatalf("round %d: Branch after Close: err = %v, want ErrClientClosed", round, err)
		}
	}
}

// branchSaveHookStore runs a one-time hook before saving group state.
type branchSaveHookStore struct {
	*memorystore.Store
	onSave func()
}

func (s *branchSaveHookStore) SaveGroupState(ctx context.Context, groupID *group.ID, state []byte) error {
	if hook := s.onSave; hook != nil {
		s.onSave = nil
		hook()
	}
	return s.Store.SaveGroupState(ctx, groupID, state)
}

func TestClientBranchCloseDuringCommit(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	cs := ciphersuite.MLS128DHKEMP256

	store := &branchSaveHookStore{Store: memorystore.NewStore()}
	c, err := NewClient([]byte("alice"), cs, WithStorage(store, store))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	groupID, err := c.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	var closeErr error
	store.onSave = func() { closeErr = c.Close() }

	var branchErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Branch panicked: %v", r)
			}
		}()
		_, _, _, branchErr = c.Branch(ctx, groupID, nil)
	}()

	if closeErr != nil {
		t.Fatalf("Close: %v", closeErr)
	}
	if !errors.Is(branchErr, ErrClientClosed) {
		t.Fatalf("Branch: err = %v, want ErrClientClosed", branchErr)
	}
}
