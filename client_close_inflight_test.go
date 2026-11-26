package mls

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

// Close waits for the PendingCommitHandles that are outstanding, and, together with every write to the store, it
// is ordered by a gate: a write holds it for reading and refuses to run once the store is closed, and Close
// takes it for writing before it closes the store. The tests below pause an operation at a known point of the
// store and call Close meanwhile.

// hookedStore wraps the in-memory store. It counts the writes, counts those that happen after Close was
// called, and can pause SaveGroupState or LoadGroupState with one-shot hooks.
type hookedStore struct {
	*memorystore.Store

	mu               sync.Mutex
	beforeSave       func()
	beforeLoad       func()
	writes           int
	writesAfterClose int
	closeCalls       int
}

func newHookedStore() *hookedStore {
	return &hookedStore{Store: memorystore.NewStore()}
}

func (s *hookedStore) setBeforeSave(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.beforeSave = f
}

func (s *hookedStore) setBeforeLoad(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.beforeLoad = f
}

func (s *hookedStore) recordWrite() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes++
	if s.closeCalls > 0 {
		s.writesAfterClose++
	}
}

func (s *hookedStore) counts() (writes, writesAfterClose, closeCalls int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes, s.writesAfterClose, s.closeCalls
}

func (s *hookedStore) SaveGroupState(ctx context.Context, groupID *group.ID, state []byte) error {
	s.mu.Lock()
	hook := s.beforeSave
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
	s.recordWrite()
	return s.Store.SaveGroupState(ctx, groupID, state)
}

func (s *hookedStore) LoadGroupState(ctx context.Context, groupID *group.ID) ([]byte, error) {
	s.mu.Lock()
	hook := s.beforeLoad
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
	return s.Store.LoadGroupState(ctx, groupID)
}

func (s *hookedStore) StoreSignatureKey(ctx context.Context, groupID *group.ID, key *ciphersuite.SignaturePrivateKey) error {
	s.recordWrite()
	return s.Store.StoreSignatureKey(ctx, groupID, key)
}

func (s *hookedStore) StoreLeafEncryptionKey(ctx context.Context, groupID *group.ID, leafIndex group.LeafNodeIndex, key []byte) error {
	s.recordWrite()
	return s.Store.StoreLeafEncryptionKey(ctx, groupID, leafIndex, key)
}

// Close implements io.Closer. Client.Close calls it through the combined store.
func (s *hookedStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeCalls++
	return nil
}

// newHookedClient creates a CacheNone client on st. A nil st leaves the default in-memory storage.
func newHookedClient(t *testing.T, name string, st *hookedStore) *Client {
	t.Helper()
	opts := []ClientOption{WithCacheStrategy(CacheNone)}
	if st != nil {
		opts = append(opts, WithStorage(st, st))
	}
	c, err := NewClient([]byte(name), ciphersuite.MLS128DHKEMP256, opts...)
	if err != nil {
		t.Fatalf("NewClient(%s): %v", name, err)
	}
	return c
}

// waitForClose returns (true, err) if Close finished within d, or (false, nil) if it is still blocked.
func waitForClose(done <-chan error, d time.Duration) (bool, error) {
	select {
	case err := <-done:
		return true, err
	case <-time.After(d):
		return false, nil
	}
}

// TestCloseWaitsForOperationInFlight checks that Close does not return, and does not close the store, while an
// operation that already passed the open check is paused inside SaveGroupState, and that no write reaches the
// store after Close.
func TestCloseWaitsForOperationInFlight(t *testing.T) {
	ops := []struct {
		name string
		run  func(ctx context.Context, c *Client, gid []byte) error
	}{
		{"SendMessage", func(ctx context.Context, c *Client, gid []byte) error {
			_, err := c.SendMessage(ctx, gid, []byte("payload"))
			return err
		}},
		{"SelfUpdate", func(ctx context.Context, c *Client, gid []byte) error {
			_, err := c.SelfUpdate(ctx, gid)
			return err
		}},
	}
	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			ctx := context.Background()
			st := newHookedStore()
			cli := newHookedClient(t, "alice", st)
			gid, err := cli.CreateGroup(ctx)
			if err != nil {
				t.Fatalf("CreateGroup: %v", err)
			}

			entered := make(chan struct{})
			release := make(chan struct{})
			releaseOnce := sync.OnceFunc(func() { close(release) })
			defer releaseOnce()
			var once sync.Once
			st.setBeforeSave(func() {
				once.Do(func() {
					close(entered)
					<-release
				})
			})

			opDone := make(chan error, 1)
			go func() { opDone <- op.run(ctx, cli, gid) }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("the operation never reached SaveGroupState")
			}

			closeDone := make(chan error, 1)
			go func() { closeDone <- cli.Close() }()
			closedEarly, _ := waitForClose(closeDone, 2*time.Second)

			releaseOnce()
			select {
			case <-opDone:
			case <-time.After(5 * time.Second):
				t.Fatal("the operation did not finish after the hook was released")
			}
			if !closedEarly {
				if returned, cerr := waitForClose(closeDone, 3*time.Second); !returned {
					t.Error("Close did not return after the operation finished")
				} else if cerr != nil {
					t.Errorf("Close: %v", cerr)
				}
			}

			_, writesAfterClose, _ := st.counts()
			if closedEarly {
				t.Error("Close returned while the operation was still in progress inside SaveGroupState")
			}
			if writesAfterClose > 0 {
				t.Errorf("%d write(s) reached the store after Close", writesAfterClose)
			}
		})
	}
}

// TestStagedHandleIsNotCreatedAfterCloseReturned checks that CommitPendingProposalsStaged, paused after the open
// check and before the handle is counted, does not hand out a handle once Close has returned. Confirming such a
// handle would write to a closed store.
func TestStagedHandleIsNotCreatedAfterCloseReturned(t *testing.T) {
	ctx := context.Background()
	st := newHookedStore()
	alice := newHookedClient(t, "alice", st)
	bob := newHookedClient(t, "bob", nil)

	gid, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes: %v", err)
	}
	if _, err := alice.ProposeAddMember(ctx, gid, bobKP); err != nil {
		t.Fatalf("ProposeAddMember: %v", err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	defer releaseOnce()
	var once sync.Once
	st.setBeforeLoad(func() {
		once.Do(func() {
			close(entered)
			<-release
		})
	})

	type stagedResult struct {
		h   *PendingCommitHandle
		err error
	}
	stagedDone := make(chan stagedResult, 1)
	go func() {
		h, err := alice.CommitPendingProposalsStaged(ctx, gid)
		stagedDone <- stagedResult{h, err}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("CommitPendingProposalsStaged never reached LoadGroupState")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- alice.Close() }()
	closedEarly, _ := waitForClose(closeDone, 2*time.Second)

	releaseOnce()
	var res stagedResult
	select {
	case res = <-stagedDone:
	case <-time.After(5 * time.Second):
		t.Fatal("CommitPendingProposalsStaged did not finish after the hook was released")
	}
	if res.err == nil && res.h != nil {
		_, _ = alice.ConfirmPendingCommit(ctx, res.h)
	}
	if !closedEarly {
		if returned, cerr := waitForClose(closeDone, 3*time.Second); !returned {
			t.Error("Close did not return after the handle was resolved")
		} else if cerr != nil {
			t.Errorf("Close: %v", cerr)
		}
	}

	_, writesAfterClose, _ := st.counts()
	if closedEarly && res.err == nil && res.h != nil {
		t.Error("CommitPendingProposalsStaged returned a handle after Close had already returned")
	}
	if writesAfterClose > 0 {
		t.Errorf("%d write(s) reached the store after Close", writesAfterClose)
	}
}

// TestCloseWithoutOperationsInFlight checks the sequential cases: after a SendMessage that finished, Close
// returns at once, closes the store once, no write follows, and a later call fails with ErrClientClosed; a handle
// created before Close blocks it until DiscardPendingCommit releases it; and once Close has completed,
// CommitPendingProposalsStaged is refused.
func TestCloseWithoutOperationsInFlight(t *testing.T) {
	ctx := context.Background()

	t.Run("send then close", func(t *testing.T) {
		st := newHookedStore()
		cli := newHookedClient(t, "alice", st)
		gid, err := cli.CreateGroup(ctx)
		if err != nil {
			t.Fatalf("CreateGroup: %v", err)
		}
		if _, err := cli.SendMessage(ctx, gid, []byte("payload")); err != nil {
			t.Fatalf("SendMessage: %v", err)
		}

		closeDone := make(chan error, 1)
		go func() { closeDone <- cli.Close() }()
		returned, cerr := waitForClose(closeDone, 3*time.Second)
		if !returned {
			t.Fatal("Close is blocked with no operation in progress")
		}
		if cerr != nil {
			t.Fatalf("Close: %v", cerr)
		}
		if _, err := cli.SendMessage(ctx, gid, []byte("after")); !errors.Is(err, ErrClientClosed) {
			t.Fatalf("SendMessage after Close = %v, want ErrClientClosed", err)
		}
		writes, writesAfterClose, closeCalls := st.counts()
		if writes == 0 {
			t.Fatal("no write was counted during SendMessage")
		}
		if closeCalls != 1 {
			t.Fatalf("the store was closed %d times, want 1", closeCalls)
		}
		if writesAfterClose != 0 {
			t.Fatalf("%d write(s) after Close", writesAfterClose)
		}
	})

	t.Run("close waits for a handle created before it", func(t *testing.T) {
		st := newHookedStore()
		alice := newHookedClient(t, "alice", st)
		bob := newHookedClient(t, "bob", nil)
		gid, err := alice.CreateGroup(ctx)
		if err != nil {
			t.Fatalf("CreateGroup: %v", err)
		}
		bobKP, err := bob.FreshKeyPackageBytes(ctx)
		if err != nil {
			t.Fatalf("FreshKeyPackageBytes: %v", err)
		}
		if _, err := alice.ProposeAddMember(ctx, gid, bobKP); err != nil {
			t.Fatalf("ProposeAddMember: %v", err)
		}
		h, err := alice.CommitPendingProposalsStaged(ctx, gid)
		if err != nil {
			t.Fatalf("CommitPendingProposalsStaged: %v", err)
		}

		closeDone := make(chan error, 1)
		go func() { closeDone <- alice.Close() }()
		if returned, _ := waitForClose(closeDone, 300*time.Millisecond); returned {
			t.Fatal("Close returned with a PendingCommitHandle that was not resolved")
		}
		if err := alice.DiscardPendingCommit(ctx, h); err != nil {
			t.Fatalf("DiscardPendingCommit: %v", err)
		}
		returned, cerr := waitForClose(closeDone, 3*time.Second)
		if !returned {
			t.Fatal("Close did not return after DiscardPendingCommit")
		}
		if cerr != nil {
			t.Fatalf("Close: %v", cerr)
		}
		if _, writesAfterClose, _ := st.counts(); writesAfterClose != 0 {
			t.Fatalf("%d write(s) after Close", writesAfterClose)
		}
	})

	t.Run("staging after close is refused", func(t *testing.T) {
		alice := newHookedClient(t, "alice", newHookedStore())
		gid, err := alice.CreateGroup(ctx)
		if err != nil {
			t.Fatalf("CreateGroup: %v", err)
		}
		if err := alice.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		h, err := alice.CommitPendingProposalsStaged(ctx, gid)
		if !errors.Is(err, ErrClientClosed) || h != nil {
			t.Fatalf("CommitPendingProposalsStaged after Close: handle=%v err=%v, want ErrClientClosed", h, err)
		}
	})
}

// TestConfirmPendingCommitWhileCloseWaits checks that Close waits for an unresolved handle, and that
// ConfirmPendingCommit can still save the group meanwhile, because the store is closed only after the handle is
// resolved. Close does not return before the confirmation, the confirmation does not fail, and the confirmed
// epoch is in the store when Close returns.
func TestConfirmPendingCommitWhileCloseWaits(t *testing.T) {
	ctx := context.Background()
	st := memorystore.NewStore()
	alice, err := NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256, WithStorage(st, st))
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	bob, err := NewClient([]byte("bob"), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}
	gid, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes: %v", err)
	}
	if _, err := alice.ProposeAddMember(ctx, gid, bobKP); err != nil {
		t.Fatalf("ProposeAddMember: %v", err)
	}
	h, err := alice.CommitPendingProposalsStaged(ctx, gid)
	if err != nil {
		t.Fatalf("CommitPendingProposalsStaged: %v", err)
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- alice.Close() }()
	if returned, _ := waitForClose(closeDone, 300*time.Millisecond); returned {
		t.Fatal("Close returned with a handle that was not resolved")
	}
	if _, err := alice.ConfirmPendingCommit(ctx, h); err != nil {
		t.Fatalf("ConfirmPendingCommit while Close waits for the handle: %v", err)
	}
	returned, cerr := waitForClose(closeDone, 3*time.Second)
	if !returned {
		t.Fatal("Close did not return after the handle was confirmed")
	}
	if cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}

	raw, err := st.LoadGroupState(ctx, group.NewGroupID(gid))
	if err != nil {
		t.Fatalf("LoadGroupState: %v", err)
	}
	g, err := group.UnmarshalGroupState(raw)
	if err != nil {
		t.Fatalf("UnmarshalGroupState: %v", err)
	}
	if epoch := g.Epoch().AsUint64(); epoch != 1 {
		t.Fatalf("stored epoch after confirming during Close = %d, want 1", epoch)
	}
}
