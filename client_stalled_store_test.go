package mls

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

// stalledStoreProbeLimit is how long the tests wait for Epoch to answer while a store write is stalled. When
// nothing holds a lock across the write, the answer comes in microseconds.
const stalledStoreProbeLimit = time.Second

// stallingStore wraps the in-memory store. While armed, the next SaveGroupState stops until unblock is called.
// The wait happens before the call is delegated to the store, so it holds no lock of the store or of the Client.
type stallingStore struct {
	*memorystore.Store
	armed     atomic.Bool
	entered   chan struct{}
	release   chan struct{}
	enterOnce sync.Once
	relOnce   sync.Once
}

func newStallingStore() *stallingStore {
	return &stallingStore{
		Store:   memorystore.NewStore(),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (s *stallingStore) SaveGroupState(ctx context.Context, id *group.ID, state []byte) error {
	if s.armed.Load() {
		s.enterOnce.Do(func() { close(s.entered) })
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.Store.SaveGroupState(ctx, id, state)
}

func (s *stallingStore) unblock() {
	s.relOnce.Do(func() { close(s.release) })
}

func newStalledStoreClient(t *testing.T, name string, st *stallingStore) *Client {
	t.Helper()
	c, err := NewClient([]byte(name), ciphersuite.MLS128DHKEMP256, WithStorage(st, st))
	if err != nil {
		t.Fatalf("NewClient(%s): %v", name, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// probeWhileWriteStalls arms the store, runs op (an operation of c that writes to the store) and, with that write
// stalled, calls Epoch on probeGID, a different group of the same client. It reports whether Epoch stayed
// blocked until the store was released, and the error of Epoch. It fails the test when op fails or its write
// never reaches the store.
func probeWhileWriteStalls(t *testing.T, st *stallingStore, c *Client, probeGID []byte, op func() error) (blocked bool, probeErr error) {
	t.Helper()
	ctx := context.Background()
	st.armed.Store(true)
	opDone := make(chan error, 1)
	go func() { opDone <- op() }()
	select {
	case <-st.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the write never reached the stalled store")
	}

	probe := make(chan error, 1)
	go func() {
		_, err := c.Epoch(ctx, probeGID)
		probe <- err
	}()
	select {
	case probeErr = <-probe:
	case <-time.After(stalledStoreProbeLimit):
		blocked = true
	}
	st.unblock()
	if blocked {
		select {
		case probeErr = <-probe:
		case <-time.After(5 * time.Second):
			t.Fatal("Epoch is still blocked after the store was released")
		}
	}
	select {
	case err := <-opDone:
		if err != nil {
			t.Fatalf("the stalled operation failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled operation did not finish after the store was released")
	}
	return blocked, probeErr
}

// TestStalledStoreWriteDoesNotBlockOtherGroups checks that a store write of an operation that creates or joins a
// group does not hold the lock of the Client, so Epoch of an unrelated group still answers while the write is
// stalled, as the per-group locks promise. CreateGroup, CreateGroupWithExtensions, JoinGroup and ExternalJoin
// used to save the group with the lock of the Client held. SendMessage, which saves under the lock of its own
// group, is the control.
func TestStalledStoreWriteDoesNotBlockOtherGroups(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		// run prepares the client and returns the unrelated group and the stalled operation.
		run func(t *testing.T, st *stallingStore) (c *Client, probeGID []byte, op func() error)
	}{
		{"CreateGroup", func(t *testing.T, st *stallingStore) (*Client, []byte, func() error) {
			alice := newStalledStoreClient(t, "alice", st)
			g1, err := alice.CreateGroup(ctx)
			if err != nil {
				t.Fatalf("CreateGroup(g1): %v", err)
			}
			return alice, g1, func() error { _, err := alice.CreateGroup(ctx); return err }
		}},
		{"CreateGroupWithExtensions", func(t *testing.T, st *stallingStore) (*Client, []byte, func() error) {
			alice := newStalledStoreClient(t, "alice", st)
			g1, err := alice.CreateGroup(ctx)
			if err != nil {
				t.Fatalf("CreateGroup(g1): %v", err)
			}
			kp, err := alice.FreshKeyPackageBytes(ctx)
			if err != nil {
				t.Fatalf("FreshKeyPackageBytes: %v", err)
			}
			return alice, g1, func() error {
				_, err := alice.CreateGroupWithExtensions(ctx, []byte("group-with-extensions"), kp, nil)
				return err
			}
		}},
		{"JoinGroup", func(t *testing.T, st *stallingStore) (*Client, []byte, func() error) {
			alice := newStalledStoreClient(t, "alice", newStallingStore())
			gid, err := alice.CreateGroup(ctx)
			if err != nil {
				t.Fatalf("alice CreateGroup: %v", err)
			}
			bob := newStalledStoreClient(t, "bob", st)
			g1, err := bob.CreateGroup(ctx)
			if err != nil {
				t.Fatalf("bob CreateGroup(g1): %v", err)
			}
			kp, err := bob.FreshKeyPackageBytes(ctx)
			if err != nil {
				t.Fatalf("bob FreshKeyPackageBytes: %v", err)
			}
			_, welcome, err := alice.InviteMember(ctx, gid, kp)
			if err != nil {
				t.Fatalf("alice InviteMember: %v", err)
			}
			return bob, g1, func() error { _, err := bob.JoinGroup(ctx, welcome); return err }
		}},
		{"ExternalJoin", func(t *testing.T, st *stallingStore) (*Client, []byte, func() error) {
			alice := newStalledStoreClient(t, "alice", newStallingStore())
			gid, err := alice.CreateGroup(ctx)
			if err != nil {
				t.Fatalf("alice CreateGroup: %v", err)
			}
			gi, err := alice.GroupInfo(ctx, gid)
			if err != nil {
				t.Fatalf("alice GroupInfo: %v", err)
			}
			bob := newStalledStoreClient(t, "bob", st)
			g1, err := bob.CreateGroup(ctx)
			if err != nil {
				t.Fatalf("bob CreateGroup(g1): %v", err)
			}
			return bob, g1, func() error { _, _, err := bob.ExternalJoin(ctx, gi); return err }
		}},
		{"SendMessage in another group (control)", func(t *testing.T, st *stallingStore) (*Client, []byte, func() error) {
			alice := newStalledStoreClient(t, "alice", st)
			g1, err := alice.CreateGroup(ctx)
			if err != nil {
				t.Fatalf("CreateGroup(g1): %v", err)
			}
			g2, err := alice.CreateGroup(ctx)
			if err != nil {
				t.Fatalf("CreateGroup(g2): %v", err)
			}
			return alice, g1, func() error { _, err := alice.SendMessage(ctx, g2, []byte("control")); return err }
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newStallingStore()
			defer st.unblock()
			c, probeGID, op := tc.run(t, st)
			blocked, probeErr := probeWhileWriteStalls(t, st, c, probeGID, op)
			if probeErr != nil {
				t.Fatalf("Epoch of the other group: %v", probeErr)
			}
			if blocked {
				t.Fatalf("Epoch of another group did not answer within %v while the write was stalled", stalledStoreProbeLimit)
			}
		})
	}
}

// TestCloseWaitsForStalledCreate checks that Close waits for the store write of a CreateGroup that is stalled, and
// does not return before it. When the write is released, the creation completes, the group is stored, and only
// then does Close return nil.
func TestCloseWaitsForStalledCreate(t *testing.T) {
	ctx := context.Background()
	st := newStallingStore()
	defer st.unblock()
	alice := newStalledStoreClient(t, "alice", st)

	st.armed.Store(true)
	type created struct {
		gid []byte
		err error
	}
	createDone := make(chan created, 1)
	go func() {
		gid, err := alice.CreateGroup(ctx)
		createDone <- created{gid, err}
	}()
	select {
	case <-st.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the write of CreateGroup never reached the stalled store")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- alice.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned with the write of CreateGroup in progress (err=%v)", err)
	case <-time.After(300 * time.Millisecond):
	}

	st.unblock()
	res := <-createDone
	if res.err != nil {
		t.Fatalf("CreateGroup with Close waiting: %v", res.err)
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not return after the write finished")
	}
	if _, err := st.LoadGroupState(ctx, group.NewGroupID(res.gid)); err != nil {
		t.Fatalf("the created group was not stored: %v", err)
	}
}
