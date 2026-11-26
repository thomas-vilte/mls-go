package mls

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

// persistGroup writes the keys first and the group state last. The state is the commit point of the epoch: a
// write that fails, or a context that is cancelled, before the state is saved leaves the stored epoch where it
// was, and the state is never saved ahead of the keys it needs. It used to save the state first, so SelfUpdate
// returned an error with no commit while the stored epoch had already advanced.
//
// The signature key is written once per entry, so the subtests that fail it first mark the entry as "signature
// key not stored", as the entry of a reloaded group is. A cancellation after the state is saved cannot turn into
// an error: the commit is durable and SelfUpdate returns it.

var errInjectedWrite = errors.New("injected store write failure")

// faultyStore is the in-memory store with minimal injection. It can fail StoreSignatureKey, fail
// StoreLeafEncryptionKey, cancel the context right after the first write that completes (cancelAfterFirst), or
// right after SaveGroupState (cancelAfterCommit). Each cancellation fires once. Everything else delegates.
type faultyStore struct {
	*memorystore.Store
	failSig           error
	failLeaf          error
	cancelAfterFirst  context.CancelFunc
	cancelAfterCommit context.CancelFunc
	saved             int
}

func (s *faultyStore) wrote() {
	if s.cancelAfterFirst != nil {
		cancel := s.cancelAfterFirst
		s.cancelAfterFirst = nil
		cancel()
	}
}

func (s *faultyStore) SaveGroupState(ctx context.Context, id *group.ID, state []byte) error {
	if err := s.Store.SaveGroupState(ctx, id, state); err != nil {
		return err
	}
	s.saved++
	if s.cancelAfterCommit != nil {
		cancel := s.cancelAfterCommit
		s.cancelAfterCommit = nil
		cancel()
	}
	s.wrote()
	return nil
}

func (s *faultyStore) StoreSignatureKey(ctx context.Context, id *group.ID, key *ciphersuite.SignaturePrivateKey) error {
	if s.failSig != nil {
		return s.failSig
	}
	if err := s.Store.StoreSignatureKey(ctx, id, key); err != nil {
		return err
	}
	s.wrote()
	return nil
}

func (s *faultyStore) StoreLeafEncryptionKey(ctx context.Context, id *group.ID, leaf group.LeafNodeIndex, key []byte) error {
	if s.failLeaf != nil {
		return s.failLeaf
	}
	if err := s.Store.StoreLeafEncryptionKey(ctx, id, leaf, key); err != nil {
		return err
	}
	s.wrote()
	return nil
}

// newFaultyPair has alice (with a store that can fail) and bob in a two-member group, in the same epoch.
func newFaultyPair(t *testing.T) (alice, bob *Client, st *faultyStore, gid []byte) {
	t.Helper()
	ctx := context.Background()
	st = &faultyStore{Store: memorystore.NewStore()}
	var err error
	if alice, err = NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256, WithStorage(st, st)); err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	if bob, err = NewClient([]byte("bob"), ciphersuite.MLS128DHKEMP256); err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}
	if gid, err = alice.CreateGroup(ctx); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	kp, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes: %v", err)
	}
	_, welcome, err := alice.InviteMember(ctx, gid, kp)
	if err != nil {
		t.Fatalf("InviteMember: %v", err)
	}
	if _, err := bob.JoinGroup(ctx, welcome); err != nil {
		t.Fatalf("JoinGroup: %v", err)
	}
	return alice, bob, st, gid
}

// forgetSignatureKeyWritten clears the mark that the signature key was written, as it is for the entry of a
// reloaded group, so the next persistGroup writes the signature key.
func forgetSignatureKeyWritten(t *testing.T, c *Client, gid []byte) {
	t.Helper()
	c.mu.Lock()
	entry := c.groupEntries[groupCacheKeyBytes(gid)]
	c.mu.Unlock()
	if entry == nil {
		t.Fatal("the group has no registered entry")
	}
	entry.mu.Lock()
	entry.sigKeyStored = false
	entry.mu.Unlock()
}

// storedEpochOf reads the stored epoch straight from the store, without the cache of the Client.
func storedEpochOf(t *testing.T, st *faultyStore, gid []byte) uint64 {
	t.Helper()
	raw, err := st.LoadGroupState(context.Background(), group.NewGroupID(gid))
	if err != nil {
		t.Fatalf("LoadGroupState: %v", err)
	}
	g, err := group.UnmarshalGroupState(raw)
	if err != nil {
		t.Fatalf("UnmarshalGroupState: %v", err)
	}
	return g.Epoch().AsUint64()
}

// bobFollowsAlice has alice send a message in her current epoch and bob read it.
func bobFollowsAlice(ctx context.Context, alice, bob *Client, gid []byte) error {
	msg, err := alice.SendMessage(ctx, gid, []byte("follow-up"))
	if err != nil {
		return fmt.Errorf("alice SendMessage: %w", err)
	}
	if _, err := bob.ReceiveMessage(ctx, gid, msg); err != nil {
		return fmt.Errorf("bob ReceiveMessage: %w", err)
	}
	return nil
}

// TestSelfUpdateWithFailedWriteKeepsStoredEpoch checks that when SelfUpdate fails because a write failed, or
// the context was cancelled, before the state was saved, the stored epoch does not advance and bob can still
// follow alice. A cancellation after the state was saved does not fail SelfUpdate.
func TestSelfUpdateWithFailedWriteKeepsStoredEpoch(t *testing.T) {
	ctx := context.Background()

	requireRefused := func(t *testing.T, alice, bob *Client, st *faultyStore, gid []byte, pre uint64, err, want error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Fatalf("SelfUpdate = %v, want %v", err, want)
		}
		if post := storedEpochOf(t, st, gid); post != pre {
			t.Errorf("SelfUpdate failed without a commit, but the stored epoch moved from %d to %d", pre, post)
		}
		if ferr := bobFollowsAlice(ctx, alice, bob, gid); ferr != nil {
			t.Errorf("bob cannot follow alice after the failure: %v", ferr)
		}
	}

	t.Run("no failure", func(t *testing.T) {
		alice, bob, st, gid := newFaultyPair(t)
		pre := storedEpochOf(t, st, gid)
		commit, err := alice.SelfUpdate(ctx, gid)
		if err != nil {
			t.Fatalf("SelfUpdate: %v", err)
		}
		if post := storedEpochOf(t, st, gid); post != pre+1 {
			t.Fatalf("stored epoch after SelfUpdate = %d, want %d", post, pre+1)
		}
		if err := bob.ProcessCommit(ctx, gid, commit); err != nil {
			t.Fatalf("bob ProcessCommit: %v", err)
		}
		if err := bobFollowsAlice(ctx, alice, bob, gid); err != nil {
			t.Fatalf("bob cannot follow alice: %v", err)
		}
	})

	t.Run("StoreSignatureKey fails", func(t *testing.T) {
		alice, bob, st, gid := newFaultyPair(t)
		pre := storedEpochOf(t, st, gid)
		forgetSignatureKeyWritten(t, alice, gid)
		st.failSig = errInjectedWrite
		_, err := alice.SelfUpdate(ctx, gid)
		st.failSig = nil
		requireRefused(t, alice, bob, st, gid, pre, err, errInjectedWrite)
	})

	t.Run("StoreLeafEncryptionKey fails", func(t *testing.T) {
		alice, bob, st, gid := newFaultyPair(t)
		pre := storedEpochOf(t, st, gid)
		st.failLeaf = errInjectedWrite
		_, err := alice.SelfUpdate(ctx, gid)
		st.failLeaf = nil
		requireRefused(t, alice, bob, st, gid, pre, err, errInjectedWrite)
	})

	t.Run("context cancelled after the first write", func(t *testing.T) {
		alice, bob, st, gid := newFaultyPair(t)
		pre := storedEpochOf(t, st, gid)
		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		st.cancelAfterFirst = cancel
		_, err := alice.SelfUpdate(cctx, gid)
		st.cancelAfterFirst = nil
		requireRefused(t, alice, bob, st, gid, pre, err, context.Canceled)
	})

	t.Run("context cancelled after the commit is saved", func(t *testing.T) {
		alice, bob, st, gid := newFaultyPair(t)
		pre := storedEpochOf(t, st, gid)
		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		st.cancelAfterCommit = cancel
		commit, err := alice.SelfUpdate(cctx, gid)
		st.cancelAfterCommit = nil
		if err != nil {
			t.Fatalf("SelfUpdate with the cancellation after the durable commit = %v, want the commit", err)
		}
		if post := storedEpochOf(t, st, gid); post != pre+1 {
			t.Fatalf("stored epoch = %d, want %d", post, pre+1)
		}
		if err := bob.ProcessCommit(ctx, gid, commit); err != nil {
			t.Fatalf("bob ProcessCommit: %v", err)
		}
		if err := bobFollowsAlice(ctx, alice, bob, gid); err != nil {
			t.Fatalf("bob cannot follow alice: %v", err)
		}
	})
}

// TestFailedCreateGroupLeavesNoEntry checks that when the save of a new group fails, CreateGroup returns the
// error, the Client keeps no entry for the group, and no state was saved: the keys are written first.
func TestFailedCreateGroupLeavesNoEntry(t *testing.T) {
	ctx := context.Background()
	st := &faultyStore{Store: memorystore.NewStore()}
	alice, err := NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256, WithStorage(st, st))
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	st.failSig = errInjectedWrite
	_, err = alice.CreateGroup(ctx)
	st.failSig = nil
	if !errors.Is(err, errInjectedWrite) {
		t.Fatalf("CreateGroup = %v, want the injected failure", err)
	}
	alice.mu.Lock()
	n := len(alice.groupEntries)
	alice.mu.Unlock()
	if n != 0 {
		t.Fatalf("len(groupEntries) = %d after a failed CreateGroup, want 0", n)
	}
	if st.saved != 0 {
		t.Fatalf("group states saved after a failed CreateGroup = %d, want 0", st.saved)
	}
}
