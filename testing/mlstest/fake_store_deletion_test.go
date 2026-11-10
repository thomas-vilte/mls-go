package mlstest

import (
	"context"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go"
	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// Tests for the Client when the store cannot delete the local state of a group that the client has left or been
// removed from. The client still forgets the group, and LeaveGroup still returns the leave proposal, which the
// remaining members need. The store is a FakeStore with injected deletion failures.

// errInjectedDelete is the error that the FakeStore returns when a deletion is made to fail.
var errInjectedDelete = errors.New("mlstest: injected deletion failure")

// newFakeStorePair creates a two-member group. Alice creates it, and bob joins as leaf 1 with bobStore and the
// given cache strategy. Both clients are closed when the test ends.
func newFakeStorePair(t *testing.T, bobStore *FakeStore, strategy mls.CacheStrategy) (alice, bob *mls.Client, groupID []byte) {
	t.Helper()
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMX25519
	alice, err := mls.NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	bob, err = mls.NewClient([]byte("bob"), cs, mls.WithStorage(bobStore, bobStore), mls.WithCacheStrategy(strategy))
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}
	t.Cleanup(func() {
		_ = alice.Close()
		_ = bob.Close()
	})
	groupID, err = alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes: %v", err)
	}
	_, welcome, err := alice.InviteMember(ctx, groupID, bobKP)
	if err != nil {
		t.Fatalf("InviteMember: %v", err)
	}
	if _, err := bob.JoinGroup(ctx, welcome); err != nil {
		t.Fatalf("JoinGroup: %v", err)
	}
	return alice, bob, groupID
}

// cacheStrategies lists the cache strategies that these tests run with. With CacheAlways the client
// keeps the group in memory, so a stale group pointer must not be usable after the group is forgotten.
var cacheStrategies = []struct {
	name     string
	strategy mls.CacheStrategy
}{
	{name: "CacheNone", strategy: mls.CacheNone},
	{name: "CacheAlways", strategy: mls.CacheAlways},
}

// TestFakeStoreRemovedMemberCannotOperateWhenDeletionFails checks that a member removed by a commit whose group
// state cannot be deleted gets ErrRemovedFromGroup, and that no later operation uses the group, although the store
// still holds the state.
func TestFakeStoreRemovedMemberCannotOperateWhenDeletionFails(t *testing.T) {
	t.Parallel()
	for _, tc := range cacheStrategies {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := NewFakeStore()
			alice, bob, gid := newFakeStorePair(t, store, tc.strategy)
			commit, err := alice.RemoveMember(ctx, gid, []byte("bob"))
			if err != nil {
				t.Fatalf("RemoveMember: %v", err)
			}
			store.FailDelete = true
			store.DeleteErr = errInjectedDelete
			if err := bob.ProcessCommit(ctx, gid, commit); !errors.Is(err, mls.ErrRemovedFromGroup) || !errors.Is(err, errInjectedDelete) {
				t.Fatalf("ProcessCommit(remove bob) = %v, want ErrRemovedFromGroup wrapping the deletion error", err)
			}
			ops := []struct {
				name string
				run  func() error
			}{
				{"SendMessage", func() error { _, err := bob.SendMessage(ctx, gid, []byte("after removal")); return err }},
				{"Epoch", func() error { _, err := bob.Epoch(ctx, gid); return err }},
				{"ListMembers", func() error { _, err := bob.ListMembers(ctx, gid); return err }},
				{"ProcessCommit", func() error { return bob.ProcessCommit(ctx, gid, commit) }},
				{"LeaveGroup", func() error { _, err := bob.LeaveGroup(ctx, gid); return err }},
			}
			for _, op := range ops {
				if err := op.run(); !errors.Is(err, mls.ErrGroupNotFound) {
					t.Errorf("%s after removal = %v, want ErrGroupNotFound", op.name, err)
				}
			}
		})
	}
}

// TestFakeStoreLeaveReturnsProposalWhenDeletionFails checks that, when the group state or the leaf keys cannot be
// deleted, LeaveGroup still returns the leave proposal together with the error. This client forgets the group, and
// the remaining member can process the proposal and commit it.
func TestFakeStoreLeaveReturnsProposalWhenDeletionFails(t *testing.T) {
	t.Parallel()
	failures := []struct {
		name   string
		inject func(*FakeStore)
	}{
		{"GroupState", func(s *FakeStore) { s.FailDelete = true; s.DeleteErr = errInjectedDelete }},
		{"LeafKeys", func(s *FakeStore) { s.FailDeleteLeaf = true; s.DeleteLeafErr = errInjectedDelete }},
	}
	for _, failure := range failures {
		for _, tc := range cacheStrategies {
			t.Run(failure.name+"/"+tc.name, func(t *testing.T) {
				ctx := context.Background()
				store := NewFakeStore()
				alice, bob, gid := newFakeStorePair(t, store, tc.strategy)
				failure.inject(store)
				proposal, err := bob.LeaveGroup(ctx, gid)
				if !errors.Is(err, errInjectedDelete) {
					t.Fatalf("LeaveGroup error = %v, want the injected deletion error", err)
				}
				if len(proposal) == 0 {
					t.Fatal("LeaveGroup returned no proposal although the proposal was created")
				}
				if _, err := bob.Epoch(ctx, gid); !errors.Is(err, mls.ErrGroupNotFound) {
					t.Errorf("Epoch after LeaveGroup = %v, want ErrGroupNotFound", err)
				}
				if _, err := bob.LeaveGroup(ctx, gid); !errors.Is(err, mls.ErrGroupNotFound) {
					t.Errorf("second LeaveGroup = %v, want ErrGroupNotFound (no second proposal)", err)
				}
				// The remaining member can process the returned proposal and commit it, which removes bob.
				if err := alice.ProcessPublicMessage(ctx, gid, proposal); err != nil {
					t.Fatalf("alice ProcessPublicMessage(leave proposal): %v", err)
				}
				if _, _, err := alice.CommitPendingProposals(ctx, gid); err != nil {
					t.Fatalf("alice CommitPendingProposals: %v", err)
				}
				members, err := alice.ListMembers(ctx, gid)
				if err != nil {
					t.Fatalf("ListMembers: %v", err)
				}
				if len(members) != 1 {
					t.Errorf("members after bob left = %d, want 1", len(members))
				}
			})
		}
	}
}
