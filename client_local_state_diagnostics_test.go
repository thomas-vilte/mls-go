//go:build diagnostics

package mls

import (
	"context"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

// Additional diagnostics for the local group state of the Client.

// stateDeleteFailingStore fails DeleteGroupState and leaves the rest of the store unchanged.
type stateDeleteFailingStore struct {
	*memorystore.Store
}

func (stateDeleteFailingStore) DeleteGroupState(context.Context, *group.ID) error {
	return errors.New("test: injected group state delete failure")
}

// newThreeMemberClientGroup creates alice (leaf 0), bob (leaf 1, with bobStore) and carol (leaf 2) in one group.
func newThreeMemberClientGroup(t *testing.T, bobStore clientTestStore) (alice, bob, carol *Client, gid []byte) {
	t.Helper()
	ctx := context.Background()
	alice, bob, gid = newTwoMemberClientGroup(t, bobStore, CacheNone)
	var err error
	carol, err = NewClient([]byte("carol"), ciphersuite.MLS128DHKEMX25519)
	if err != nil {
		t.Fatalf("NewClient(carol): %v", err)
	}
	t.Cleanup(func() { _ = carol.Close() })
	carolKP, err := carol.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(carol): %v", err)
	}
	commit, welcome, err := alice.InviteMember(ctx, gid, carolKP)
	if err != nil {
		t.Fatalf("InviteMember(carol): %v", err)
	}
	if err := bob.ProcessCommit(ctx, gid, commit); err != nil {
		t.Fatalf("bob ProcessCommit(invite carol): %v", err)
	}
	if _, err := carol.JoinGroup(ctx, welcome); err != nil {
		t.Fatalf("carol JoinGroup: %v", err)
	}
	return alice, bob, carol, gid
}

// TestRemovalWithPathReportsRemovedFromGroup checks that a commit that only removes bob, with a path, reports
// ErrRemovedFromGroup to bob.
func TestRemovalWithPathReportsRemovedFromGroup(t *testing.T) {
	ctx := context.Background()
	alice, bob, carol, gid := newThreeMemberClientGroup(t, memorystore.NewStore())
	_ = carol
	commit, err := alice.RemoveMember(ctx, gid, []byte("bob"))
	if err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if err := bob.ProcessCommit(ctx, gid, commit); !errors.Is(err, ErrRemovedFromGroup) {
		t.Fatalf("ProcessCommit(remove only) = %v, want ErrRemovedFromGroup", err)
	}
	if _, err := bob.Epoch(ctx, gid); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("bob keeps group state after removal: Epoch err = %v", err)
	}
}

// TestRemovalWithRefilledLeafReportsRemovedFromGroup checks that bob is reported as removed when the same
// commit removes him and adds dave into his blanked leaf, so his leaf is no longer the blank one.
func TestRemovalWithRefilledLeafReportsRemovedFromGroup(t *testing.T) {
	ctx := context.Background()
	alice, bob, _, gid := newThreeMemberClientGroup(t, memorystore.NewStore())
	dave, err := NewClient([]byte("dave"), ciphersuite.MLS128DHKEMX25519)
	if err != nil {
		t.Fatalf("NewClient(dave): %v", err)
	}
	t.Cleanup(func() { _ = dave.Close() })
	daveKP, err := dave.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(dave): %v", err)
	}
	if _, err := alice.ProposeRemoveMember(ctx, gid, []byte("bob")); err != nil {
		t.Fatalf("ProposeRemoveMember(bob): %v", err)
	}
	if _, err := alice.ProposeAddMember(ctx, gid, daveKP); err != nil {
		t.Fatalf("ProposeAddMember(dave): %v", err)
	}
	commit, _, err := alice.CommitPendingProposals(ctx, gid)
	if err != nil {
		t.Fatalf("CommitPendingProposals(remove bob + add dave): %v", err)
	}
	err = bob.ProcessCommit(ctx, gid, commit)
	if !errors.Is(err, ErrRemovedFromGroup) {
		t.Errorf("ProcessCommit(remove bob + add dave in one commit) = %v; want ErrRemovedFromGroup (bob's leaf was refilled)", err)
	}
	if _, e := bob.Epoch(ctx, gid); !errors.Is(e, ErrGroupNotFound) {
		t.Errorf("bob still holds the group after being removed (Epoch err = %v); its state and leaf keys were not forgotten", e)
	}
}

// TestRemovedMemberCannotSendWhenStateDeletionFails checks that a removed member cannot keep sending when its
// group state cannot be deleted.
func TestRemovedMemberCannotSendWhenStateDeletionFails(t *testing.T) {
	ctx := context.Background()
	bobStore := stateDeleteFailingStore{Store: memorystore.NewStore()}
	alice, bob, gid := newTwoMemberClientGroup(t, bobStore, CacheNone)
	commit, err := alice.RemoveMember(ctx, gid, []byte("bob"))
	if err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	err = bob.ProcessCommit(ctx, gid, commit)
	if !errors.Is(err, ErrRemovedFromGroup) {
		t.Fatalf("ProcessCommit(remove bob) = %v, want an error wrapping ErrRemovedFromGroup", err)
	}
	if _, sendErr := bob.SendMessage(ctx, gid, []byte("after removal")); sendErr == nil {
		t.Errorf("SendMessage succeeded after removal whose state deletion failed; the removed member keeps operating the group")
	}
}

// TestLeaveCommitIsKeptWhenLeafKeyDeletionFails checks that the leave commit is not lost when the leaf keys
// cannot be deleted after the group state is gone.
func TestLeaveCommitIsKeptWhenLeafKeyDeletionFails(t *testing.T) {
	ctx := context.Background()
	bobStore := failingLeafKeyDeleteStore{Store: memorystore.NewStore(), err: errors.New("test: injected leaf delete failure")}
	_, bob, gid := newTwoMemberClientGroup(t, bobStore, CacheNone)
	commit, err := bob.LeaveGroup(ctx, gid)
	t.Logf("LeaveGroup: err=%v commitLen=%d", err, len(commit))
	if len(commit) == 0 {
		_, e := bob.Epoch(ctx, gid)
		t.Errorf("LeaveGroup returned no commit (err=%v); local group state is already gone (Epoch err=%v), so the leave commit is lost and cannot be retried", err, e)
	}
}

// TestClientPlainStoreDoesNotLoadStateOfAnotherGroup checks that, with a plain store, the state of another
// group copied under a group's key is not loaded as that group.
func TestClientPlainStoreDoesNotLoadStateOfAnotherGroup(t *testing.T) {
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMX25519
	store := memorystore.NewStore()
	bob, err := NewClient([]byte("bob"), cs, WithStorage(store, store))
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}
	t.Cleanup(func() { _ = bob.Close() })

	join := func(identity string) []byte {
		alice, err := NewClient([]byte(identity), cs)
		if err != nil {
			t.Fatalf("NewClient(%s): %v", identity, err)
		}
		t.Cleanup(func() { _ = alice.Close() })
		gid, err := alice.CreateGroup(ctx)
		if err != nil {
			t.Fatalf("CreateGroup(%s): %v", identity, err)
		}
		kp, err := bob.FreshKeyPackageBytes(ctx)
		if err != nil {
			t.Fatalf("FreshKeyPackageBytes: %v", err)
		}
		_, welcome, err := alice.InviteMember(ctx, gid, kp)
		if err != nil {
			t.Fatalf("InviteMember(%s): %v", identity, err)
		}
		if _, err := bob.JoinGroup(ctx, welcome); err != nil {
			t.Fatalf("JoinGroup(%s): %v", identity, err)
		}
		return gid
	}
	gid1 := join("alice1")
	gid2 := join("alice2")

	st2, err := store.LoadGroupState(ctx, group.NewGroupID(gid2))
	if err != nil {
		t.Fatalf("LoadGroupState(gid2): %v", err)
	}
	if err := store.SaveGroupState(ctx, group.NewGroupID(gid1), st2); err != nil {
		t.Fatalf("SaveGroupState(swap): %v", err)
	}
	members, err := bob.ListMembers(ctx, gid1)
	if err != nil {
		t.Logf("ListMembers(gid1) after swap: err=%v (refused as expected)", err)
		return
	}
	for _, m := range members {
		if string(m.Identity) == "alice2" {
			t.Errorf("ListMembers(gid1) returned alice2, a member of gid2: the state of gid2 was loaded under gid1 without error")
		}
	}
}
