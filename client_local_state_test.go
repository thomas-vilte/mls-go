package mls

import (
	"context"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

// errGroupStateDelete is the error that failingGroupStateDeleteStore returns when the group state cannot be deleted.
var errGroupStateDelete = errors.New("test: group state cannot be deleted")

// failingGroupStateDeleteStore is an in-memory store whose DeleteGroupState always fails. It counts the calls to
// DeleteLeafEncryptionKeys, which still succeed.
type failingGroupStateDeleteStore struct {
	*memorystore.Store
	leafDeletes int
}

// DeleteGroupState fails with errGroupStateDelete and deletes nothing.
func (s *failingGroupStateDeleteStore) DeleteGroupState(context.Context, *group.ID) error {
	return errGroupStateDelete
}

// DeleteLeafEncryptionKeys counts the call and deletes the leaf keys.
func (s *failingGroupStateDeleteStore) DeleteLeafEncryptionKeys(ctx context.Context, groupID *group.ID) error {
	s.leafDeletes++
	return s.Store.DeleteLeafEncryptionKeys(ctx, groupID)
}

// TestRemovedMemberCannotOperateWhenStateDeletionFails checks that a removed member still gets
// ErrRemovedFromGroup when its group state cannot be deleted, and that it can no longer send or read through
// the group.
func TestRemovedMemberCannotOperateWhenStateDeletionFails(t *testing.T) {
	ctx := context.Background()
	store := &failingGroupStateDeleteStore{Store: memorystore.NewStore()}
	alice, bob, gid := newTwoMemberClientGroup(t, store, CacheNone)
	commit, err := alice.RemoveMember(ctx, gid, []byte("bob"))
	if err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if err := bob.ProcessCommit(ctx, gid, commit); !errors.Is(err, ErrRemovedFromGroup) {
		t.Fatalf("ProcessCommit(remove bob) = %v, want ErrRemovedFromGroup", err)
	}
	if _, err := bob.SendMessage(ctx, gid, []byte("after removal")); !errors.Is(err, ErrGroupNotFound) {
		t.Errorf("SendMessage after removal = %v, want ErrGroupNotFound", err)
	}
	if _, err := bob.Epoch(ctx, gid); !errors.Is(err, ErrGroupNotFound) {
		t.Errorf("Epoch after removal = %v, want ErrGroupNotFound", err)
	}
}

// TestLeaveGroupReturnsCommitWhenStateDeletionFails checks that the leave commit is returned together with the
// deletion error, so the remaining members can still receive it, and that the Client forgets the group.
func TestLeaveGroupReturnsCommitWhenStateDeletionFails(t *testing.T) {
	ctx := context.Background()
	store := &failingGroupStateDeleteStore{Store: memorystore.NewStore()}
	_, bob, gid := newTwoMemberClientGroup(t, store, CacheNone)
	commit, err := bob.LeaveGroup(ctx, gid)
	if !errors.Is(err, errGroupStateDelete) {
		t.Fatalf("LeaveGroup error = %v, want the group state deletion error", err)
	}
	if len(commit) == 0 {
		t.Fatal("LeaveGroup returned no commit although the commit was created")
	}
	if _, err := bob.Epoch(ctx, gid); !errors.Is(err, ErrGroupNotFound) {
		t.Errorf("Epoch after LeaveGroup = %v, want ErrGroupNotFound", err)
	}
}

// TestLeaveGroupDeletesLeafKeysWhenStateDeletionFails checks that a failed group state deletion does not skip
// the deletion of the leaf keys.
func TestLeaveGroupDeletesLeafKeysWhenStateDeletionFails(t *testing.T) {
	ctx := context.Background()
	store := &failingGroupStateDeleteStore{Store: memorystore.NewStore()}
	_, bob, gid := newTwoMemberClientGroup(t, store, CacheNone)
	store.leafDeletes = 0
	if _, err := bob.LeaveGroup(ctx, gid); !errors.Is(err, errGroupStateDelete) {
		t.Fatalf("LeaveGroup error = %v, want the group state deletion error", err)
	}
	if store.leafDeletes != 1 {
		t.Errorf("DeleteLeafEncryptionKeys called %d times, want 1", store.leafDeletes)
	}
}

// TestLeaveGroupReturnsCommitWhenLeafKeyDeletionFails checks that the leave commit is still returned together
// with the error when the leaf keys cannot be deleted, and that the group state is gone.
func TestLeaveGroupReturnsCommitWhenLeafKeyDeletionFails(t *testing.T) {
	ctx := context.Background()
	errDelete := errors.New("test: leaf keys cannot be deleted")
	store := failingLeafKeyDeleteStore{Store: memorystore.NewStore(), err: errDelete}
	_, bob, gid := newTwoMemberClientGroup(t, store, CacheNone)
	commit, err := bob.LeaveGroup(ctx, gid)
	if !errors.Is(err, errDelete) {
		t.Fatalf("LeaveGroup error = %v, want the leaf key deletion error", err)
	}
	if len(commit) == 0 {
		t.Fatal("LeaveGroup returned no commit although the commit was created")
	}
	if _, err := bob.Epoch(ctx, gid); !errors.Is(err, ErrGroupNotFound) {
		t.Errorf("Epoch after LeaveGroup = %v, want ErrGroupNotFound", err)
	}
}

// TestClientRefusesStateOfAnotherGroup checks that the Client refuses the state of gid2 handed back by a store
// under the key of gid1, and that it keeps serving gid2.
func TestClientRefusesStateOfAnotherGroup(t *testing.T) {
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
	if _, err := bob.ListMembers(ctx, gid1); !errors.Is(err, errStateGroupMismatch) {
		t.Errorf("ListMembers(gid1) with the state of gid2 = %v, want errStateGroupMismatch", err)
	}
	if _, err := bob.Epoch(ctx, gid1); !errors.Is(err, errStateGroupMismatch) {
		t.Errorf("Epoch(gid1) with the state of gid2 = %v, want errStateGroupMismatch", err)
	}
	if _, err := bob.ListMembers(ctx, gid2); err != nil {
		t.Errorf("ListMembers(gid2) = %v, want nil", err)
	}
}
