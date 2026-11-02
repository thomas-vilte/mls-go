package mls

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
	filestore "github.com/thomas-vilte/mls-go/storage/file"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

// clientTestStore is the backend a client uses for both group state and key material.
type clientTestStore interface {
	group.GroupStorage
	group.KeyStore
}

// failingLeafKeyDeleteStore is an in-memory store whose leaf key deletion always fails.
type failingLeafKeyDeleteStore struct {
	*memorystore.Store
	err error
}

// DeleteLeafEncryptionKeys fails with the injected error and deletes nothing.
func (s failingLeafKeyDeleteStore) DeleteLeafEncryptionKeys(context.Context, *group.ID) error {
	return s.err
}

// clientStoreBackend returns a fresh store for bob and the directory where it keeps its files
// ("" when the store is in memory).
type clientStoreBackend func(t *testing.T) (clientTestStore, string)

// fileStoreBackend returns a file store in a temporary directory and that directory.
func fileStoreBackend(t *testing.T) (store clientTestStore, dir string) {
	t.Helper()
	dir = t.TempDir()
	fs, err := filestore.NewStore(dir)
	if err != nil {
		t.Fatalf("file.NewStore: %v", err)
	}
	return fs, dir
}

// memoryStoreBackend returns an in-memory store and an empty directory.
func memoryStoreBackend(t *testing.T) (store clientTestStore, dir string) {
	t.Helper()
	return memorystore.NewStore(), ""
}

// newTwoMemberClientGroup creates a two-member group. Alice creates it and bob, who is leaf 1, joins it with
// bobStore, strategy and extra options. Both clients are closed when the test ends.
func newTwoMemberClientGroup(t *testing.T, bobStore clientTestStore, strategy CacheStrategy, extra ...ClientOption) (alice, bob *Client, groupID []byte) {
	t.Helper()
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMX25519
	var err error
	alice, err = NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	opts := append([]ClientOption{WithStorage(bobStore, bobStore), WithCacheStrategy(strategy)}, extra...)
	bob, err = NewClient([]byte("bob"), cs, opts...)
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

// remainingGroupMaterial lists what store and dir still hold for groupID: the group state, the signature
// key, the leaf key of leaf 1, and every file in dir that stores group state or a leaf key.
// An empty result means no state or key material of the group remains.
func remainingGroupMaterial(t *testing.T, store clientTestStore, dir string, groupID []byte) []string {
	t.Helper()
	ctx := context.Background()
	gid := group.NewGroupID(groupID)
	var present []string
	if _, err := store.LoadGroupState(ctx, gid); err == nil {
		present = append(present, "group state")
	}
	if _, err := store.LoadSignatureKey(ctx, gid); err == nil {
		present = append(present, "signature key")
	}
	if _, err := store.LoadLeafEncryptionKey(ctx, gid, 1); err == nil {
		present = append(present, "leaf key 1")
	}
	if dir != "" {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("ReadDir: %v", err)
		}
		for _, e := range entries {
			if name := e.Name(); strings.Contains(name, ".bin") || strings.Contains(name, ".leaf.") {
				present = append(present, "file "+name)
			}
		}
	}
	return present
}

// TestClientDeletesGroupMaterialOnLeaveAndRemoval checks that a member that leaves a group or is removed from
// it deletes the group state and its leaf HPKE keys (RFC 9420 §9.2). The controls check that an active group
// keeps both, and that a commit that fails for another reason does not remove the member.
func TestClientDeletesGroupMaterialOnLeaveAndRemoval(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name     string
		backend  clientStoreBackend
		strategy CacheStrategy
	}{
		{"file/CacheNone", fileStoreBackend, CacheNone},
		{"file/CacheAlways", fileStoreBackend, CacheAlways},
		{"memory/CacheNone", memoryStoreBackend, CacheNone},
		{"memory/CacheAlways", memoryStoreBackend, CacheAlways},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("control/active", func(t *testing.T) {
				store, dir := tc.backend(t)
				alice, bob, gid := newTwoMemberClientGroup(t, store, tc.strategy)
				commit, err := alice.SelfUpdate(ctx, gid)
				if err != nil {
					t.Fatalf("SelfUpdate: %v", err)
				}
				if err := bob.ProcessCommit(ctx, gid, commit); err != nil {
					t.Fatalf("ProcessCommit(self update): %v", err)
				}
				present := remainingGroupMaterial(t, store, dir, gid)
				for _, want := range []string{"group state", "signature key", "leaf key 1"} {
					if !slices.Contains(present, want) {
						t.Errorf("active group no longer holds %q; present = %v", want, present)
					}
				}
				if dir != "" {
					for _, name := range []string{hex.EncodeToString(gid) + ".bin", hex.EncodeToString(gid) + ".leaf.1.bin"} {
						if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
							t.Errorf("active group file %s: %v", name, err)
						}
					}
				}
			})

			t.Run("control/failed_commit", func(t *testing.T) {
				store, dir := tc.backend(t)
				alice, bob, gid := newTwoMemberClientGroup(t, store, tc.strategy)
				commit, err := alice.SelfUpdate(ctx, gid)
				if err != nil {
					t.Fatalf("SelfUpdate: %v", err)
				}
				tampered := slices.Clone(commit)
				tampered[len(tampered)-1] ^= 0x01
				if err := bob.ProcessCommit(ctx, gid, tampered); err == nil || errors.Is(err, ErrRemovedFromGroup) {
					t.Fatalf("ProcessCommit(tampered commit) = %v, want a failure other than ErrRemovedFromGroup", err)
				}
				present := remainingGroupMaterial(t, store, dir, gid)
				for _, want := range []string{"group state", "signature key", "leaf key 1"} {
					if !slices.Contains(present, want) {
						t.Errorf("rejected commit removed %q; present = %v", want, present)
					}
				}
				if err := bob.ProcessCommit(ctx, gid, commit); err != nil {
					t.Fatalf("ProcessCommit(valid commit) after a rejected one: %v", err)
				}
			})

			t.Run("leave", func(t *testing.T) {
				store, dir := tc.backend(t)
				_, bob, gid := newTwoMemberClientGroup(t, store, tc.strategy)
				if _, err := bob.LeaveGroup(ctx, gid); err != nil {
					t.Fatalf("LeaveGroup: %v", err)
				}
				if left := remainingGroupMaterial(t, store, dir, gid); len(left) != 0 {
					t.Errorf("LeaveGroup left state or key material behind: %v", left)
				}
			})

			t.Run("removed", func(t *testing.T) {
				store, dir := tc.backend(t)
				events := make(chan GroupEvent, 64)
				alice, bob, gid := newTwoMemberClientGroup(t, store, tc.strategy, WithEventHandler(func(e GroupEvent) {
					select {
					case events <- e:
					default:
					}
				}))
				removeCommit, err := alice.RemoveMember(ctx, gid, []byte("bob"))
				if err != nil {
					t.Fatalf("RemoveMember: %v", err)
				}
				if err := bob.ProcessCommit(ctx, gid, removeCommit); !errors.Is(err, ErrRemovedFromGroup) {
					t.Fatalf("ProcessCommit(removal of bob) = %v, want ErrRemovedFromGroup", err)
				}
				if left := remainingGroupMaterial(t, store, dir, gid); len(left) != 0 {
					t.Errorf("removal left state or key material behind: %v", left)
				}
				if _, err := bob.SendMessage(ctx, gid, []byte("after removal")); !errors.Is(err, ErrGroupNotFound) {
					t.Errorf("SendMessage after removal = %v, want ErrGroupNotFound", err)
				}
				seen := awaitEventTypes(t, events, EventMemberRemoved)
				if got := string(seen[EventMemberRemoved].MemberIdentity); got != "bob" {
					t.Errorf("EventMemberRemoved identity = %q, want bob", got)
				}
			})

			t.Run("removed_public", func(t *testing.T) {
				store, dir := tc.backend(t)
				alice, bob, gid := newTwoMemberClientGroup(t, store, tc.strategy)
				removeCommit, err := alice.RemoveMember(ctx, gid, []byte("bob"))
				if err != nil {
					t.Fatalf("RemoveMember: %v", err)
				}
				if err := bob.ProcessPublicMessage(ctx, gid, removeCommit); !errors.Is(err, ErrRemovedFromGroup) {
					t.Fatalf("ProcessPublicMessage(removal of bob) = %v, want ErrRemovedFromGroup", err)
				}
				if left := remainingGroupMaterial(t, store, dir, gid); len(left) != 0 {
					t.Errorf("public removal left state or key material behind: %v", left)
				}
			})
		})
	}
}

// TestLeaveGroupReportsLeafKeyDeletionFailure checks that LeaveGroup still forgets the group state and returns
// the store error when the leaf keys cannot be deleted.
func TestLeaveGroupReportsLeafKeyDeletionFailure(t *testing.T) {
	ctx := context.Background()
	errDelete := errors.New("test: leaf keys cannot be deleted")
	store := failingLeafKeyDeleteStore{Store: memorystore.NewStore(), err: errDelete}
	_, bob, gid := newTwoMemberClientGroup(t, store, CacheAlways)
	if _, err := bob.LeaveGroup(ctx, gid); !errors.Is(err, errDelete) {
		t.Fatalf("LeaveGroup = %v, want the leaf key deletion error", err)
	}
	if _, err := bob.Epoch(ctx, gid); !errors.Is(err, ErrGroupNotFound) {
		t.Errorf("Epoch after LeaveGroup = %v, want ErrGroupNotFound", err)
	}
}

// TestConfirmPendingCommitAfterRemovalDoesNotRestoreState checks that a staged commit confirmed after the local
// member was removed fails and does not write the group state back.
func TestConfirmPendingCommitAfterRemovalDoesNotRestoreState(t *testing.T) {
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMX25519
	for _, tc := range []struct {
		name     string
		backend  clientStoreBackend
		strategy CacheStrategy
	}{
		{"file/CacheNone", fileStoreBackend, CacheNone},
		{"memory/CacheAlways", memoryStoreBackend, CacheAlways},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, dir := tc.backend(t)
			alice, bob, gid := newTwoMemberClientGroup(t, store, tc.strategy)
			carol, err := NewClient([]byte("carol"), cs)
			if err != nil {
				t.Fatalf("NewClient(carol): %v", err)
			}
			t.Cleanup(func() { _ = carol.Close() })
			carolKP, err := carol.FreshKeyPackageBytes(ctx)
			if err != nil {
				t.Fatalf("FreshKeyPackageBytes(carol): %v", err)
			}
			// Bob stages a commit that adds carol and does not confirm it yet.
			if _, err := bob.ProposeAddMember(ctx, gid, carolKP); err != nil {
				t.Fatalf("ProposeAddMember: %v", err)
			}
			handle, err := bob.CommitPendingProposalsStaged(ctx, gid)
			if err != nil {
				t.Fatalf("CommitPendingProposalsStaged: %v", err)
			}
			// Alice removes bob while bob's commit is still pending.
			removeCommit, err := alice.RemoveMember(ctx, gid, []byte("bob"))
			if err != nil {
				t.Fatalf("RemoveMember: %v", err)
			}
			if err := bob.ProcessCommit(ctx, gid, removeCommit); !errors.Is(err, ErrRemovedFromGroup) {
				t.Fatalf("ProcessCommit(removal of bob) = %v, want ErrRemovedFromGroup", err)
			}
			if _, err := bob.ConfirmPendingCommit(ctx, handle); !errors.Is(err, ErrGroupNotFound) {
				t.Errorf("ConfirmPendingCommit after removal = %v, want ErrGroupNotFound", err)
			}
			if left := remainingGroupMaterial(t, store, dir, gid); len(left) != 0 {
				t.Errorf("confirming a pending commit after removal restored state or keys: %v", left)
			}
			// Discard is the other way to resolve the handle. It must refuse as well, and must not
			// count the handle out a second time.
			if err := bob.DiscardPendingCommit(ctx, handle); !errors.Is(err, ErrGroupNotFound) {
				t.Errorf("DiscardPendingCommit after removal = %v, want ErrGroupNotFound", err)
			}
			if left := remainingGroupMaterial(t, store, dir, gid); len(left) != 0 {
				t.Errorf("discarding a pending commit after removal restored state or keys: %v", left)
			}
			// The handle was released, so Close does not wait for it.
			closed := make(chan error, 1)
			go func() { closed <- bob.Close() }()
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("Close blocked on a pending commit handle that was released after removal")
			}
		})
	}
}
