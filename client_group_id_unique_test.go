package mls

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

var cacheStrategies = []struct {
	name     string
	strategy CacheStrategy
}{
	{"CacheAlways", CacheAlways},
	{"CacheNone", CacheNone},
}

func newGroupIDTestClient(t *testing.T, id string, opts ...ClientOption) *Client {
	t.Helper()
	c, err := NewClient([]byte(id), ciphersuite.MLS128DHKEMP256, opts...)
	if err != nil {
		t.Fatalf("NewClient(%s): %v", id, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func mustEpoch(t *testing.T, c *Client, groupID []byte) uint64 {
	t.Helper()
	epoch, err := c.Epoch(context.Background(), groupID)
	if err != nil {
		t.Fatalf("Epoch: %v", err)
	}
	return epoch
}

func mustEpochAuthenticator(t *testing.T, c *Client, groupID []byte) []byte {
	t.Helper()
	auth, err := c.EpochAuthenticator(context.Background(), groupID)
	if err != nil {
		t.Fatalf("EpochAuthenticator: %v", err)
	}
	return auth
}

// TestStaleWelcomeForJoinedGroupIsRefused checks that a Welcome for a group the Client already participates in
// is refused with ErrGroupExists and leaves the group where it was (RFC 9420 §12.4.3). The Welcome is an old one
// for a KeyPackage that is still pending, so it decrypts: before, it replaced the group and moved it back from
// epoch 3 to epoch 1.
func TestStaleWelcomeForJoinedGroupIsRefused(t *testing.T) {
	for _, cs := range cacheStrategies {
		t.Run(cs.name, func(t *testing.T) {
			ctx := context.Background()
			alice := newGroupIDTestClient(t, "alice")
			bob := newGroupIDTestClient(t, "bob", WithCacheStrategy(cs.strategy))

			kpOld, err := bob.FreshKeyPackageBytes(ctx)
			if err != nil {
				t.Fatalf("FreshKeyPackageBytes(old): %v", err)
			}
			kpNew, err := bob.FreshKeyPackageBytes(ctx)
			if err != nil {
				t.Fatalf("FreshKeyPackageBytes(new): %v", err)
			}
			groupID, err := alice.CreateGroup(ctx)
			if err != nil {
				t.Fatalf("CreateGroup: %v", err)
			}
			_, welcomeOld, err := alice.InviteMember(ctx, groupID, kpOld)
			if err != nil {
				t.Fatalf("InviteMember(old): %v", err)
			}
			// Remove bob before inviting him again, so the second invitation is not a duplicate member.
			if _, err := alice.RemoveMember(ctx, groupID, []byte("bob")); err != nil {
				t.Fatalf("RemoveMember: %v", err)
			}
			_, welcomeNew, err := alice.InviteMember(ctx, groupID, kpNew)
			if err != nil {
				t.Fatalf("InviteMember(new): %v", err)
			}
			if _, err := bob.JoinGroup(ctx, welcomeNew); err != nil {
				t.Fatalf("JoinGroup(new): %v", err)
			}
			if got := mustEpoch(t, bob, groupID); got != 3 {
				t.Fatalf("bob epoch before the old Welcome = %d, want 3", got)
			}
			authBefore := mustEpochAuthenticator(t, bob, groupID)

			if _, err := bob.JoinGroup(ctx, welcomeOld); !errors.Is(err, ErrGroupExists) {
				t.Fatalf("JoinGroup(old Welcome of a joined group) = %v, want ErrGroupExists", err)
			}
			if got := mustEpoch(t, bob, groupID); got != 3 {
				t.Fatalf("bob epoch after the old Welcome = %d, want 3", got)
			}
			if !bytes.Equal(mustEpochAuthenticator(t, bob, groupID), authBefore) {
				t.Fatal("bob's group state changed after the refused Welcome")
			}
		})
	}
}

// TestWelcomeForAnotherGroupKeepsExistingGroup checks the control of the uniqueness rule: a Welcome for a
// group with a different ID is accepted, and the group the Client already has keeps its epoch.
func TestWelcomeForAnotherGroupKeepsExistingGroup(t *testing.T) {
	ctx := context.Background()
	alice := newGroupIDTestClient(t, "alice")
	bob := newGroupIDTestClient(t, "bob")

	kp1, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(1): %v", err)
	}
	kp2, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(2): %v", err)
	}
	g1, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup(1): %v", err)
	}
	_, w1, err := alice.InviteMember(ctx, g1, kp1)
	if err != nil {
		t.Fatalf("InviteMember(1): %v", err)
	}
	if _, err := bob.JoinGroup(ctx, w1); err != nil {
		t.Fatalf("JoinGroup(1): %v", err)
	}
	if _, err := bob.SelfUpdate(ctx, g1); err != nil {
		t.Fatalf("SelfUpdate: %v", err)
	}

	g2, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup(2): %v", err)
	}
	_, w2, err := alice.InviteMember(ctx, g2, kp2)
	if err != nil {
		t.Fatalf("InviteMember(2): %v", err)
	}
	joined, err := bob.JoinGroup(ctx, w2)
	if err != nil {
		t.Fatalf("JoinGroup(2): %v", err)
	}
	if !bytes.Equal(joined, g2) {
		t.Fatalf("JoinGroup(2) = %x, want %x", joined, g2)
	}
	if got := mustEpoch(t, bob, g1); got != 2 {
		t.Fatalf("epoch of the first group = %d, want 2", got)
	}
}

// TestCreateGroupWithExtensionsRefusesGroupIDInUse checks that CreateGroupWithExtensions refuses an ID of a
// group the Client already has with ErrGroupExists and leaves that group intact, while a fresh ID is accepted.
func TestCreateGroupWithExtensionsRefusesGroupIDInUse(t *testing.T) {
	for _, cs := range cacheStrategies {
		t.Run(cs.name, func(t *testing.T) {
			ctx := context.Background()
			bob := newGroupIDTestClient(t, "bob", WithCacheStrategy(cs.strategy))

			groupID, err := bob.CreateGroup(ctx)
			if err != nil {
				t.Fatalf("CreateGroup: %v", err)
			}
			if _, err := bob.SelfUpdate(ctx, groupID); err != nil {
				t.Fatalf("SelfUpdate: %v", err)
			}
			kp, err := bob.FreshKeyPackageBytes(ctx)
			if err != nil {
				t.Fatalf("FreshKeyPackageBytes: %v", err)
			}
			if _, err := bob.CreateGroupWithExtensions(ctx, groupID, kp, nil); !errors.Is(err, ErrGroupExists) {
				t.Fatalf("CreateGroupWithExtensions(ID in use) = %v, want ErrGroupExists", err)
			}
			if got := mustEpoch(t, bob, groupID); got != 1 {
				t.Fatalf("epoch after the refused create = %d, want 1", got)
			}

			fresh := []byte("fresh-group-id")
			got, err := bob.CreateGroupWithExtensions(ctx, fresh, kp, nil)
			if err != nil {
				t.Fatalf("CreateGroupWithExtensions(fresh ID): %v", err)
			}
			if !bytes.Equal(got, fresh) {
				t.Fatalf("CreateGroupWithExtensions(fresh ID) = %x, want %x", got, fresh)
			}
		})
	}
}

// TestExternalJoinOfOwnGroupIsRefused checks that ExternalJoin, which is not a resync, refuses a GroupInfo of a
// group the Client already participates in (RFC 9420 §12.4.3), and that the group does not change.
func TestExternalJoinOfOwnGroupIsRefused(t *testing.T) {
	ctx := context.Background()
	alice := newGroupIDTestClient(t, "alice")
	bob := newGroupIDTestClient(t, "bob")

	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	kp, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes: %v", err)
	}
	_, welcome, err := alice.InviteMember(ctx, groupID, kp)
	if err != nil {
		t.Fatalf("InviteMember: %v", err)
	}
	if _, err := bob.JoinGroup(ctx, welcome); err != nil {
		t.Fatalf("JoinGroup: %v", err)
	}
	info, err := bob.GroupInfo(ctx, groupID)
	if err != nil {
		t.Fatalf("GroupInfo: %v", err)
	}
	before := mustEpochAuthenticator(t, alice, groupID)

	if _, _, err := alice.ExternalJoin(ctx, info); !errors.Is(err, ErrGroupExists) {
		t.Fatalf("ExternalJoin(own group) = %v, want ErrGroupExists", err)
	}
	if !bytes.Equal(mustEpochAuthenticator(t, alice, groupID), before) {
		t.Fatal("alice's group changed after the refused ExternalJoin")
	}
}

// TestExternalJoinOfCollidingGroupIDIsRefused checks that a GroupInfo of another group that reuses the ID of one
// of the Client's groups is refused with ErrGroupExists.
func TestExternalJoinOfCollidingGroupIDIsRefused(t *testing.T) {
	ctx := context.Background()
	alice := newGroupIDTestClient(t, "alice")
	mallory := newGroupIDTestClient(t, "mallory")

	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	kp, err := mallory.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes: %v", err)
	}
	if _, err := mallory.CreateGroupWithExtensions(ctx, groupID, kp, nil); err != nil {
		t.Fatalf("mallory CreateGroupWithExtensions: %v", err)
	}
	info, err := mallory.GroupInfo(ctx, groupID)
	if err != nil {
		t.Fatalf("GroupInfo: %v", err)
	}
	if _, _, err := alice.ExternalJoin(ctx, info); !errors.Is(err, ErrGroupExists) {
		t.Fatalf("ExternalJoin(colliding group ID) = %v, want ErrGroupExists", err)
	}
}

// failLeafKeyDeleteStore fails DeleteLeafEncryptionKeys while failDelete is set.
type failLeafKeyDeleteStore struct {
	*memorystore.Store
	failDelete atomic.Bool
}

func (s *failLeafKeyDeleteStore) DeleteLeafEncryptionKeys(ctx context.Context, id *group.ID) error {
	if s.failDelete.Load() {
		return errors.New("injected: leaf key delete failed")
	}
	return s.Store.DeleteLeafEncryptionKeys(ctx, id)
}

// TestForgottenGroupDoesNotBlockRejoin checks that a group the Client left, whose cleanup did not finish, does
// not count as a group the Client participates in: a later Welcome to the same group is accepted, and the
// rejoined member agrees with the group.
func TestForgottenGroupDoesNotBlockRejoin(t *testing.T) {
	ctx := context.Background()
	ms := memorystore.NewStore()
	ks := &failLeafKeyDeleteStore{Store: ms}
	alice := newGroupIDTestClient(t, "alice")
	bob := newGroupIDTestClient(t, "bob", WithStorage(ms, ks))

	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	kp, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes: %v", err)
	}
	_, welcome, err := alice.InviteMember(ctx, groupID, kp)
	if err != nil {
		t.Fatalf("InviteMember: %v", err)
	}
	if _, err := bob.JoinGroup(ctx, welcome); err != nil {
		t.Fatalf("JoinGroup: %v", err)
	}

	ks.failDelete.Store(true)
	_, leaveErr := bob.LeaveGroup(ctx, groupID)
	ks.failDelete.Store(false)
	if leaveErr == nil {
		t.Fatal("LeaveGroup succeeded although the leaf key deletion was made to fail")
	}
	if _, err := bob.Epoch(ctx, groupID); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("Epoch after leaving = %v, want ErrGroupNotFound", err)
	}

	if _, err := alice.RemoveMember(ctx, groupID, []byte("bob")); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	kp2, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(2): %v", err)
	}
	_, welcome2, err := alice.InviteMember(ctx, groupID, kp2)
	if err != nil {
		t.Fatalf("InviteMember(2): %v", err)
	}
	if _, err := bob.JoinGroup(ctx, welcome2); err != nil {
		t.Fatalf("JoinGroup after leaving: %v", err)
	}
	if !bytes.Equal(mustEpochAuthenticator(t, bob, groupID), mustEpochAuthenticator(t, alice, groupID)) {
		t.Fatal("bob's epoch authenticator after rejoining differs from alice's")
	}
}

// barrierLoadStore holds LoadGroupState for the armed group ID until two calls have arrived, so two operations
// that check the same ID both get past the store check before either registers the group.
type barrierLoadStore struct {
	*memorystore.Store
	armed   []byte
	arrived chan struct{}
	release chan struct{}
}

func (s *barrierLoadStore) LoadGroupState(ctx context.Context, groupID *group.ID) ([]byte, error) {
	if bytes.Equal(groupID.AsSlice(), s.armed) {
		s.arrived <- struct{}{}
		select {
		case <-s.release:
		case <-time.After(5 * time.Second):
		}
	}
	return s.Store.LoadGroupState(ctx, groupID)
}

// TestConcurrentCreatesOfSameGroupIDOneWins checks that when two CreateGroupWithExtensions calls for the same
// free group ID both pass the store check, exactly one of them registers the group and the other gets
// ErrGroupExists, instead of both succeeding and the second replacing the first.
func TestConcurrentCreatesOfSameGroupIDOneWins(t *testing.T) {
	for _, cs := range cacheStrategies {
		t.Run(cs.name, func(t *testing.T) {
			ctx := context.Background()
			groupID := []byte("contested-group-id")
			ms := memorystore.NewStore()
			store := &barrierLoadStore{Store: ms, armed: groupID, arrived: make(chan struct{}, 2), release: make(chan struct{})}
			bob := newGroupIDTestClient(t, "bob", WithStorage(store, ms), WithCacheStrategy(cs.strategy))
			kps := make([][]byte, 2)
			for i := range kps {
				kp, err := bob.FreshKeyPackageBytes(ctx)
				if err != nil {
					t.Fatalf("FreshKeyPackageBytes: %v", err)
				}
				kps[i] = kp
			}

			errs := make([]error, 2)
			var wg sync.WaitGroup
			for i := range kps {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					_, errs[i] = bob.CreateGroupWithExtensions(ctx, groupID, kps[i], nil)
				}(i)
			}
			for range kps {
				select {
				case <-store.arrived:
				case <-time.After(5 * time.Second):
					t.Fatal("the two creates did not both reach the store check")
				}
			}
			close(store.release)
			wg.Wait()

			if (errs[0] == nil) == (errs[1] == nil) {
				t.Fatalf("create 1 = %v, create 2 = %v, want exactly one success", errs[0], errs[1])
			}
			for _, err := range errs {
				if err != nil && !errors.Is(err, ErrGroupExists) {
					t.Fatalf("losing create returned %v, want ErrGroupExists", err)
				}
			}
		})
	}
}
