package mls

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/keypackages"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

// errInjectedSave is the storage failure that the tests below inject.
var errInjectedSave = errors.New("injected SaveGroupState failure")

// failingGroupStorage wraps a real GroupStorage and fails SaveGroupState while fail is set. SaveGroupState is
// the only write of persistGroup, which ConfirmPendingCommit, DiscardPendingCommit and ProcessCommit use.
type failingGroupStorage struct {
	group.GroupStorage
	fail atomic.Bool
}

func (s *failingGroupStorage) SaveGroupState(ctx context.Context, groupID *group.ID, state []byte) error {
	if s.fail.Load() {
		return errInjectedSave
	}
	return s.GroupStorage.SaveGroupState(ctx, groupID, state)
}

// newClientWithStagedAdd creates alice with a storage that can fail and a group with a pending Add for bob, and
// returns the handle of CommitPendingProposalsStaged, which is already counted in the pending handles that
// Close waits for. alice uses the given cache strategy.
func newClientWithStagedAdd(t *testing.T, strategy CacheStrategy) (*Client, *failingGroupStorage, *PendingCommitHandle) {
	t.Helper()
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256

	mem := memorystore.NewStore()
	fgs := &failingGroupStorage{GroupStorage: mem}
	alice, err := NewClient([]byte("alice"), cs, WithStorage(fgs, mem), WithCacheStrategy(strategy))
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	bob, err := NewClient([]byte("bob"), cs)
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}
	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes: %v", err)
	}
	if _, err := alice.ProposeAddMember(ctx, groupID, bobKP); err != nil {
		t.Fatalf("ProposeAddMember: %v", err)
	}
	handle, err := alice.CommitPendingProposalsStaged(ctx, groupID)
	if err != nil {
		t.Fatalf("CommitPendingProposalsStaged: %v", err)
	}
	return alice, fgs, handle
}

// closeReturns calls Close in a goroutine and reports whether it returns within d.
func closeReturns(c *Client, d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		_ = c.Close()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// storedGroup loads the group from the store, without the cache of the client.
func storedGroup(t *testing.T, store group.GroupStorage, groupID []byte) *group.Group {
	t.Helper()
	raw, err := store.LoadGroupState(context.Background(), group.NewGroupID(groupID))
	if err != nil {
		t.Fatalf("LoadGroupState: %v", err)
	}
	g, err := group.UnmarshalGroupState(raw)
	if err != nil {
		t.Fatalf("UnmarshalGroupState: %v", err)
	}
	return g
}

// TestPendingCommitResolutionReleasesHandle checks that ConfirmPendingCommit and DiscardPendingCommit resolve
// the handle on every path. A failure used to return before the handle was released, so Close waited for it
// forever.
func TestPendingCommitResolutionReleasesHandle(t *testing.T) {
	ctx := context.Background()

	t.Run("confirm that saves", func(t *testing.T) {
		alice, _, handle := newClientWithStagedAdd(t, CacheNone)
		if _, err := alice.ConfirmPendingCommit(ctx, handle); err != nil {
			t.Fatalf("ConfirmPendingCommit: %v", err)
		}
		if !closeReturns(alice, 2*time.Second) {
			t.Fatal("Close did not return after ConfirmPendingCommit succeeded")
		}
	})

	t.Run("confirm whose save fails", func(t *testing.T) {
		alice, fgs, handle := newClientWithStagedAdd(t, CacheNone)
		fgs.fail.Store(true)
		if _, err := alice.ConfirmPendingCommit(ctx, handle); !errors.Is(err, errInjectedSave) {
			t.Fatalf("ConfirmPendingCommit = %v, want the injected storage failure", err)
		}
		fgs.fail.Store(false)
		if !closeReturns(alice, 2*time.Second) {
			t.Fatal("Close did not return after ConfirmPendingCommit failed to save")
		}
	})

	t.Run("confirm whose welcome fails", func(t *testing.T) {
		alice, _, handle := newClientWithStagedAdd(t, CacheNone)
		if len(handle.newMemberKPs) == 0 {
			t.Fatal("the handle has no new KeyPackages, so there is no Welcome to create")
		}
		// A KeyPackage with an invalid HPKE init key: CreateWelcome encrypts to it. Applications validate the
		// KeyPackage when they propose the Add, so this only happens by changing the handle.
		kp := *handle.newMemberKPs[0]
		kp.InitKey = []byte{0x01}
		handle.newMemberKPs = []*keypackages.KeyPackage{&kp}

		if _, err := alice.ConfirmPendingCommit(ctx, handle); err == nil || !strings.Contains(err.Error(), "creating welcome") {
			t.Fatalf("ConfirmPendingCommit = %v, want a \"creating welcome\" error", err)
		}
		if !closeReturns(alice, 2*time.Second) {
			t.Fatal("Close did not return after CreateWelcome failed in ConfirmPendingCommit")
		}
	})

	t.Run("discard that saves", func(t *testing.T) {
		alice, _, handle := newClientWithStagedAdd(t, CacheNone)
		if err := alice.DiscardPendingCommit(ctx, handle); err != nil {
			t.Fatalf("DiscardPendingCommit: %v", err)
		}
		if !closeReturns(alice, 2*time.Second) {
			t.Fatal("Close did not return after DiscardPendingCommit succeeded")
		}
	})

	// Under CacheAlways, DiscardPendingCommit saves the group back in StateOperational. Under CacheNone it
	// writes nothing, so only CacheAlways can fail to save here.
	t.Run("discard whose save fails", func(t *testing.T) {
		alice, fgs, handle := newClientWithStagedAdd(t, CacheAlways)
		fgs.fail.Store(true)
		if err := alice.DiscardPendingCommit(ctx, handle); !errors.Is(err, errInjectedSave) {
			t.Fatalf("DiscardPendingCommit = %v, want the injected storage failure", err)
		}
		fgs.fail.Store(false)
		if !closeReturns(alice, 2*time.Second) {
			t.Fatal("Close did not return after DiscardPendingCommit failed to save")
		}
	})
}

// TestFailedConfirmUnderCacheAlwaysNeverWritesMergedState checks that when ConfirmPendingCommit fails to save under
// CacheAlways, the handle is already merged in memory, and neither retrying Confirm nor calling Discard writes that
// state to the store. The cache is reloaded from the store.
func TestFailedConfirmUnderCacheAlwaysNeverWritesMergedState(t *testing.T) {
	ctx := context.Background()
	alice, fgs, handle := newClientWithStagedAdd(t, CacheAlways)
	groupID := handle.g.ID().AsSlice()

	fgs.fail.Store(true)
	if _, err := alice.ConfirmPendingCommit(ctx, handle); !errors.Is(err, errInjectedSave) {
		t.Fatalf("ConfirmPendingCommit = %v, want the injected storage failure", err)
	}
	fgs.fail.Store(false)

	if _, err := alice.ConfirmPendingCommit(ctx, handle); err == nil {
		t.Fatal("retrying ConfirmPendingCommit on the merged handle succeeded, want an error")
	}
	if err := alice.DiscardPendingCommit(ctx, handle); err == nil {
		t.Fatal("DiscardPendingCommit on the merged handle succeeded, want an error")
	}
	// The group starts in epoch 0 and the staged commit was never applied to the store, so the stored epoch is
	// the one before the commit. If the merged state (epoch 1) reached the store, this check sees it.
	const epochBeforeCommit = 0
	if got := storedGroup(t, fgs, groupID).Epoch().AsUint64(); got != epochBeforeCommit {
		t.Fatalf("stored epoch = %d, want %d: the merged state was written after the failure", got, epochBeforeCommit)
	}
	cacheEpoch, err := alice.Epoch(ctx, groupID)
	if err != nil {
		t.Fatalf("Epoch: %v", err)
	}
	if cacheEpoch != epochBeforeCommit {
		t.Fatalf("cached epoch = %d, want %d: the cache must be reloaded from the store", cacheEpoch, epochBeforeCommit)
	}
	if !closeReturns(alice, 2*time.Second) {
		t.Fatal("Close did not return after the failed ConfirmPendingCommit")
	}
}

// TestFailedSaveKeepsGroupOfPendingHandleCached checks that under CacheAlways with a staged commit, a failed save of
// another operation does not separate the group from its handle: the group stays in StatePendingCommit, refuses new
// proposals, and Discard neither loses nor rolls back the stored state.
func TestFailedSaveKeepsGroupOfPendingHandleCached(t *testing.T) {
	ctx := context.Background()
	alice, fgs, handle := newClientWithStagedAdd(t, CacheAlways)
	groupID := handle.g.ID().AsSlice()
	before := len(storedGroup(t, fgs, groupID).StoredProposals())

	fgs.fail.Store(true)
	_ = alice.RevokeProposals(ctx, groupID, nil)
	fgs.fail.Store(false)

	carol, err := NewClient([]byte("carol"), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("NewClient(carol): %v", err)
	}
	carolKP, err := carol.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(carol): %v", err)
	}
	if _, err := alice.ProposeAddMember(ctx, groupID, carolKP); err == nil {
		t.Fatal("ProposeAddMember with a staged commit succeeded: the group was separated from its handle")
	}

	if err := alice.DiscardPendingCommit(ctx, handle); err != nil {
		t.Fatalf("DiscardPendingCommit: %v", err)
	}
	if got := len(storedGroup(t, fgs, groupID).StoredProposals()); got != before {
		t.Fatalf("stored proposals after Discard = %d, want %d", got, before)
	}
	if !closeReturns(alice, 2*time.Second) {
		t.Fatal("Close did not return after DiscardPendingCommit")
	}
}

// TestFailedWelcomeUnderCacheAlwaysDropsMergedGroup checks that when CreateWelcome fails after the commit was
// merged, the merged group is not saved, so the cache is reloaded from the store and holds the stored epoch.
func TestFailedWelcomeUnderCacheAlwaysDropsMergedGroup(t *testing.T) {
	ctx := context.Background()
	alice, fgs, handle := newClientWithStagedAdd(t, CacheAlways)
	groupID := handle.g.ID().AsSlice()

	if len(handle.newMemberKPs) == 0 {
		t.Fatal("the handle has no new KeyPackages, so there is no Welcome to create")
	}
	// An invalid HPKE init key makes CreateWelcome fail after MergeCommit.
	kp := *handle.newMemberKPs[0]
	kp.InitKey = []byte{0x01}
	handle.newMemberKPs = []*keypackages.KeyPackage{&kp}

	if _, err := alice.ConfirmPendingCommit(ctx, handle); err == nil || !strings.Contains(err.Error(), "creating welcome") {
		t.Fatalf("ConfirmPendingCommit = %v, want a \"creating welcome\" error", err)
	}

	storedEpoch := storedGroup(t, fgs, groupID).Epoch().AsUint64()
	cacheEpoch, err := alice.Epoch(ctx, groupID)
	if err != nil {
		t.Fatalf("Epoch: %v", err)
	}
	if cacheEpoch != storedEpoch {
		t.Fatalf("cached epoch = %d, stored epoch = %d: the cache kept the merged state that was not saved", cacheEpoch, storedEpoch)
	}
	if !closeReturns(alice, 2*time.Second) {
		t.Fatal("Close did not return after CreateWelcome failed under CacheAlways")
	}
}

// newClientWithPendingCommitFromBob has alice join bob's group and returns bob's SelfUpdate commit, which alice
// has not processed yet (epoch 1 to 2). alice uses a storage that can fail and the given cache strategy.
func newClientWithPendingCommitFromBob(t *testing.T, strategy CacheStrategy) (alice *Client, fgs *failingGroupStorage, gid, bobCommit []byte) {
	t.Helper()
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256
	mem := memorystore.NewStore()
	fgs = &failingGroupStorage{GroupStorage: mem}
	alice, err := NewClient([]byte("alice"), cs, WithStorage(fgs, mem), WithCacheStrategy(strategy))
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	bob, err := NewClient([]byte("bob"), cs)
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}
	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(bob): %v", err)
	}
	gid, err = alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	_, welcome, err := alice.InviteMember(ctx, gid, bobKP)
	if err != nil {
		t.Fatalf("InviteMember(bob): %v", err)
	}
	bobGid, err := bob.JoinGroup(ctx, welcome)
	if err != nil {
		t.Fatalf("JoinGroup(bob): %v", err)
	}
	bobCommit, err = bob.SelfUpdate(ctx, bobGid)
	if err != nil {
		t.Fatalf("SelfUpdate(bob): %v", err)
	}
	return alice, fgs, gid, bobCommit
}

// TestProcessCommitWithFailedSave checks the cache after ProcessCommit fails to save. Under CacheAlways,
// ProcessCommit changes the cached group before it saves it, so the cache used to keep epoch 2 while the store
// stayed in epoch 1. The cache is now dropped, and the commit applies when it is processed again. Under
// CacheNone nothing is cached, and the same failure leaves both at epoch 1.
func TestProcessCommitWithFailedSave(t *testing.T) {
	ctx := context.Background()

	t.Run("CacheAlways drops the group that was not saved", func(t *testing.T) {
		alice, fgs, gid, commit := newClientWithPendingCommitFromBob(t, CacheAlways)
		if got := storedGroup(t, fgs, gid).Epoch().AsUint64(); got != 1 {
			t.Fatalf("stored epoch before the commit = %d, want 1", got)
		}

		fgs.fail.Store(true)
		if err := alice.ProcessCommit(ctx, gid, commit); !errors.Is(err, errInjectedSave) {
			t.Fatalf("ProcessCommit = %v, want the injected storage failure", err)
		}
		fgs.fail.Store(false)

		storedEpoch := storedGroup(t, fgs, gid).Epoch().AsUint64()
		cacheEpoch, err := alice.Epoch(ctx, gid)
		if err != nil {
			t.Fatalf("Epoch: %v", err)
		}
		if cacheEpoch != storedEpoch {
			t.Fatalf("cached epoch = %d, stored epoch = %d: the cache and the store diverge", cacheEpoch, storedEpoch)
		}
		// The commit was never saved, so with a healthy store it applies.
		if err := alice.ProcessCommit(ctx, gid, commit); err != nil {
			t.Fatalf("ProcessCommit again with a healthy store: %v", err)
		}
	})

	t.Run("CacheAlways without a failure", func(t *testing.T) {
		alice, fgs, gid, commit := newClientWithPendingCommitFromBob(t, CacheAlways)
		if err := alice.ProcessCommit(ctx, gid, commit); err != nil {
			t.Fatalf("ProcessCommit: %v", err)
		}
		cacheEpoch, err := alice.Epoch(ctx, gid)
		if err != nil {
			t.Fatalf("Epoch: %v", err)
		}
		if storedEpoch := storedGroup(t, fgs, gid).Epoch().AsUint64(); cacheEpoch != 2 || storedEpoch != 2 {
			t.Fatalf("cached epoch = %d, stored epoch = %d, want 2 for both", cacheEpoch, storedEpoch)
		}
	})

	t.Run("CacheNone keeps the stored epoch", func(t *testing.T) {
		alice, fgs, gid, commit := newClientWithPendingCommitFromBob(t, CacheNone)
		fgs.fail.Store(true)
		if err := alice.ProcessCommit(ctx, gid, commit); !errors.Is(err, errInjectedSave) {
			t.Fatalf("ProcessCommit = %v, want the injected storage failure", err)
		}
		fgs.fail.Store(false)

		cacheEpoch, err := alice.Epoch(ctx, gid)
		if err != nil {
			t.Fatalf("Epoch: %v", err)
		}
		if storedEpoch := storedGroup(t, fgs, gid).Epoch().AsUint64(); cacheEpoch != 1 || storedEpoch != 1 {
			t.Fatalf("after the failed save: cached epoch = %d, stored epoch = %d, want 1 for both", cacheEpoch, storedEpoch)
		}
		if err := alice.ProcessCommit(ctx, gid, commit); err != nil {
			t.Fatalf("ProcessCommit again with a healthy store: %v", err)
		}
		cacheEpoch, err = alice.Epoch(ctx, gid)
		if err != nil {
			t.Fatalf("Epoch after the retry: %v", err)
		}
		if storedEpoch := storedGroup(t, fgs, gid).Epoch().AsUint64(); cacheEpoch != 2 || storedEpoch != 2 {
			t.Fatalf("after the retry: cached epoch = %d, stored epoch = %d, want 2 for both", cacheEpoch, storedEpoch)
		}
	})
}
