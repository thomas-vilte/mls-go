//go:build diagnostics

package mls

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

// groupDeleteHookStore runs hook once, inside DeleteGroupState and before the real delete.
type groupDeleteHookStore struct {
	*memorystore.Store
	mu       sync.Mutex
	onDelete func()
}

func (s *groupDeleteHookStore) DeleteGroupState(ctx context.Context, id *group.ID) error {
	s.mu.Lock()
	f := s.onDelete
	s.onDelete = nil
	s.mu.Unlock()
	if f != nil {
		f()
	}
	return s.Store.DeleteGroupState(ctx, id)
}

func TestClientOperationsDoNotGrowGroupEntries(t *testing.T) {
	ctx := t.Context()
	c, err := NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close(c): %v", err)
		}
	})

	ops := []struct {
		name string
		run  func(id []byte) error
	}{
		{"read/Epoch", func(id []byte) error { _, err := c.Epoch(ctx, id); return err }},
		{"read/ListMembers", func(id []byte) error { _, err := c.ListMembers(ctx, id); return err }},
		{"write/SendMessage", func(id []byte) error { _, err := c.SendMessage(ctx, id, []byte("x")); return err }},
		{"write/ReceiveMessage", func(id []byte) error { _, err := c.ReceiveMessage(ctx, id, []byte{1, 2, 3, 4}); return err }},
		{"write/ProcessCommit", func(id []byte) error { return c.ProcessCommit(ctx, id, []byte{1, 2, 3, 4}) }},
		{"write/ProcessPublicMessage", func(id []byte) error { return c.ProcessPublicMessage(ctx, id, []byte{1, 2, 3, 4}) }},
		{"write/LeaveGroup", func(id []byte) error { _, err := c.LeaveGroup(ctx, id); return err }},
		{"write/SelfUpdate", func(id []byte) error { _, err := c.SelfUpdate(ctx, id); return err }},
		{"write/RemoveMember", func(id []byte) error { _, err := c.RemoveMember(ctx, id, []byte("bob")); return err }},
		{"write/ProposeRemoveMember", func(id []byte) error { _, err := c.ProposeRemoveMember(ctx, id, []byte("bob")); return err }},
		{"write/ProposeAddMember", func(id []byte) error { _, err := c.ProposeAddMember(ctx, id, []byte{1}); return err }},
		{"write/InviteMember", func(id []byte) error { _, _, err := c.InviteMember(ctx, id, []byte{1}); return err }},
		{"write/CommitPendingProposals", func(id []byte) error { _, _, err := c.CommitPendingProposals(ctx, id); return err }},
		{"write/CommitPendingProposalsStaged", func(id []byte) error { _, err := c.CommitPendingProposalsStaged(ctx, id); return err }},
		{"write/Branch", func(id []byte) error { _, _, _, err := c.Branch(ctx, id, nil); return err }},
		{"write/RevokeProposals", func(id []byte) error { return c.RevokeProposals(ctx, id, nil) }},
		{"write/CancelPendingProposals", func(id []byte) error { return c.CancelPendingProposals(ctx, id) }},
	}
	const n = 25
	for _, op := range ops {
		before := clientGroupEntryCount(c)
		for range n {
			_ = op.run(randomClientGroupID(t))
		}
		if grown := clientGroupEntryCount(c) - before; grown != 0 {
			t.Errorf("%s: %d calls with arbitrary group IDs grew groupEntries by %d (want 0)", op.name, n, grown)
		}
	}
}

func TestClientLeaveGroupDoesNotRestoreStateDuringSend(t *testing.T) {
	ctx := t.Context()
	cs := ciphersuite.MLS128DHKEMP256

	alice, err := NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	t.Cleanup(func() {
		if err := alice.Close(); err != nil {
			t.Errorf("Close(alice): %v", err)
		}
	})

	bobStore := &groupDeleteHookStore{Store: memorystore.NewStore()}
	bob, err := NewClient([]byte("bob"), cs, WithStorage(bobStore, bobStore), WithCacheStrategy(CacheAlways))
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}
	t.Cleanup(func() {
		if err := bob.Close(); err != nil {
			t.Errorf("Close(bob): %v", err)
		}
	})

	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes: %v", err)
	}
	gid, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	_, welcome, err := alice.InviteMember(ctx, gid, bobKP)
	if err != nil {
		t.Fatalf("InviteMember: %v", err)
	}
	joinedID, err := bob.JoinGroup(ctx, welcome)
	if err != nil {
		t.Fatalf("JoinGroup: %v", err)
	}
	if !bytes.Equal(joinedID, gid) {
		t.Fatalf("joined group id mismatch")
	}

	inDelete := make(chan struct{})
	release := make(chan struct{})
	bobStore.mu.Lock()
	bobStore.onDelete = func() {
		close(inDelete)
		<-release
	}
	bobStore.mu.Unlock()

	leaveErrCh := make(chan error, 1)
	go func() {
		_, err := bob.LeaveGroup(ctx, gid)
		leaveErrCh <- err
	}()
	<-inDelete // LeaveGroup holds the entry lock and is blocked inside DeleteGroupState.

	sendErrCh := make(chan error, 1)
	go func() {
		_, err := bob.SendMessage(ctx, gid, []byte("after leave"))
		sendErrCh <- err
	}()
	// SendMessage takes the entry pointer while the entry is still registered, then
	// blocks on entry.mu. The sleep is a best-effort ordering aid for the repro.
	time.Sleep(300 * time.Millisecond)
	close(release)

	if err := <-leaveErrCh; err != nil {
		t.Fatalf("LeaveGroup: %v", err)
	}
	sendErr := <-sendErrCh

	_, loadErr := bobStore.LoadGroupState(ctx, group.NewGroupID(gid))
	_, epochErr := bob.Epoch(ctx, gid)

	t.Logf("SendMessage (in flight) err = %v; epoch err = %v; load err = %v", sendErr, epochErr, loadErr)
	if sendErr == nil {
		t.Errorf("SendMessage succeeded on a group that LeaveGroup had just deleted")
	}
	if loadErr == nil {
		t.Errorf("left group state is back in storage after the in-flight SendMessage (resurrected)")
	}
	if !errors.Is(epochErr, ErrGroupNotFound) {
		t.Errorf("Epoch after LeaveGroup = %v, want ErrGroupNotFound", epochErr)
	}
}

func TestClientLeaveGroupConcurrentCloseAndJoin(t *testing.T) {
	ctx := t.Context()
	cs := ciphersuite.MLS128DHKEMP256
	for round := range 40 {
		alice, err := NewClient([]byte(fmt.Sprintf("alice-%d", round)), cs)
		if err != nil {
			t.Fatalf("NewClient(alice): %v", err)
		}
		bob, err := NewClient([]byte(fmt.Sprintf("bob-%d", round)), cs)
		if err != nil {
			t.Fatalf("NewClient(bob): %v", err)
		}
		// gid1: bob already belongs to it and will leave it.
		kp1, err := bob.FreshKeyPackageBytes(ctx)
		if err != nil {
			t.Fatalf("FreshKeyPackageBytes(1): %v", err)
		}
		gid1, err := alice.CreateGroup(ctx)
		if err != nil {
			t.Fatalf("CreateGroup(1): %v", err)
		}
		_, welcome1, err := alice.InviteMember(ctx, gid1, kp1)
		if err != nil {
			t.Fatalf("InviteMember(1): %v", err)
		}
		if _, err := bob.JoinGroup(ctx, welcome1); err != nil {
			t.Fatalf("JoinGroup(1): %v", err)
		}
		// gid2: bob joins it concurrently with the leave.
		kp2, err := bob.FreshKeyPackageBytes(ctx)
		if err != nil {
			t.Fatalf("FreshKeyPackageBytes(2): %v", err)
		}
		gid2, err := alice.CreateGroup(ctx)
		if err != nil {
			t.Fatalf("CreateGroup(2): %v", err)
		}
		_, welcome2, err := alice.InviteMember(ctx, gid2, kp2)
		if err != nil {
			t.Fatalf("InviteMember(2): %v", err)
		}

		var wg sync.WaitGroup
		errs := make(chan error, 4)
		start := make(chan struct{})
		run := func(name string, fn func() error) {
			wg.Go(func() {
				defer func() {
					if r := recover(); r != nil {
						errs <- fmt.Errorf("%s panicked: %v", name, r)
					}
				}()
				<-start
				if err := fn(); err != nil && !errors.Is(err, ErrClientClosed) && !errors.Is(err, ErrGroupNotFound) {
					errs <- fmt.Errorf("%s: %w", name, err)
				}
			})
		}
		run("LeaveGroup", func() error { _, err := bob.LeaveGroup(ctx, gid1); return err })
		run("Close", func() error { return bob.Close() })
		run("Epoch", func() error { _, err := bob.Epoch(ctx, gid1); return err })
		run("JoinGroup", func() error { _, err := bob.JoinGroup(ctx, welcome2); return err })
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Errorf("round %d: %v", round, err)
		}
		_ = alice.Close()
	}
}

func TestClientOperationsRejectClosedClient(t *testing.T) {
	ctx := t.Context()
	c, err := NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	gid, err := c.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	kp, err := c.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	calls := []struct {
		name string
		run  func() error
	}{
		{"CreateGroup", func() error { _, err := c.CreateGroup(ctx); return err }},
		{"CreateGroupWithExtensions", func() error { _, err := c.CreateGroupWithExtensions(ctx, gid, kp, nil); return err }},
		{"FreshKeyPackageBytes", func() error { _, err := c.FreshKeyPackageBytes(ctx); return err }},
		{"Epoch", func() error { _, err := c.Epoch(ctx, gid); return err }},
		{"OwnLeafIndex", func() error { _, err := c.OwnLeafIndex(ctx, gid); return err }},
		{"ListMembers", func() error { _, err := c.ListMembers(ctx, gid); return err }},
		{"Export", func() error { _, err := c.Export(ctx, gid, "l", nil, 16); return err }},
		{"EpochAuthenticator", func() error { _, err := c.EpochAuthenticator(ctx, gid); return err }},
		{"ResumptionPSK", func() error { _, _, err := c.ResumptionPSK(ctx, gid); return err }},
		{"GroupInfo", func() error { _, err := c.GroupInfo(ctx, gid); return err }},
		{"SendMessage", func() error { _, err := c.SendMessage(ctx, gid, []byte("x")); return err }},
		{"ReceiveMessage", func() error { _, err := c.ReceiveMessage(ctx, gid, []byte{1, 2, 3, 4}); return err }},
		{"ProcessCommit", func() error { return c.ProcessCommit(ctx, gid, []byte{1, 2, 3, 4}) }},
		{"ProcessPublicMessage", func() error { return c.ProcessPublicMessage(ctx, gid, []byte{1, 2, 3, 4}) }},
		{"InviteMember", func() error { _, _, err := c.InviteMember(ctx, gid, kp); return err }},
		{"ProposeAddMember", func() error { _, err := c.ProposeAddMember(ctx, gid, kp); return err }},
		{"ProposeRemoveMember", func() error { _, err := c.ProposeRemoveMember(ctx, gid, []byte("bob")); return err }},
		{"RemoveMember", func() error { _, err := c.RemoveMember(ctx, gid, []byte("bob")); return err }},
		{"SelfUpdate", func() error { _, err := c.SelfUpdate(ctx, gid); return err }},
		{"LeaveGroup", func() error { _, err := c.LeaveGroup(ctx, gid); return err }},
		{"Branch", func() error { _, _, _, err := c.Branch(ctx, gid, nil); return err }},
		{"CommitPendingProposals", func() error { _, _, err := c.CommitPendingProposals(ctx, gid); return err }},
		{"CommitPendingProposalsStaged", func() error { _, err := c.CommitPendingProposalsStaged(ctx, gid); return err }},
		{"CancelPendingProposals", func() error { return c.CancelPendingProposals(ctx, gid) }},
		{"RevokeProposals", func() error { return c.RevokeProposals(ctx, gid, [][]byte{{1}}) }},
		{"JoinGroup", func() error { _, err := c.JoinGroup(ctx, []byte{1, 2, 3, 4}); return err }},
		{"ExternalJoin", func() error { _, _, err := c.ExternalJoin(ctx, []byte{1, 2, 3, 4}); return err }},
		{"ProposeReInit", func() error { _, err := c.ProposeReInit(ctx, gid, []byte("new")); return err }},
		{"ProposeResumptionPSK", func() error { _, err := c.ProposeResumptionPSK(ctx, gid, 0); return err }},
		{"ProposeGroupContextExtensions", func() error { _, err := c.ProposeGroupContextExtensions(ctx, gid, []byte{1}); return err }},
	}
	for _, tc := range calls {
		err := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("PANIC: %v", r)
				}
			}()
			return tc.run()
		}()
		if !errors.Is(err, ErrClientClosed) {
			t.Errorf("%s after Close: err = %v, want ErrClientClosed", tc.name, err)
		}
	}
}

func TestClientBranchConcurrentSendWithCache(t *testing.T) {
	ctx := t.Context()
	c, err := NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256, WithCacheStrategy(CacheAlways))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close(c): %v", err)
		}
	})
	gid, err := c.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	for i := range 30 {
		var wg sync.WaitGroup
		wg.Go(func() {
			if _, _, _, err := c.Branch(ctx, gid, nil); err != nil {
				t.Errorf("Branch round %d: %v", i, err)
			}
		})
		wg.Go(func() {
			if _, err := c.SendMessage(ctx, gid, []byte("m")); err != nil {
				t.Errorf("SendMessage round %d: %v", i, err)
			}
		})
		wg.Wait()
	}
}

func TestClientConcurrentGroupReadsAndWrites(t *testing.T) {
	ctx := t.Context()
	for _, strategy := range []CacheStrategy{CacheNone, CacheAlways} {
		c, err := NewClient([]byte(fmt.Sprintf("alice-%d", strategy)), ciphersuite.MLS128DHKEMP256, WithCacheStrategy(strategy))
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		gid, err := c.CreateGroup(ctx)
		if err != nil {
			t.Fatalf("CreateGroup: %v", err)
		}
		var wg sync.WaitGroup
		errs := make(chan error, 64)
		for range 4 {
			wg.Go(func() {
				for range 20 {
					if _, err := c.Epoch(ctx, gid); err != nil {
						errs <- fmt.Errorf("Epoch: %w", err)
						return
					}
					if _, err := c.ListMembers(ctx, gid); err != nil {
						errs <- fmt.Errorf("ListMembers: %w", err)
						return
					}
				}
			})
			wg.Go(func() {
				for range 20 {
					if _, err := c.SendMessage(ctx, gid, []byte("m")); err != nil {
						errs <- fmt.Errorf("SendMessage: %w", err)
						return
					}
				}
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Errorf("strategy %d: %v", strategy, err)
		}
		_ = c.Close()
	}
}

// TestClientRejectsUnsupportedKeyPackage checks that client operations reject
// KeyPackages with unsupported cipher suites without panicking.
func TestClientRejectsUnsupportedKeyPackage(t *testing.T) {
	ctx := t.Context()
	c, err := NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	groupID, err := c.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	// The KeyPackage must come from another client: its signature key is not yet in the tree.
	other, err := NewClient([]byte("bob"), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("NewClient(other): %v", err)
	}
	t.Cleanup(func() { _ = other.Close() })
	valid, err := other.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes: %v", err)
	}
	bad := bytes.Clone(valid)
	bad[2], bad[3] = 0x00, 0x80 // protocol_version(2) || cipher_suite(2)

	cases := []struct {
		name string
		run  func() error
	}{
		{"InviteMember", func() error { _, _, err := c.InviteMember(ctx, groupID, bad); return err }},
		{"ProposeAddMember", func() error { _, err := c.ProposeAddMember(ctx, groupID, bad); return err }},
		{"Branch", func() error { _, _, _, err := c.Branch(ctx, groupID, [][]byte{bad}); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s panicked: %v", tc.name, r)
				}
			}()
			if err := tc.run(); err == nil {
				t.Errorf("%s accepted a KeyPackage with unsupported cipher suite 0x0080", tc.name)
			}
		})
	}

	// Control: the valid KeyPackage must still be accepted by InviteMember.
	if _, _, err := c.InviteMember(ctx, groupID, valid); err != nil {
		t.Errorf("control InviteMember(valid KP): %v", err)
	}
}

func TestClientCloseConcurrentIdentityRead(t *testing.T) {
	ctx := t.Context()
	for range 20 {
		c, err := NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256)
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		gid, err := c.CreateGroup(ctx)
		if err != nil {
			t.Fatalf("CreateGroup: %v", err)
		}
		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Go(func() {
			<-start
			_, _ = c.SelfUpdate(ctx, gid)
		})
		wg.Go(func() {
			<-start
			_ = c.Close()
		})
		close(start)
		wg.Wait()
	}
}
