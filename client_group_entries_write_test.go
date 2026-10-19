package mls

import (
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

func TestClientWriteOperationsDoNotRegisterUnknownGroups(t *testing.T) {
	t.Parallel()

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

	ops := map[string]func(id []byte) error{
		"SendMessage": func(id []byte) error {
			_, err := c.SendMessage(ctx, id, []byte("x"))
			return err
		},
		"ReceiveMessage": func(id []byte) error {
			_, err := c.ReceiveMessage(ctx, id, []byte{1, 2, 3, 4})
			return err
		},
		"ProcessCommit": func(id []byte) error {
			return c.ProcessCommit(ctx, id, []byte{1, 2, 3, 4})
		},
		"ProcessPublicMessage": func(id []byte) error {
			return c.ProcessPublicMessage(ctx, id, []byte{1, 2, 3, 4})
		},
		"LeaveGroup": func(id []byte) error {
			_, err := c.LeaveGroup(ctx, id)
			return err
		},
		"SelfUpdate": func(id []byte) error {
			_, err := c.SelfUpdate(ctx, id)
			return err
		},
		"RemoveMember": func(id []byte) error {
			_, err := c.RemoveMember(ctx, id, []byte("bob"))
			return err
		},
		"ProposeRemoveMember": func(id []byte) error {
			_, err := c.ProposeRemoveMember(ctx, id, []byte("bob"))
			return err
		},
		"ProposeAddMember": func(id []byte) error {
			_, err := c.ProposeAddMember(ctx, id, []byte{1})
			return err
		},
		"InviteMember": func(id []byte) error {
			_, _, err := c.InviteMember(ctx, id, []byte{1})
			return err
		},
		"CommitPendingProposals": func(id []byte) error {
			_, _, err := c.CommitPendingProposals(ctx, id)
			return err
		},
		"CommitPendingProposalsStaged": func(id []byte) error {
			_, err := c.CommitPendingProposalsStaged(ctx, id)
			return err
		},
		"CommitPendingProposalsWithOptions": func(id []byte) error {
			_, _, err := c.CommitPendingProposalsWithOptions(ctx, id, CommitPendingProposalsOptions{})
			return err
		},
		"Branch": func(id []byte) error {
			_, _, _, err := c.Branch(ctx, id, nil)
			return err
		},
		"RevokeProposals": func(id []byte) error {
			return c.RevokeProposals(ctx, id, nil)
		},
		"CancelPendingProposals": func(id []byte) error {
			return c.CancelPendingProposals(ctx, id)
		},
		"ProposeGroupContextExtensions": func(id []byte) error {
			_, err := c.ProposeGroupContextExtensions(ctx, id, []byte{0})
			return err
		},
		"ProposeResumptionPSK": func(id []byte) error {
			_, err := c.ProposeResumptionPSK(ctx, id, 0)
			return err
		},
		"ProposeReInit": func(id []byte) error {
			_, err := c.ProposeReInit(ctx, id, []byte("new-group"))
			return err
		},
	}

	for name, op := range ops {
		for i := 0; i < 25; i++ {
			if err := op(randomClientGroupID(t)); !errors.Is(err, ErrGroupNotFound) {
				t.Fatalf("%s with unknown ID (call %d): err = %v, want ErrGroupNotFound", name, i, err)
			}
		}
		if err := op(nil); !errors.Is(err, ErrEmptyGroupID) {
			t.Fatalf("%s with empty ID: err = %v, want ErrEmptyGroupID", name, err)
		}
	}
	if n := clientGroupEntryCount(c); n != 0 {
		t.Fatalf("len(groupEntries) = %d after write calls on unknown groups, want 0", n)
	}
}

func TestClientWriteStoredGroupRegistersEntry(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	cs := ciphersuite.MLS128DHKEMP256
	store := memorystore.NewStore()

	first, err := NewClient([]byte("alice"), cs, WithStorage(store, store))
	if err != nil {
		t.Fatalf("NewClient(first): %v", err)
	}
	t.Cleanup(func() {
		if err := first.Close(); err != nil {
			t.Errorf("Close(first): %v", err)
		}
	})
	groupID, err := first.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	second, err := NewClient([]byte("alice"), cs, WithStorage(store, store), WithCacheStrategy(CacheAlways))
	if err != nil {
		t.Fatalf("NewClient(second): %v", err)
	}
	t.Cleanup(func() {
		if err := second.Close(); err != nil {
			t.Errorf("Close(second): %v", err)
		}
	})
	if n := clientGroupEntryCount(second); n != 0 {
		t.Fatalf("len(groupEntries) = %d before any call, want 0", n)
	}
	// CancelPendingProposals is a write that loads and saves the group without signing
	// anything. A signing write would fail here: the restarted Client has a new signature
	// key, which does not match the stored leaf.
	if err := second.CancelPendingProposals(ctx, groupID); err != nil {
		t.Fatalf("CancelPendingProposals on a stored group after restart: %v", err)
	}
	if n := clientGroupEntryCount(second); n != 1 {
		t.Fatalf("len(groupEntries) = %d after a write to a stored group, want 1", n)
	}
	members, err := second.ListMembers(ctx, groupID)
	if err != nil {
		t.Fatalf("ListMembers after CancelPendingProposals: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("ListMembers = %d members, want 1", len(members))
	}
	if n := clientGroupEntryCount(second); n != 1 {
		t.Fatalf("len(groupEntries) = %d after ListMembers, want 1", n)
	}
}

func TestClientWriteFailsWhenClosedDuringLoad(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	cs := ciphersuite.MLS128DHKEMP256
	store := &groupLoadHookStore{Store: memorystore.NewStore()}

	first, err := NewClient([]byte("alice"), cs, WithStorage(store, store))
	if err != nil {
		t.Fatalf("NewClient(first): %v", err)
	}
	t.Cleanup(func() {
		if err := first.Close(); err != nil {
			t.Errorf("Close(first): %v", err)
		}
	})
	groupID, err := first.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	second, err := NewClient([]byte("alice"), cs, WithStorage(store, store))
	if err != nil {
		t.Fatalf("NewClient(second): %v", err)
	}
	t.Cleanup(func() {
		if err := second.Close(); err != nil {
			t.Errorf("Close(second): %v", err)
		}
	})

	var closeErr error
	store.onLoad = func() { closeErr = second.Close() }
	_, err = second.SelfUpdate(ctx, groupID)
	if closeErr != nil {
		t.Fatalf("Close: %v", closeErr)
	}
	if !errors.Is(err, ErrClientClosed) {
		t.Fatalf("SelfUpdate while Close runs: err = %v, want ErrClientClosed", err)
	}
	if n := clientGroupEntryCount(second); n != 0 {
		t.Fatalf("len(groupEntries) = %d after Close, want 0", n)
	}
	// The group must still be at epoch 0 for the other Client: nothing was persisted.
	epoch, err := first.Epoch(ctx, groupID)
	if err != nil {
		t.Fatalf("Epoch on the other Client: %v", err)
	}
	if epoch != 0 {
		t.Fatalf("Epoch on the other Client = %d, want 0 (the aborted write must not persist)", epoch)
	}
}

func TestClientReadRegisteredGroupFailsWhenClosedDuringLoad(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := &groupLoadHookStore{Store: memorystore.NewStore()}

	// The default cache strategy (CacheNone) reloads the group from storage on each call,
	// so the store hook runs on every read.
	c, err := NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256, WithStorage(store, store))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close(c): %v", err)
		}
	})
	groupID, err := c.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if n := clientGroupEntryCount(c); n != 1 {
		t.Fatalf("len(groupEntries) = %d after CreateGroup, want 1 (the entry must be registered)", n)
	}

	var closeErr error
	store.onLoad = func() { closeErr = c.Close() }
	epoch, err := c.Epoch(ctx, groupID)
	if closeErr != nil {
		t.Fatalf("Close: %v", closeErr)
	}
	if !errors.Is(err, ErrClientClosed) {
		t.Fatalf("Epoch while Close runs on a registered entry: err = %v, want ErrClientClosed", err)
	}
	if epoch != 0 {
		t.Fatalf("Epoch while Close runs = %d, want 0", epoch)
	}
}
