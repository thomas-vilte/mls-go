//go:build diagnostics

package mls

import (
	"context"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

// Additional diagnostics for the local group state of the Client.

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
