//go:build diagnostics

package mls

import (
	"context"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

// Additional diagnostics for valid Client flows: leaving, removal, rejoining and
// message delivery.

// newValidClientPair creates a two-member group of alice and bob, with bob on an in-memory store and the given
// cache strategy.
func newValidClientPair(t *testing.T, strategy CacheStrategy) (alice, bob *Client, gid []byte) {
	t.Helper()
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMX25519
	var err error
	alice, err = NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	bobStore := memorystore.NewStore()
	bob, err = NewClient([]byte("bob"), cs, WithStorage(bobStore, bobStore), WithCacheStrategy(strategy))
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}
	t.Cleanup(func() {
		_ = alice.Close()
		_ = bob.Close()
	})
	gid, err = alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	kp, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes: %v", err)
	}
	_, w, err := alice.InviteMember(ctx, gid, kp)
	if err != nil {
		t.Fatalf("InviteMember: %v", err)
	}
	if _, err := bob.JoinGroup(ctx, w); err != nil {
		t.Fatalf("JoinGroup: %v", err)
	}
	return alice, bob, gid
}

// TestOtherMembersProcessLeaveCommit checks that alice processes the leave commit of bob.
func TestOtherMembersProcessLeaveCommit(t *testing.T) {
	ctx := context.Background()
	alice, bob, gid := newValidClientPair(t, CacheNone)
	commit, err := bob.LeaveGroup(ctx, gid)
	if err != nil {
		t.Fatalf("LeaveGroup: %v", err)
	}
	if err := alice.ProcessCommit(ctx, gid, commit); err != nil {
		t.Fatalf("alice.ProcessCommit(bob leave): %v", err)
	}
}

// TestRejoinAfterLeave checks that bob can join again with a new Welcome after leaving the group.
func TestRejoinAfterLeave(t *testing.T) {
	ctx := context.Background()
	alice, bob, gid := newValidClientPair(t, CacheNone)
	commit, err := bob.LeaveGroup(ctx, gid)
	if err != nil {
		t.Fatalf("LeaveGroup: %v", err)
	}
	if err := alice.ProcessCommit(ctx, gid, commit); err != nil {
		t.Fatalf("alice.ProcessCommit(bob leave): %v", err)
	}
	kp, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes: %v", err)
	}
	_, w, err := alice.InviteMember(ctx, gid, kp)
	if err != nil {
		t.Fatalf("InviteMember(rejoin): %v", err)
	}
	if _, err := bob.JoinGroup(ctx, w); err != nil {
		t.Fatalf("JoinGroup(rejoin): %v", err)
	}
	ct, err := alice.SendMessage(ctx, gid, []byte("welcome back"))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if _, err := bob.ReceiveMessage(ctx, gid, ct); err != nil {
		t.Fatalf("ReceiveMessage after rejoin: %v", err)
	}
}

// TestRejoinAfterRemoval checks that bob can join again with a new Welcome after being removed.
func TestRejoinAfterRemoval(t *testing.T) {
	ctx := context.Background()
	alice, bob, gid := newValidClientPair(t, CacheNone)
	commit, err := alice.RemoveMember(ctx, gid, []byte("bob"))
	if err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if err := bob.ProcessCommit(ctx, gid, commit); err == nil {
		t.Fatalf("bob.ProcessCommit(remove bob) returned nil; want a removal result")
	}
	kp, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes: %v", err)
	}
	_, w, err := alice.InviteMember(ctx, gid, kp)
	if err != nil {
		t.Fatalf("InviteMember(rejoin): %v", err)
	}
	if _, err := bob.JoinGroup(ctx, w); err != nil {
		t.Fatalf("JoinGroup(rejoin after removal): %v", err)
	}
}
