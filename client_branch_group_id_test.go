package mls

import (
	"bytes"
	"context"
	"testing"
)

// TestBranchUsesFreshGroupIDAndKeepsParent checks that Branch gives the subgroup a new group ID, so the member
// who joins it accepts its Welcome (RFC 9420 §12.4.3), and that the parent group keeps its epoch and keeps
// working for the brancher and for that member.
func TestBranchUsesFreshGroupIDAndKeepsParent(t *testing.T) {
	ctx := context.Background()
	alice := newGroupIDTestClient(t, "alice")
	charlie := newGroupIDTestClient(t, "charlie")

	kp, err := charlie.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(parent): %v", err)
	}
	parentID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	_, welcome, err := alice.InviteMember(ctx, parentID, kp)
	if err != nil {
		t.Fatalf("InviteMember: %v", err)
	}
	if _, err := charlie.JoinGroup(ctx, welcome); err != nil {
		t.Fatalf("JoinGroup(parent): %v", err)
	}
	parentEpoch := mustEpoch(t, alice, parentID)

	kpBranch, err := charlie.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(branch): %v", err)
	}
	branchID, _, branchWelcome, err := alice.Branch(ctx, parentID, [][]byte{kpBranch})
	if err != nil {
		t.Fatalf("Branch: %v", err)
	}
	if bytes.Equal(branchID, parentID) {
		t.Fatalf("Branch reused the parent group ID %x", parentID)
	}
	if got := mustEpoch(t, alice, parentID); got != parentEpoch {
		t.Fatalf("alice's parent epoch after Branch = %d, want %d", got, parentEpoch)
	}

	pskKey, pskSecret, err := charlie.ResumptionPSK(ctx, parentID)
	if err != nil {
		t.Fatalf("ResumptionPSK: %v", err)
	}
	joined, err := charlie.JoinGroupWithPSKs(ctx, branchWelcome, map[string][]byte{pskKey: pskSecret})
	if err != nil {
		t.Fatalf("JoinGroupWithPSKs(branch): %v", err)
	}
	if !bytes.Equal(joined, branchID) {
		t.Fatalf("charlie joined %x, want the branch %x", joined, branchID)
	}
	if got := mustEpoch(t, charlie, parentID); got != parentEpoch {
		t.Fatalf("charlie's parent epoch after joining the branch = %d, want %d", got, parentEpoch)
	}

	msg, err := alice.SendMessage(ctx, parentID, []byte("parent still works"))
	if err != nil {
		t.Fatalf("SendMessage(parent): %v", err)
	}
	got, err := charlie.ReceiveMessage(ctx, parentID, msg)
	if err != nil {
		t.Fatalf("ReceiveMessage(parent): %v", err)
	}
	if !bytes.Equal(got.Plaintext, []byte("parent still works")) {
		t.Fatalf("ReceiveMessage(parent) = %q", got.Plaintext)
	}
}
