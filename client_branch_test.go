package mls

import (
	"context"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// TestClientBranch_EndToEnd exercises RFC 9420 §11.3 subgroup branching
// entirely through the Client API: alice branches a subgroup off her group
// with bob, inviting charlie; charlie joins using ResumptionPSK (which
// supplies the value JoinGroupWithPSKs needs, since it's never transmitted
// in the Welcome) and lands in the new group at the committer's epoch.
func TestClientBranch_EndToEnd(t *testing.T) {
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256

	alice, err := NewClient([]byte("alice-client-branch"), cs)
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	bob, err := NewClient([]byte("bob-client-branch"), cs)
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}
	charlie, err := NewClient([]byte("charlie-client-branch"), cs)
	if err != nil {
		t.Fatalf("NewClient(charlie): %v", err)
	}

	bobKPBytes, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(bob): %v", err)
	}
	charlieOldKPBytes, err := charlie.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(charlie, old group): %v", err)
	}
	oldGroupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if _, _, err := alice.InviteMember(ctx, oldGroupID, bobKPBytes); err != nil {
		t.Fatalf("InviteMember(bob): %v", err)
	}
	// RFC §11.3: subgroup members MUST be current members of the old group —
	// charlie must actually join oldGroupID before being branched into a
	// subgroup, so his Client holds oldGroupID's resumption secret locally.
	_, oldWelcome, err := alice.InviteMember(ctx, oldGroupID, charlieOldKPBytes)
	if err != nil {
		t.Fatalf("InviteMember(charlie): %v", err)
	}
	if _, err := charlie.JoinGroup(ctx, oldWelcome); err != nil {
		t.Fatalf("charlie JoinGroup(old group): %v", err)
	}

	// RFC §11.3 step 1: fetch a fresh KeyPackage per subgroup member.
	charlieKPBytes, err := charlie.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(charlie, branch): %v", err)
	}

	newGroupID, _, welcome, err := alice.Branch(ctx, oldGroupID, [][]byte{charlieKPBytes})
	if err != nil {
		t.Fatalf("Branch: %v", err)
	}
	if welcome == nil {
		t.Fatal("expected a Welcome for charlie")
	}

	aliceEpoch, err := alice.Epoch(ctx, newGroupID)
	if err != nil {
		t.Fatalf("Epoch(alice, new group): %v", err)
	}
	if aliceEpoch != 1 {
		t.Fatalf("alice's branch epoch = %d, want 1 (RFC §11.3)", aliceEpoch)
	}

	// Plain JoinGroup must fail: it has no way to supply the branch PSK.
	if _, err := charlie.JoinGroup(ctx, welcome); err == nil {
		t.Fatal("JoinGroup should fail on a branch Welcome (no PSK support), but succeeded")
	}

	// Charlie retrieves the resumption secret from the OLD group he was
	// already a member of — never transmitted in the Welcome.
	pskKey, pskSecret, err := charlie.ResumptionPSK(ctx, oldGroupID)
	if err != nil {
		t.Fatalf("ResumptionPSK: %v", err)
	}

	joinedGroupID, err := charlie.JoinGroupWithPSKs(ctx, welcome, map[string][]byte{pskKey: pskSecret})
	if err != nil {
		t.Fatalf("JoinGroupWithPSKs: %v", err)
	}
	charlieEpoch, err := charlie.Epoch(ctx, joinedGroupID)
	if err != nil {
		t.Fatalf("Epoch(charlie): %v", err)
	}
	if charlieEpoch != aliceEpoch {
		t.Fatalf("charlie epoch = %d, want %d (alice's)", charlieEpoch, aliceEpoch)
	}

	// The branch group is fully operational: alice can message charlie.
	msg, err := alice.SendMessage(ctx, newGroupID, []byte("hello from the branch"))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	received, err := charlie.ReceiveMessage(ctx, joinedGroupID, msg)
	if err != nil {
		t.Fatalf("ReceiveMessage: %v", err)
	}
	if string(received.Plaintext) != "hello from the branch" {
		t.Fatalf("plaintext = %q", received.Plaintext)
	}
}

// TestClientBranch_NoOtherMembers verifies branching with only the caller
// (no Welcome needed) works and doesn't require the joiner-side PSK dance.
func TestClientBranch_NoOtherMembers(t *testing.T) {
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256

	alice, err := NewClient([]byte("alice-solo-branch"), cs)
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	newGroupID, commit, welcome, err := alice.Branch(ctx, groupID, nil)
	if err != nil {
		t.Fatalf("Branch: %v", err)
	}
	if commit == nil {
		t.Fatal("expected commit bytes")
	}
	if welcome != nil {
		t.Fatal("expected nil welcome (no other members)")
	}
	epoch, err := alice.Epoch(ctx, newGroupID)
	if err != nil {
		t.Fatalf("Epoch: %v", err)
	}
	if epoch != 1 {
		t.Fatalf("epoch = %d, want 1", epoch)
	}
}
