package mls

import (
	"context"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// TestClientRevokeProposals_HappyPath covers the RevokeProposals wrapper: a
// member receives an Add proposal from another member via ProcessPublicMessage
// (which populates the pending store with a computable ProposalRef), and the
// proposal is then revoked by that ref. The wrapper must remove it from both
// the pending store and the proposalByRef lookup, so a subsequent
// CommitPendingProposals has nothing left to commit for it.
func TestClientRevokeProposals_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256

	alice, err := NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	bob, err := NewClient([]byte("bob"), cs)
	if err != nil {
		t.Fatalf("bob: %v", err)
	}
	charlie, err := NewClient([]byte("charlie"), cs)
	if err != nil {
		t.Fatalf("charlie: %v", err)
	}

	// 1. alice creates a group and invites bob.
	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("alice.CreateGroup: %v", err)
	}
	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("bob.FreshKeyPackageBytes: %v", err)
	}
	_, bobWelcome, err := alice.InviteMember(ctx, groupID, bobKP)
	if err != nil {
		t.Fatalf("alice.InviteMember(bob): %v", err)
	}
	bobGroupID, err := bob.JoinGroup(ctx, bobWelcome)
	if err != nil {
		t.Fatalf("bob.JoinGroup: %v", err)
	}

	// 2. alice creates an Add proposal for charlie.
	charlieKP, err := charlie.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("charlie.FreshKeyPackageBytes: %v", err)
	}
	addProposalMsg, err := alice.ProposeAddMember(ctx, groupID, charlieKP)
	if err != nil {
		t.Fatalf("alice.ProposeAddMember: %v", err)
	}
	if len(addProposalMsg) == 0 {
		t.Fatal("ProposeAddMember returned empty bytes")
	}

	// 3. bob receives the proposal over the wire (ProcessPublicMessage).
	//    This populates his pending store with a StoredProposal whose Ref != nil.
	if err := bob.ProcessPublicMessage(ctx, bobGroupID, addProposalMsg); err != nil {
		t.Fatalf("bob.ProcessPublicMessage(add): %v", err)
	}
	bobGroup := loadGroupForTest(t, bob, bobGroupID)
	pending := bobGroup.Proposals()
	if got := len(pending.Proposals); got != 1 {
		t.Fatalf("bob pending proposals = %d, want 1", got)
	}
	ref := pending.Proposals[0].Ref
	if len(ref) == 0 {
		t.Fatal("StoredProposal.Ref is nil/empty — RegisterProposalRef not called on receive path")
	}

	// 4. The in-flight add is revoked. RevokeProposals must be idempotent.
	if err := bob.RevokeProposals(ctx, bobGroupID, [][]byte{ref}); err != nil {
		t.Fatalf("bob.RevokeProposals(valid ref): %v", err)
	}

	// 5. The proposal was removed from the pending store (the proposalByRef
	//    lookup is cleared alongside it inside g.RevokeProposal).
	bobGroup = loadGroupForTest(t, bob, bobGroupID)
	if got := len(bobGroup.Proposals().Proposals); got != 0 {
		t.Fatalf("after RevokeProposals, pending = %d, want 0", got)
	}

	// 6. CommitPendingProposals no longer includes charlie's add: a revoked
	//    proposal makes the subsequent commit empty (empty welcome). Before
	//    the revoke we'd expect a non-empty welcome (carrying charlie's add).
	commit, welcome, err := bob.CommitPendingProposals(ctx, bobGroupID)
	if err != nil {
		t.Fatalf("CommitPendingProposals after revoke: %v", err)
	}
	if len(welcome) != 0 {
		t.Fatalf("welcome after revoke = %d bytes, want empty (charlie add was revoked)", len(welcome))
	}
	if len(commit) == 0 {
		t.Fatal("commit bytes empty")
	}

	// 7. Idempotency: revoking the same ref again is not an error.
	if err := bob.RevokeProposals(ctx, bobGroupID, [][]byte{ref}); err != nil {
		t.Fatalf("bob.RevokeProposals(already-revoked ref, idempotent): %v", err)
	}

	// 8. Empty refs are silently skipped (no error, no panic).
	if err := bob.RevokeProposals(ctx, bobGroupID, [][]byte{nil, {}}); err != nil {
		t.Fatalf("bob.RevokeProposals(empty refs): %v", err)
	}
}
