package mls

import (
	"context"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
)

// twoClientsForLeave returns a group created by alice with bob joined: alice is leaf 0 and bob is leaf 1.
func twoClientsForLeave(t *testing.T, ctx context.Context) (alice, bob *Client, aliceGroupID, bobGroupID []byte) {
	t.Helper()
	cs := ciphersuite.MLS128DHKEMP256
	alice, err := NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("creating alice client: %v", err)
	}
	bob, err = NewClient([]byte("bob"), cs)
	if err != nil {
		t.Fatalf("creating bob client: %v", err)
	}
	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("creating bob key package: %v", err)
	}
	aliceGroupID, err = alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}
	_, bobWelcome, err := alice.InviteMember(ctx, aliceGroupID, bobKP)
	if err != nil {
		t.Fatalf("inviting bob: %v", err)
	}
	bobGroupID, err = bob.JoinGroup(ctx, bobWelcome)
	if err != nil {
		t.Fatalf("bob joining group: %v", err)
	}
	return alice, bob, aliceGroupID, bobGroupID
}

// TestLeaveGroupReturnsRemoveProposal checks, at the Client level, that a member cannot remove itself with a
// Commit (RFC 9420 §12.2), so:
//   - RemoveMember with the caller's own identity is refused and leaves no pending proposal behind;
//   - LeaveGroup returns a signed Remove proposal for the caller's own leaf, not a Commit. Another member
//     processes it and commits it, and the leaver's local state is deleted.
func TestLeaveGroupReturnsRemoveProposal(t *testing.T) {
	t.Run("commit_removing_own_identity_is_refused", func(t *testing.T) {
		ctx := context.Background()
		_, bob, _, bobGroupID := twoClientsForLeave(t, ctx)

		epochBefore, err := bob.Epoch(ctx, bobGroupID)
		if err != nil {
			t.Fatalf("Epoch before RemoveMember: %v", err)
		}
		if _, err := bob.RemoveMember(ctx, bobGroupID, []byte("bob")); err == nil {
			t.Fatal("RemoveMember with the caller's own identity succeeded, want an error (RFC 9420 §12.2)")
		}
		epochAfter, err := bob.Epoch(ctx, bobGroupID)
		if err != nil {
			t.Fatalf("Epoch after refused RemoveMember: %v", err)
		}
		if epochAfter != epochBefore {
			t.Fatalf("epoch after refused RemoveMember = %d, want %d", epochAfter, epochBefore)
		}
		// The refused removal must not leave a Remove of the committer in the pending proposals,
		// otherwise every later commit of this member would fail.
		if _, err := bob.SelfUpdate(ctx, bobGroupID); err != nil {
			t.Fatalf("SelfUpdate after refused RemoveMember: %v", err)
		}
	})

	t.Run("leave_returns_remove_proposal_another_member_commits", func(t *testing.T) {
		ctx := context.Background()
		alice, bob, aliceGroupID, bobGroupID := twoClientsForLeave(t, ctx)

		msg, err := bob.LeaveGroup(ctx, bobGroupID)
		if err != nil {
			t.Fatalf("LeaveGroup: %v", err)
		}

		// The output is a signed PublicMessage that carries a Remove proposal for the leaver's own leaf (leaf 1).
		mlsMsg, err := framing.UnmarshalMLSMessage(msg)
		if err != nil {
			t.Fatalf("LeaveGroup output does not parse as an MLSMessage: %v", err)
		}
		pub, ok := mlsMsg.AsPublic()
		if !ok {
			t.Fatal("LeaveGroup output is not a PublicMessage")
		}
		if got := pub.Content.ContentType(); got != framing.ContentTypeProposal {
			t.Fatalf("LeaveGroup output content type = %v, want a proposal: a member must not commit its own removal (RFC 9420 §12.2)", got)
		}
		body, ok := pub.Content.Body.(framing.ProposalBody)
		if !ok {
			t.Fatal("LeaveGroup proposal has no proposal body")
		}
		proposal, err := group.UnmarshalProposal(body.Data)
		if err != nil {
			t.Fatalf("parsing leave proposal: %v", err)
		}
		if proposal.Type != group.ProposalTypeRemove || proposal.Remove == nil || proposal.Remove.Removed != group.LeafNodeIndex(1) {
			t.Fatalf("leave proposal = %+v, want a Remove of leaf 1", proposal)
		}
		if pub.Content.Sender.LeafIndex != 1 {
			t.Fatalf("leave proposal sender = %d, want 1", pub.Content.Sender.LeafIndex)
		}

		// The leaver's local state is deleted.
		if _, err := bob.Epoch(ctx, bobGroupID); !errors.Is(err, ErrGroupNotFound) {
			t.Fatalf("Epoch after LeaveGroup = %v, want ErrGroupNotFound", err)
		}

		// Alice processes the proposal and commits it, and the commit removes bob.
		if err := alice.ProcessPublicMessage(ctx, aliceGroupID, msg); err != nil {
			t.Fatalf("alice processing leave proposal: %v", err)
		}
		commit, _, err := alice.CommitPendingProposals(ctx, aliceGroupID)
		if err != nil {
			t.Fatalf("alice committing leave proposal: %v", err)
		}
		if len(commit) == 0 {
			t.Fatal("CommitPendingProposals returned no commit")
		}
		members, err := alice.ListMembers(ctx, aliceGroupID)
		if err != nil {
			t.Fatalf("listing members: %v", err)
		}
		if len(members) != 1 || string(members[0].Identity) != "alice" {
			t.Fatalf("members after alice committed bob's leave = %v, want only alice", members)
		}
	})
}
