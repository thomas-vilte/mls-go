package mls_test

// A delivery service may send the same proposal PublicMessage more than once within an epoch, and it
// sends a proposal back to its own sender. A proposal received N times is stored once, so the commit does
// not fail on duplicates and a revoked proposal cannot be committed through a leftover copy.
//
// These tests use the public client API. The only internal function is group.ComputeProposalRef, which
// computes the same reference as Client does, so that RevokeProposals can be called with it.

import (
	"context"
	"fmt"
	"testing"

	"github.com/thomas-vilte/mls-go"
	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
)

var repeatedProposalsCS = ciphersuite.MLS128DHKEMX25519

// newThreeMemberGroup creates a group of three members in a common epoch.
// Indexes: 0 committer (alice), 1 proposer (bob), 2 removed (carol).
func newThreeMemberGroup(t *testing.T) (members []*mls.Client, groupID []byte) {
	t.Helper()
	ctx := context.Background()
	clients := make([]*mls.Client, 3)
	for i := range clients {
		c, err := mls.NewClient([]byte(fmt.Sprintf("member-%d", i)), repeatedProposalsCS)
		if err != nil {
			t.Fatalf("NewClient(%d): %v", i, err)
		}
		clients[i] = c
	}
	gid, err := clients[0].CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	for i := 1; i < len(clients); i++ {
		kp, err := clients[i].FreshKeyPackageBytes(ctx)
		if err != nil {
			t.Fatalf("FreshKeyPackageBytes(%d): %v", i, err)
		}
		if _, err := clients[0].ProposeAddMember(ctx, gid, kp); err != nil {
			t.Fatalf("ProposeAddMember(%d): %v", i, err)
		}
	}
	_, welcome, err := clients[0].CommitPendingProposals(ctx, gid)
	if err != nil {
		t.Fatalf("CommitPendingProposals(setup): %v", err)
	}
	for i := 1; i < len(clients); i++ {
		if _, err := clients[i].JoinGroup(ctx, welcome); err != nil {
			t.Fatalf("JoinGroup(%d): %v", i, err)
		}
	}
	return clients, gid
}

// removeCarolProposal returns the PublicMessage of a Remove of carol, proposed by bob.
func removeCarolProposal(t *testing.T, clients []*mls.Client, gid []byte) []byte {
	t.Helper()
	msg, err := clients[1].ProposeRemoveMember(context.Background(), gid, []byte("member-2"))
	if err != nil {
		t.Fatalf("ProposeRemoveMember: %v", err)
	}
	return msg
}

// proposalRefOf computes the ProposalRef of a proposal PublicMessage the way Client does: from the
// AuthenticatedContent without the GroupContext.
func proposalRefOf(t *testing.T, msg []byte) []byte {
	t.Helper()
	m, err := framing.UnmarshalMLSMessage(msg)
	if err != nil {
		t.Fatalf("UnmarshalMLSMessage: %v", err)
	}
	pm, ok := m.AsPublic()
	if !ok {
		t.Fatalf("the message is not a PublicMessage")
	}
	ac := &framing.AuthenticatedContent{
		WireFormat: framing.WireFormatPublicMessage,
		Content:    pm.Content,
		Auth:       pm.Auth,
	}
	return group.ComputeProposalRef(ac.Marshal(), repeatedProposalsCS)
}

// memberCount returns how many members the client sees in the group.
func memberCount(t *testing.T, c *mls.Client, gid []byte) int {
	t.Helper()
	ms, err := c.ListMembers(context.Background(), gid)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	return len(ms)
}

// TestCommitAppliesSingleRemoveProposal checks that a Remove received once is committed and applied
// (3 members become 2).
func TestCommitAppliesSingleRemoveProposal(t *testing.T) {
	ctx := context.Background()
	clients, gid := newThreeMemberGroup(t)
	msg := removeCarolProposal(t, clients, gid)
	if err := clients[0].ProcessPublicMessage(ctx, gid, msg); err != nil {
		t.Fatalf("ProcessPublicMessage: %v", err)
	}
	if _, _, err := clients[0].CommitPendingProposals(ctx, gid); err != nil {
		t.Fatalf("commit with a single copy of the Remove failed: %v", err)
	}
	if n := memberCount(t, clients[0], gid); n != 2 {
		t.Fatalf("members after the commit = %d, want 2", n)
	}
}

// TestCommitSucceedsAfterRemoveProposalIsDeliveredTwice checks that the same Remove PublicMessage
// delivered twice within an epoch is stored once, so the commit does not fail on a duplicate remove
// and applies the Remove once.
func TestCommitSucceedsAfterRemoveProposalIsDeliveredTwice(t *testing.T) {
	ctx := context.Background()
	clients, gid := newThreeMemberGroup(t)
	msg := removeCarolProposal(t, clients, gid)
	for i := 1; i <= 2; i++ {
		if err := clients[0].ProcessPublicMessage(ctx, gid, msg); err != nil {
			t.Fatalf("delivery %d of the same PublicMessage was rejected: %v", i, err)
		}
	}
	if _, _, err := clients[0].CommitPendingProposals(ctx, gid); err != nil {
		t.Fatalf("commit after receiving the same Remove twice failed: %v", err)
	}
	if n := memberCount(t, clients[0], gid); n != 2 {
		t.Fatalf("members after the commit = %d, want 2", n)
	}
}

// TestRevokeProposalsDropsSingleRemoveCopy checks that RevokeProposals withdraws a Remove that was
// received once, so the commit does not remove carol.
func TestRevokeProposalsDropsSingleRemoveCopy(t *testing.T) {
	ctx := context.Background()
	clients, gid := newThreeMemberGroup(t)
	msg := removeCarolProposal(t, clients, gid)
	ref := proposalRefOf(t, msg)
	if err := clients[0].ProcessPublicMessage(ctx, gid, msg); err != nil {
		t.Fatalf("ProcessPublicMessage: %v", err)
	}
	if err := clients[0].RevokeProposals(ctx, gid, [][]byte{ref}); err != nil {
		t.Fatalf("RevokeProposals: %v", err)
	}
	if _, _, err := clients[0].CommitPendingProposals(ctx, gid); err != nil {
		t.Fatalf("commit without pending proposals failed: %v", err)
	}
	if n := memberCount(t, clients[0], gid); n != 3 {
		t.Fatalf("members = %d, want 3: a revoked proposal must not be applied (with 2, the computed ref does not match the stored one)", n)
	}
}

// TestRevokeProposalsLeavesNoCommittableCopy checks that after the same Remove is delivered twice, a
// single RevokeProposals with its ref withdraws the proposal: no second copy is left that a later commit
// would apply, so carol stays in the group.
func TestRevokeProposalsLeavesNoCommittableCopy(t *testing.T) {
	ctx := context.Background()
	clients, gid := newThreeMemberGroup(t)
	msg := removeCarolProposal(t, clients, gid)
	ref := proposalRefOf(t, msg)
	for i := 1; i <= 2; i++ {
		if err := clients[0].ProcessPublicMessage(ctx, gid, msg); err != nil {
			t.Fatalf("delivery %d: %v", i, err)
		}
	}
	if err := clients[0].RevokeProposals(ctx, gid, [][]byte{ref}); err != nil {
		t.Fatalf("RevokeProposals: %v", err)
	}
	if _, _, err := clients[0].CommitPendingProposals(ctx, gid); err != nil {
		t.Fatalf("commit after revoking the proposal failed: %v", err)
	}
	if n := memberCount(t, clients[0], gid); n != 3 {
		t.Fatalf("members = %d, want 3: a copy of the revoked Remove was committed and carol was removed", n)
	}
}

// TestDistinctProposalsAccumulate checks that different proposals still accumulate. Bob proposes an
// Add (dave) and a Remove (carol), alice receives each once, and the commit applies both: three members
// remain, carol leaves and dave joins.
func TestDistinctProposalsAccumulate(t *testing.T) {
	ctx := context.Background()
	clients, gid := newThreeMemberGroup(t)
	dave, err := mls.NewClient([]byte("member-3"), repeatedProposalsCS)
	if err != nil {
		t.Fatalf("NewClient(dave): %v", err)
	}
	daveKP, err := dave.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(dave): %v", err)
	}
	addMsg, err := clients[1].ProposeAddMember(ctx, gid, daveKP)
	if err != nil {
		t.Fatalf("ProposeAddMember(dave): %v", err)
	}
	removeMsg := removeCarolProposal(t, clients, gid)
	for _, msg := range [][]byte{addMsg, removeMsg} {
		if err := clients[0].ProcessPublicMessage(ctx, gid, msg); err != nil {
			t.Fatalf("ProcessPublicMessage: %v", err)
		}
	}
	if _, _, err := clients[0].CommitPendingProposals(ctx, gid); err != nil {
		t.Fatalf("commit with a distinct Add and Remove failed: %v", err)
	}
	if n := memberCount(t, clients[0], gid); n != 3 {
		t.Fatalf("members = %d, want 3 (carol leaves, dave joins)", n)
	}
}

// TestCommitAppliesOwnRemoveEchoOnce checks that the delivery service sending alice the Remove she
// signed herself is the same proposal (same ProposalRef): it is not stored again, and the commit applies
// it once.
func TestCommitAppliesOwnRemoveEchoOnce(t *testing.T) {
	ctx := context.Background()
	clients, gid := newThreeMemberGroup(t)
	msg, err := clients[0].ProposeRemoveMember(ctx, gid, []byte("member-2"))
	if err != nil {
		t.Fatalf("ProposeRemoveMember: %v", err)
	}
	if err := clients[0].ProcessPublicMessage(ctx, gid, msg); err != nil {
		t.Fatalf("the echo of the own Remove was rejected: %v", err)
	}
	if _, _, err := clients[0].CommitPendingProposals(ctx, gid); err != nil {
		t.Fatalf("the echo of the own Remove made the commit fail: %v", err)
	}
	if n := memberCount(t, clients[0], gid); n != 2 {
		t.Fatalf("members after the commit = %d, want 2", n)
	}
}

// TestCommitAppliesOwnAddEchoOnce checks the same for an own Add: the echo does not fail with a
// duplicate init key and does not duplicate the proposal.
func TestCommitAppliesOwnAddEchoOnce(t *testing.T) {
	ctx := context.Background()
	clients, gid := newThreeMemberGroup(t)
	dave, err := mls.NewClient([]byte("member-3"), repeatedProposalsCS)
	if err != nil {
		t.Fatalf("NewClient(dave): %v", err)
	}
	daveKP, err := dave.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(dave): %v", err)
	}
	msg, err := clients[0].ProposeAddMember(ctx, gid, daveKP)
	if err != nil {
		t.Fatalf("ProposeAddMember(dave): %v", err)
	}
	if err := clients[0].ProcessPublicMessage(ctx, gid, msg); err != nil {
		t.Fatalf("the echo of the own Add was rejected: %v", err)
	}
	if _, _, err := clients[0].CommitPendingProposals(ctx, gid); err != nil {
		t.Fatalf("the echo of the own Add made the commit fail: %v", err)
	}
	if n := memberCount(t, clients[0], gid); n != 4 {
		t.Fatalf("members after the commit = %d, want 4", n)
	}
}
