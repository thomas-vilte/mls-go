package mls

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
)

// countingProposalPolicy accepts every proposal and counts calls to the policy.
type countingProposalPolicy struct {
	calls *int
}

func (p countingProposalPolicy) ReviewProposal(_ context.Context, _ GroupSnapshot, _ ReviewableProposal) error {
	*p.calls++
	return nil
}

// TestClientPublicCommitProposalReview checks inline proposal review through
// ProcessPublicMessage. Rejected commits must preserve epoch and membership,
// and messages that fail verification must not reach the policy.
func TestClientPublicCommitProposalReview(t *testing.T) {
	ctx := t.Context()

	t.Run("reject/policy_blocks_inline_add", func(t *testing.T) {
		alice, bob, groupID := newCommitPolicyTestPair(t, WithProposalPolicy(identityBlockingPolicy{blocked: "mallory"}))
		commit := newInlineAddCommit(t, bob, groupID, newCommitPolicyTestClient(t, "mallory"))
		epochBefore, membersBefore := commitPolicyTestState(t, alice, groupID)

		err := alice.ProcessPublicMessage(ctx, groupID, commit)
		if err == nil || !strings.Contains(err.Error(), "blocked by policy") {
			t.Fatalf("ProcessPublicMessage(inline add of mallory): err = %v, want policy rejection", err)
		}
		epochAfter, membersAfter := commitPolicyTestState(t, alice, groupID)
		if epochAfter != epochBefore || !slices.Equal(membersAfter, membersBefore) {
			t.Fatalf("rejected commit changed state: epoch %d -> %d, members %v -> %v",
				epochBefore, epochAfter, membersBefore, membersAfter)
		}
	})

	t.Run("reject/credential_validator_blocks_inline_add", func(t *testing.T) {
		alice, bob, groupID := newCommitPolicyTestPair(t, WithCredentialValidator(rejectingValidator{rejectIdentity: "mallory"}))
		commit := newInlineAddCommit(t, bob, groupID, newCommitPolicyTestClient(t, "mallory"))
		epochBefore, membersBefore := commitPolicyTestState(t, alice, groupID)

		err := alice.ProcessPublicMessage(ctx, groupID, commit)
		if err == nil || !strings.Contains(err.Error(), `identity "mallory" rejected`) {
			t.Fatalf("ProcessPublicMessage(inline add of mallory): err = %v, want credential rejection", err)
		}
		epochAfter, membersAfter := commitPolicyTestState(t, alice, groupID)
		if epochAfter != epochBefore || !slices.Equal(membersAfter, membersBefore) {
			t.Fatalf("rejected commit changed state: epoch %d -> %d, members %v -> %v",
				epochBefore, epochAfter, membersBefore, membersAfter)
		}
	})

	// The last byte of a member's PublicMessage lies in the membership tag. Flipping it keeps the
	// message parseable but breaks its verification, so the policy must not see the commit.
	t.Run("reject/unauthenticated_commit_does_not_reach_policy", func(t *testing.T) {
		calls := 0
		alice, bob, groupID := newCommitPolicyTestPair(t, WithProposalPolicy(countingProposalPolicy{calls: &calls}))
		commit := newInlineAddCommit(t, bob, groupID, newCommitPolicyTestClient(t, "carol"))
		tampered := bytes.Clone(commit)
		tampered[len(tampered)-1] ^= 0x01
		callsBefore := calls
		epochBefore, _ := commitPolicyTestState(t, alice, groupID)

		if err := alice.ProcessPublicMessage(ctx, groupID, tampered); err == nil {
			t.Fatal("ProcessPublicMessage(tampered commit): err = nil, want a verification failure")
		}
		if calls != callsBefore {
			t.Fatalf("ProposalPolicy ran %d time(s) on a commit that failed verification, want 0", calls-callsBefore)
		}
		if epochAfter, _ := commitPolicyTestState(t, alice, groupID); epochAfter != epochBefore {
			t.Fatalf("tampered commit changed the epoch: %d -> %d", epochBefore, epochAfter)
		}
	})

	t.Run("control/policy_allows_other_identity", func(t *testing.T) {
		alice, bob, groupID := newCommitPolicyTestPair(t, WithProposalPolicy(identityBlockingPolicy{blocked: "mallory"}))
		commit := newInlineAddCommit(t, bob, groupID, newCommitPolicyTestClient(t, "carol"))
		epochBefore, _ := commitPolicyTestState(t, alice, groupID)

		if err := alice.ProcessPublicMessage(ctx, groupID, commit); err != nil {
			t.Fatalf("ProcessPublicMessage(inline add of carol): %v", err)
		}
		epochAfter, members := commitPolicyTestState(t, alice, groupID)
		if epochAfter != epochBefore+1 || !slices.Contains(members, "carol") {
			t.Fatalf("accepted commit: epoch %d -> %d, members %v; want epoch %d and carol present",
				epochBefore, epochAfter, members, epochBefore+1)
		}
	})
}
