//go:build diagnostics

package mls

import (
	"strings"
	"testing"
)

// Additional diagnostics for client commit policy enforcement.

// TestClientPublicCommitEnforcesProposalPolicy checks that both client commit entry points apply the configured proposal policy.
func TestClientPublicCommitEnforcesProposalPolicy(t *testing.T) {
	ctx := t.Context()
	alice, bob, groupID := newCommitPolicyTestPair(t, WithProposalPolicy(identityBlockingPolicy{blocked: "mallory"}))
	commit := newInlineAddCommit(t, bob, groupID, newCommitPolicyTestClient(t, "mallory"))

	// Control: ProcessCommit refuses the commit, and a refusal leaves the state unchanged.
	if err := alice.ProcessCommit(ctx, groupID, commit); err == nil || !strings.Contains(err.Error(), "blocked by policy") {
		t.Fatalf("control ProcessCommit(add mallory): err = %v, want policy rejection", err)
	}
	epochBefore, membersBefore := commitPolicyTestState(t, alice, groupID)
	err := alice.ProcessPublicMessage(ctx, groupID, commit)
	epochAfter, membersAfter := commitPolicyTestState(t, alice, groupID)
	if err == nil || !strings.Contains(err.Error(), "blocked by policy") {
		t.Errorf("ProcessPublicMessage(same commit adding mallory): err = %v, want policy rejection; epoch %d -> %d, members %v -> %v",
			err, epochBefore, epochAfter, membersBefore, membersAfter)
	}
}

// TestClientPublicCommitEnforcesCredentialValidator checks that both client commit entry points apply the configured credential validator.
func TestClientPublicCommitEnforcesCredentialValidator(t *testing.T) {
	ctx := t.Context()
	alice, bob, groupID := newCommitPolicyTestPair(t, WithCredentialValidator(rejectingValidator{rejectIdentity: "mallory"}))
	commit := newInlineAddCommit(t, bob, groupID, newCommitPolicyTestClient(t, "mallory"))

	// Control: the same bytes through ProcessCommit are refused.
	if err := alice.ProcessCommit(ctx, groupID, commit); err == nil || !strings.Contains(err.Error(), `identity "mallory" rejected`) {
		t.Fatalf("control ProcessCommit(add mallory): err = %v, want credential rejection", err)
	}
	epochBefore, membersBefore := commitPolicyTestState(t, alice, groupID)
	err := alice.ProcessPublicMessage(ctx, groupID, commit)
	epochAfter, membersAfter := commitPolicyTestState(t, alice, groupID)
	if err == nil || !strings.Contains(err.Error(), `identity "mallory" rejected`) {
		t.Errorf("ProcessPublicMessage(same commit adding mallory) with validator: err = %v, want credential rejection; epoch %d -> %d, members %v -> %v",
			err, epochBefore, epochAfter, membersBefore, membersAfter)
	}
}
