package mls

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
)

// identityBlockingPolicy is an application ProposalPolicy that blocks every Add of one identity.
type identityBlockingPolicy struct {
	blocked string
}

func (p identityBlockingPolicy) ReviewProposal(_ context.Context, _ GroupSnapshot, proposal ReviewableProposal) error {
	if proposal.Type == group.ProposalTypeAdd && proposal.Add != nil && string(proposal.Add.Identity) == p.blocked {
		return fmt.Errorf("add of %q blocked by policy", p.blocked)
	}
	return nil
}

// newCommitPolicyTestClient returns a client with a Basic credential for identity.
func newCommitPolicyTestClient(t *testing.T, identity string) *Client {
	t.Helper()
	c, err := NewClient([]byte(identity), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("creating %s client: %v", identity, err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("closing %s client: %v", identity, err)
		}
	})
	return c
}

// newCommitPolicyTestPair creates a group with aliceOpts on Alice and no review
// hooks on Bob, who produces the commits exercised by these tests.
func newCommitPolicyTestPair(t *testing.T, aliceOpts ...ClientOption) (alice, bob *Client, groupID []byte) {
	t.Helper()
	ctx := t.Context()
	alice, err := NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256, aliceOpts...)
	if err != nil {
		t.Fatalf("creating alice client: %v", err)
	}
	t.Cleanup(func() {
		if err := alice.Close(); err != nil {
			t.Errorf("closing alice client: %v", err)
		}
	})
	bob = newCommitPolicyTestClient(t, "bob")
	groupID, err = alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}
	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("creating bob key package: %v", err)
	}
	_, welcome, err := alice.InviteMember(ctx, groupID, bobKP)
	if err != nil {
		t.Fatalf("inviting bob: %v", err)
	}
	if _, err := bob.JoinGroup(ctx, welcome); err != nil {
		t.Fatalf("bob joining group: %v", err)
	}
	return alice, bob, groupID
}

// newInlineAddCommit makes committer add member and returns the commit, which carries the Add
// by value. The committer runs no review hooks, so the commit reaches the receiver unchanged.
func newInlineAddCommit(t *testing.T, committer *Client, groupID []byte, member *Client) []byte {
	t.Helper()
	ctx := t.Context()
	kp, err := member.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("creating member key package: %v", err)
	}
	commit, _, err := committer.InviteMember(ctx, groupID, kp)
	if err != nil {
		t.Fatalf("committer inviting member: %v", err)
	}
	return commit
}

// commitPolicyTestState returns the epoch and the member identities that c reports for groupID.
func commitPolicyTestState(t *testing.T, c *Client, groupID []byte) (epoch uint64, identities []string) {
	t.Helper()
	ctx := t.Context()
	epoch, err := c.Epoch(ctx, groupID)
	if err != nil {
		t.Fatalf("reading epoch: %v", err)
	}
	members, err := c.ListMembers(ctx, groupID)
	if err != nil {
		t.Fatalf("listing members: %v", err)
	}
	identities = make([]string, 0, len(members))
	for _, m := range members {
		identities = append(identities, string(m.Identity))
	}
	// ListMembers follows the group's member map, so the order is not stable.
	slices.Sort(identities)
	return epoch, identities
}

// TestClientCommitProposalReview checks that ProcessCommit reviews inline Add proposals.
// Rejections must preserve the receiver's epoch and membership. Admission decisions
// belong to the application.
func TestClientCommitProposalReview(t *testing.T) {
	ctx := t.Context()

	t.Run("reject/policy_blocks_inline_add", func(t *testing.T) {
		alice, bob, groupID := newCommitPolicyTestPair(t, WithProposalPolicy(identityBlockingPolicy{blocked: "mallory"}))
		commit := newInlineAddCommit(t, bob, groupID, newCommitPolicyTestClient(t, "mallory"))
		epochBefore, membersBefore := commitPolicyTestState(t, alice, groupID)

		err := alice.ProcessCommit(ctx, groupID, commit)
		if err == nil || !strings.Contains(err.Error(), "blocked by policy") {
			t.Fatalf("ProcessCommit(inline add of mallory): err = %v, want policy rejection", err)
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

		err := alice.ProcessCommit(ctx, groupID, commit)
		if err == nil || !strings.Contains(err.Error(), `identity "mallory" rejected`) {
			t.Fatalf("ProcessCommit(inline add of mallory): err = %v, want credential rejection", err)
		}
		epochAfter, membersAfter := commitPolicyTestState(t, alice, groupID)
		if epochAfter != epochBefore || !slices.Equal(membersAfter, membersBefore) {
			t.Fatalf("rejected commit changed state: epoch %d -> %d, members %v -> %v",
				epochBefore, epochAfter, membersBefore, membersAfter)
		}
	})

	t.Run("control/policy_allows_other_identity", func(t *testing.T) {
		alice, bob, groupID := newCommitPolicyTestPair(t, WithProposalPolicy(identityBlockingPolicy{blocked: "mallory"}))
		commit := newInlineAddCommit(t, bob, groupID, newCommitPolicyTestClient(t, "carol"))
		epochBefore, _ := commitPolicyTestState(t, alice, groupID)

		if err := alice.ProcessCommit(ctx, groupID, commit); err != nil {
			t.Fatalf("ProcessCommit(inline add of carol): %v", err)
		}
		epochAfter, members := commitPolicyTestState(t, alice, groupID)
		if epochAfter != epochBefore+1 || !slices.Contains(members, "carol") {
			t.Fatalf("accepted commit: epoch %d -> %d, members %v; want epoch %d and carol present",
				epochBefore, epochAfter, members, epochBefore+1)
		}
	})

	t.Run("control/validator_allows_other_identity", func(t *testing.T) {
		alice, bob, groupID := newCommitPolicyTestPair(t, WithCredentialValidator(rejectingValidator{rejectIdentity: "mallory"}))
		commit := newInlineAddCommit(t, bob, groupID, newCommitPolicyTestClient(t, "carol"))

		if err := alice.ProcessCommit(ctx, groupID, commit); err != nil {
			t.Fatalf("ProcessCommit(inline add of carol) with validator: %v", err)
		}
	})

	// Without a ProposalPolicy or a WithCredentialValidator option the commit is processed as before.
	t.Run("control/no_hooks_keeps_previous_behavior", func(t *testing.T) {
		alice, bob, groupID := newCommitPolicyTestPair(t)
		commit := newInlineAddCommit(t, bob, groupID, newCommitPolicyTestClient(t, "mallory"))

		if err := alice.ProcessCommit(ctx, groupID, commit); err != nil {
			t.Fatalf("ProcessCommit(inline add of mallory) without hooks: %v", err)
		}
	})
}
