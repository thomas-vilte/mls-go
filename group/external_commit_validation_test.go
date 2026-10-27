package group

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/treesync"
)

// externalCommitTestState is what a rejected external commit must leave unchanged on the receiving group.
type externalCommitTestState struct {
	epoch        uint64
	groupContext []byte
	members      int
}

func captureExternalCommitTestState(g *Group) externalCommitTestState {
	return externalCommitTestState{
		epoch:        g.epoch.AsUint64(),
		groupContext: g.groupContext.Marshal(),
		members:      g.MemberCount(),
	}
}

// assertExternalCommitStateUnchanged fails the test if g no longer matches the state captured before a rejected commit.
func assertExternalCommitStateUnchanged(t *testing.T, g *Group, before externalCommitTestState) {
	t.Helper()
	after := captureExternalCommitTestState(g)
	if after.epoch != before.epoch {
		t.Fatalf("epoch = %d after rejected commit, want %d", after.epoch, before.epoch)
	}
	if !bytes.Equal(after.groupContext, before.groupContext) {
		t.Fatal("GroupContext changed after rejected commit")
	}
	if after.members != before.members {
		t.Fatalf("member count = %d after rejected commit, want %d", after.members, before.members)
	}
}

// groupHasBasicIdentity reports whether g holds a present leaf whose credential identifies user.
func groupHasBasicIdentity(g *Group, user *testUser) bool {
	identity := user.kp.LeafNode.Credential.Identity
	for i := range g.ratchetTree.NumLeaves {
		leaf := g.ratchetTree.GetLeaf(treesync.LeafIndex(i))
		if leaf == nil || leaf.State != treesync.NodeStatePresent || leaf.LeafData == nil || leaf.LeafData.Credential == nil {
			continue
		}
		if bytes.Equal(leaf.LeafData.Credential.Identity, identity) {
			return true
		}
	}
	return false
}

// newExternalCommitTestCommit builds an external commit by joiner against alice's current GroupInfo. When
// removePrior is non-nil, the commit also carries a Remove for that leaf index.
func newExternalCommitTestCommit(t *testing.T, aliceGroup *Group, alice, joiner *testUser, removePrior *LeafNodeIndex) *StagedCommit {
	t.Helper()
	groupInfo, err := aliceGroup.GetGroupInfo(alice.sigPriv)
	if err != nil {
		t.Fatalf("GetGroupInfo: %v", err)
	}
	_, staged, err := ExternalCommit(
		groupInfo,
		aliceGroup.cipherSuite,
		joiner.sigPriv,
		joiner.sigPub,
		removePrior,
		joiner.kp.LeafNode.Credential,
	)
	if err != nil {
		t.Fatalf("ExternalCommit(%s): %v", joiner.kp.LeafNode.Credential.Identity, err)
	}
	return staged
}

// externalCommitTestProposals returns the proposal list carried by the commit in ac.
func externalCommitTestProposals(t *testing.T, ac *framing.AuthenticatedContent) []ProposalOrRef {
	t.Helper()
	body, ok := ac.Content.Body.(framing.CommitBody)
	if !ok {
		t.Fatal("content is not a commit")
	}
	commit, err := UnmarshalCommit(body.Data)
	if err != nil {
		t.Fatalf("UnmarshalCommit: %v", err)
	}
	return commit.Proposals
}

// externalCommitWithProposals replaces the proposal list of the commit in ac and re-signs it as joiner. The
// UpdatePath is kept so receiver tests can exercise proposal validation before path processing.
func externalCommitWithProposals(t *testing.T, ac *framing.AuthenticatedContent, proposals []ProposalOrRef, joiner *testUser) *framing.AuthenticatedContent {
	t.Helper()
	body, ok := ac.Content.Body.(framing.CommitBody)
	if !ok {
		t.Fatal("content is not a commit")
	}
	commit, err := UnmarshalCommit(body.Data)
	if err != nil {
		t.Fatalf("UnmarshalCommit: %v", err)
	}
	commit.Proposals = proposals
	forged := *ac
	forged.Content.Body = framing.CommitBody{Data: commit.Marshal()}
	sig, err := ciphersuite.SignWithLabel(joiner.sigPriv, "FramedContentTBS", forged.MarshalTBS())
	if err != nil {
		t.Fatalf("SignWithLabel(forged external commit): %v", err)
	}
	forged.Auth.Signature = sig
	return &forged
}

// TestExternalCommitValidation checks external proposal rules, rejected-state preservation, and valid joins and resynchronization.
func TestExternalCommitValidation(t *testing.T) {
	// Attack: mallory removes bob with an external commit. alice must reject it and stay at epoch 1.
	t.Run("attack/remove_other_member_rejected", func(t *testing.T) {
		aliceGroup, bobGroup, alice, bob := makeTwoMemberGroups(t)
		mallory := newTestUser(t, "mallory")
		bobLeaf := bobGroup.ownLeafIndex
		before := captureExternalCommitTestState(aliceGroup)

		staged := newExternalCommitTestCommit(t, aliceGroup, alice, mallory, &bobLeaf)
		err := aliceGroup.ProcessReceivedCommit(staged.authenticatedContent, treesync.LeafIndex(0), aliceGroup.myLeafEncryptionKey)
		if !errors.Is(err, ErrInvalidProposal) {
			t.Fatalf("ProcessReceivedCommit(external commit removing bob): err = %v, want ErrInvalidProposal", err)
		}
		assertExternalCommitStateUnchanged(t, aliceGroup, before)
		if !groupHasBasicIdentity(aliceGroup, bob) {
			t.Fatal("bob's leaf was removed by a rejected external commit")
		}

		// alice still accepts bob's commit at the same epoch, so the rejection left no partial state.
		sc, err := bobGroup.Commit(bob.sigPriv, bob.sigPub, nil)
		if err != nil {
			t.Fatalf("Commit(bob) after rejected commit: %v", err)
		}
		if err := bobGroup.MergeCommit(sc); err != nil {
			t.Fatalf("MergeCommit(bob) after rejected commit: %v", err)
		}
		if err := aliceGroup.ProcessReceivedCommit(sc.authenticatedContent, treesync.LeafIndex(bobLeaf), aliceGroup.myLeafEncryptionKey); err != nil {
			t.Fatalf("ProcessReceivedCommit(bob) after rejected commit: %v", err)
		}
		if got := aliceGroup.epoch.AsUint64(); got != 2 {
			t.Fatalf("alice epoch = %d after bob's commit, want 2", got)
		}
	})

	// Control: an external commit without a Remove is accepted and advances the epoch.
	t.Run("control/external_commit_without_remove_accepted", func(t *testing.T) {
		aliceGroup, _, alice, _ := makeTwoMemberGroups(t)
		mallory := newTestUser(t, "mallory")

		staged := newExternalCommitTestCommit(t, aliceGroup, alice, mallory, nil)
		if err := aliceGroup.ProcessReceivedCommit(staged.authenticatedContent, treesync.LeafIndex(0), aliceGroup.myLeafEncryptionKey); err != nil {
			t.Fatalf("ProcessReceivedCommit(external commit without Remove): %v", err)
		}
		if got := aliceGroup.epoch.AsUint64(); got != 2 {
			t.Fatalf("alice epoch = %d after external join, want 2", got)
		}
		if !groupHasBasicIdentity(aliceGroup, mallory) {
			t.Fatal("joiner is missing from alice's tree after external join")
		}
	})

	// Control: bob resynchronizes by removing his own prior leaf. The identity matches, so the
	// commit is accepted and bob keeps his place in the group.
	t.Run("control/resync_of_own_prior_leaf_accepted", func(t *testing.T) {
		aliceGroup, bobGroup, alice, bob := makeTwoMemberGroups(t)
		bobLeaf := bobGroup.ownLeafIndex

		staged := newExternalCommitTestCommit(t, aliceGroup, alice, bob, &bobLeaf)
		if err := aliceGroup.ProcessReceivedCommit(staged.authenticatedContent, treesync.LeafIndex(0), aliceGroup.myLeafEncryptionKey); err != nil {
			t.Fatalf("ProcessReceivedCommit(bob resync): %v", err)
		}
		if got := aliceGroup.epoch.AsUint64(); got != 2 {
			t.Fatalf("alice epoch = %d after resync, want 2", got)
		}
		if !groupHasBasicIdentity(aliceGroup, bob) {
			t.Fatal("bob is missing from alice's tree after resync")
		}
	})

	// Reject: an Add in an external commit. RFC 9420 §12.2 allows no other proposal type.
	t.Run("reject/add_rejected", func(t *testing.T) {
		aliceGroup, _, alice, _ := makeTwoMemberGroups(t)
		mallory := newTestUser(t, "mallory")
		dave := newTestUser(t, "dave")
		before := captureExternalCommitTestState(aliceGroup)

		staged := newExternalCommitTestCommit(t, aliceGroup, alice, mallory, nil)
		proposals := append(externalCommitTestProposals(t, staged.authenticatedContent),
			ProposalOrRef{Proposal: &Proposal{Type: ProposalTypeAdd, Add: &AddProposal{KeyPackage: dave.kp}}})
		forged := externalCommitWithProposals(t, staged.authenticatedContent, proposals, mallory)

		// The error must come from the external Commit list check. Without it, the added leaf
		// only fails later, as a path length mismatch, which is not the rule under test.
		err := aliceGroup.ProcessReceivedCommit(forged, treesync.LeafIndex(0), aliceGroup.myLeafEncryptionKey)
		if !errors.Is(err, ErrInvalidProposal) || !strings.Contains(err.Error(), "external commit contains invalid proposals") {
			t.Fatalf("ProcessReceivedCommit(external commit with Add): err = %v, want the external commit proposal check (ErrInvalidProposal)", err)
		}
		assertExternalCommitStateUnchanged(t, aliceGroup, before)
	})

	// Reject: a proposal by reference in an external commit (RFC 9420 §12.4.3.2).
	t.Run("reject/by_reference_rejected", func(t *testing.T) {
		aliceGroup, _, alice, _ := makeTwoMemberGroups(t)
		mallory := newTestUser(t, "mallory")
		before := captureExternalCommitTestState(aliceGroup)

		staged := newExternalCommitTestCommit(t, aliceGroup, alice, mallory, nil)
		externalInit := externalCommitTestProposals(t, staged.authenticatedContent)[0]
		ref := ProposalOrRef{ProposalRef: bytes.Repeat([]byte{0xA5}, 32)}
		forged := externalCommitWithProposals(t, staged.authenticatedContent, []ProposalOrRef{ref, externalInit}, mallory)

		err := aliceGroup.ProcessReceivedCommit(forged, treesync.LeafIndex(0), aliceGroup.myLeafEncryptionKey)
		if !errors.Is(err, ErrInvalidProposal) {
			t.Fatalf("ProcessReceivedCommit(external commit with proposal by reference): err = %v, want ErrInvalidProposal", err)
		}
		assertExternalCommitStateUnchanged(t, aliceGroup, before)
	})

	// Reject: an Update carried by value in an external commit (RFC 9420 §12.2).
	t.Run("reject/inline_update_rejected", func(t *testing.T) {
		aliceGroup, bobGroup, alice, bob := makeTwoMemberGroups(t)
		mallory := newTestUser(t, "mallory")
		update, err := bobGroup.SelfUpdate(bob.sigPriv)
		if err != nil {
			t.Fatalf("SelfUpdate(bob): %v", err)
		}
		before := captureExternalCommitTestState(aliceGroup)

		staged := newExternalCommitTestCommit(t, aliceGroup, alice, mallory, nil)
		proposals := append(externalCommitTestProposals(t, staged.authenticatedContent), ProposalOrRef{Proposal: update})
		forged := externalCommitWithProposals(t, staged.authenticatedContent, proposals, mallory)

		err = aliceGroup.ProcessReceivedCommit(forged, treesync.LeafIndex(0), aliceGroup.myLeafEncryptionKey)
		if !errors.Is(err, ErrInvalidProposal) {
			t.Fatalf("ProcessReceivedCommit(external commit with inline Update): err = %v, want ErrInvalidProposal", err)
		}
		assertExternalCommitStateUnchanged(t, aliceGroup, before)
	})
}
