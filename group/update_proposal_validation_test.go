package group

import (
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/schedule"
	"github.com/thomas-vilte/mls-go/secrettree"
	"github.com/thomas-vilte/mls-go/treesync"
)

// updateProposalTestMembers is a three-member group at epoch 1, with the group instance and the user of each member.
type updateProposalTestMembers struct {
	alice, bob, charlie                *testUser
	aliceGroup, bobGroup, charlieGroup *Group
}

// newUpdateProposalTestMembers builds the group. alice creates it and adds bob and charlie in one commit, and
// both joiners take the same Welcome.
func newUpdateProposalTestMembers(t *testing.T) *updateProposalTestMembers {
	t.Helper()
	m := &updateProposalTestMembers{
		alice:   newTestUser(t, "alice"),
		bob:     newTestUser(t, "bob"),
		charlie: newTestUser(t, "charlie"),
	}

	groupID, err := NewGroupIDRandom()
	if err != nil {
		t.Fatalf("NewGroupIDRandom: %v", err)
	}
	m.aliceGroup, err = NewGroup(groupID, ciphersuite.MLS128DHKEMP256, m.alice.kp, m.alice.priv)
	if err != nil {
		t.Fatalf("NewGroup(alice): %v", err)
	}
	if _, err = m.aliceGroup.AddMember(m.bob.kp); err != nil {
		t.Fatalf("AddMember(bob): %v", err)
	}
	if _, err = m.aliceGroup.AddMember(m.charlie.kp); err != nil {
		t.Fatalf("AddMember(charlie): %v", err)
	}
	sc, err := m.aliceGroup.Commit(m.alice.sigPriv, m.alice.sigPub, nil)
	if err != nil {
		t.Fatalf("Commit(add bob, charlie): %v", err)
	}
	joinerSecret := sc.JoinerSecret()
	if err = m.aliceGroup.MergeCommit(sc); err != nil {
		t.Fatalf("MergeCommit(add bob, charlie): %v", err)
	}
	welcome, err := m.aliceGroup.CreateWelcomeWithOpts(
		[]*keypackages.KeyPackage{m.bob.kp, m.charlie.kp},
		m.alice.sigPriv,
		WithJoinerSecret(joinerSecret),
		WithStagedCommit(sc),
	)
	if err != nil {
		t.Fatalf("CreateWelcome: %v", err)
	}
	m.bobGroup = joinUpdateProposalTestGroup(t, welcome, m.aliceGroup, m.bob)
	m.charlieGroup = joinUpdateProposalTestGroup(t, welcome, m.aliceGroup, m.charlie)
	return m
}

// joinUpdateProposalTestGroup joins user from welcome and aligns the joiner's epoch secrets with alice's, the
// same alignment makeTwoMemberGroups applies, so commits and messages verify across members.
func joinUpdateProposalTestGroup(t *testing.T, welcome *Welcome, aliceGroup *Group, user *testUser) *Group {
	t.Helper()
	joined, err := JoinFromWelcomeWithContext(t.Context(), welcome, user.kp, user.priv, nil)
	if err != nil {
		t.Fatalf("JoinFromWelcome: %v", err)
	}
	joined.epochSecrets = &schedule.EpochSecrets{
		InitSecret:       aliceGroup.epochSecrets.InitSecret.Clone(),
		SenderDataSecret: aliceGroup.epochSecrets.SenderDataSecret.Clone(),
		EncryptionSecret: aliceGroup.epochSecrets.EncryptionSecret.Clone(),
		ExporterSecret:   aliceGroup.epochSecrets.ExporterSecret.Clone(),
		ExternalSecret:   aliceGroup.epochSecrets.ExternalSecret.Clone(),
		ConfirmationKey:  aliceGroup.epochSecrets.ConfirmationKey.Clone(),
		MembershipKey:    aliceGroup.epochSecrets.MembershipKey.Clone(),
		ResumptionSecret: aliceGroup.epochSecrets.ResumptionSecret.Clone(),
	}
	joined.keySchedule = schedule.NewKeySchedule(joined.cipherSuite, joined.epochSecrets.InitSecret)
	joined.secretTree, err = secrettree.NewTree(joined.epochSecrets.EncryptionSecret, joined.ratchetTree.NumLeaves, joined.cipherSuite)
	if err != nil {
		t.Fatalf("secrettree.NewTree(joiner): %v", err)
	}
	return joined
}

// deliverSignedUpdateProposal has bob create a self-update, sign it as a PublicMessage (RFC 9420 §6.2),
// and deliver it to the receivers, so that a commit can reference it by hash.
func deliverSignedUpdateProposal(t *testing.T, bobGroup *Group, bob *testUser, receivers ...*Group) *Proposal {
	t.Helper()
	update, err := bobGroup.SelfUpdate(bob.sigPriv)
	if err != nil {
		t.Fatalf("SelfUpdate(bob): %v", err)
	}
	msg, err := bobGroup.SignProposalAsPublicMessage(update, bob.sigPriv)
	if err != nil {
		t.Fatalf("SignProposalAsPublicMessage(bob update): %v", err)
	}
	mlsMsg, err := framing.UnmarshalMLSMessage(msg)
	if err != nil {
		t.Fatalf("UnmarshalMLSMessage(bob update): %v", err)
	}
	pm, ok := mlsMsg.AsPublic()
	if !ok {
		t.Fatal("bob update is not a PublicMessage")
	}
	for _, r := range receivers {
		if err := r.ProcessPublicMessage(pm); err != nil {
			t.Fatalf("ProcessPublicMessage(bob update): %v", err)
		}
	}
	return update
}

// commitWithInlineUpdateProposal rewrites the commit in ac so that its only proposal is upd carried by
// value, and re-signs it as signer. The UpdatePath is left untouched, so the result differs
// from the by-reference original in the proposal list alone.
func commitWithInlineUpdateProposal(t *testing.T, ac *framing.AuthenticatedContent, upd *Proposal, signer *testUser) *framing.AuthenticatedContent {
	t.Helper()
	body, ok := ac.Content.Body.(framing.CommitBody)
	if !ok {
		t.Fatal("content is not a commit")
	}
	commit, err := UnmarshalCommit(body.Data)
	if err != nil {
		t.Fatalf("UnmarshalCommit: %v", err)
	}
	commit.Proposals = []ProposalOrRef{{Proposal: upd}}
	forged := *ac
	forged.Content.Body = framing.CommitBody{Data: commit.Marshal()}
	sig, err := ciphersuite.SignWithLabel(signer.sigPriv, "FramedContentTBS", forged.MarshalTBS())
	if err != nil {
		t.Fatalf("SignWithLabel(forged commit): %v", err)
	}
	forged.Auth.Signature = sig
	return &forged
}

// TestUpdateProposalValidation checks that inline Update proposals are rejected and referenced updates from other members are accepted.
func TestUpdateProposalValidation(t *testing.T) {
	// Generation: charlie holds bob's Update without a ProposalRef, so Commit would send it by value.
	t.Run("generation/inline_update_rejected", func(t *testing.T) {
		m := newUpdateProposalTestMembers(t)
		update, err := m.bobGroup.SelfUpdate(m.bob.sigPriv)
		if err != nil {
			t.Fatalf("SelfUpdate(bob): %v", err)
		}
		m.charlieGroup.proposals.AddProposal(update, m.bobGroup.ownLeafIndex)
		if _, err := m.charlieGroup.Commit(m.charlie.sigPriv, m.charlie.sigPub, nil); !errors.Is(err, ErrInvalidProposal) {
			t.Fatalf("Commit with inline Update: err = %v, want ErrInvalidProposal", err)
		}
	})

	// Reception: the commit that charlie makes with bob's Update by reference, rewritten with
	// the same Update by value and re-signed by charlie.
	t.Run("reception/inline_update_rejected", func(t *testing.T) {
		m := newUpdateProposalTestMembers(t)
		update := deliverSignedUpdateProposal(t, m.bobGroup, m.bob, m.aliceGroup, m.charlieGroup)
		sc, err := m.charlieGroup.Commit(m.charlie.sigPriv, m.charlie.sigPub, nil)
		if err != nil {
			t.Fatalf("Commit(by reference): %v", err)
		}
		forged := commitWithInlineUpdateProposal(t, sc.authenticatedContent, update, m.charlie)
		err = m.aliceGroup.ProcessReceivedCommit(forged, treesync.LeafIndex(m.charlieGroup.ownLeafIndex), m.aliceGroup.myLeafEncryptionKey)
		if !errors.Is(err, ErrInvalidProposal) {
			t.Fatalf("ProcessReceivedCommit(inline Update): err = %v, want ErrInvalidProposal", err)
		}
		if got := m.aliceGroup.epoch.AsUint64(); got != 1 {
			t.Fatalf("alice epoch = %d after rejected commit, want 1", got)
		}
	})

	// Control: the same Update sent by reference is accepted and advances the epoch.
	t.Run("control/by_reference_update", func(t *testing.T) {
		m := newUpdateProposalTestMembers(t)
		deliverSignedUpdateProposal(t, m.bobGroup, m.bob, m.aliceGroup, m.charlieGroup)
		sc, err := m.charlieGroup.Commit(m.charlie.sigPriv, m.charlie.sigPub, nil)
		if err != nil {
			t.Fatalf("Commit(by reference): %v", err)
		}
		if err := m.aliceGroup.ProcessReceivedCommit(sc.authenticatedContent, treesync.LeafIndex(m.charlieGroup.ownLeafIndex), m.aliceGroup.myLeafEncryptionKey); err != nil {
			t.Fatalf("ProcessReceivedCommit(by reference): %v", err)
		}
		if got := m.aliceGroup.epoch.AsUint64(); got != 2 {
			t.Fatalf("alice epoch = %d after by-reference commit, want 2", got)
		}
	})

	// Control: a commit with no proposals and an UpdatePath, which refreshes the committer's own
	// leaf, is accepted and advances the epoch.
	t.Run("control/path_only_commit", func(t *testing.T) {
		m := newUpdateProposalTestMembers(t)
		sc, err := m.charlieGroup.Commit(m.charlie.sigPriv, m.charlie.sigPub, nil)
		if err != nil {
			t.Fatalf("Commit(path only): %v", err)
		}
		if err := m.aliceGroup.ProcessReceivedCommit(sc.authenticatedContent, treesync.LeafIndex(m.charlieGroup.ownLeafIndex), m.aliceGroup.myLeafEncryptionKey); err != nil {
			t.Fatalf("ProcessReceivedCommit(path only): %v", err)
		}
		if got := m.aliceGroup.epoch.AsUint64(); got != 2 {
			t.Fatalf("alice epoch = %d after path-only commit, want 2", got)
		}
	})
}
