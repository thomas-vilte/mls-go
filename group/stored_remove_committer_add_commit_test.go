package group

import (
	"testing"

	"github.com/thomas-vilte/mls-go/keypackages"
)

// TestStoredRemoveOfCommitterDoesNotBlockAddCommit checks that a stored Remove of the committer does not stop
// it from committing (RFC 9420 §12.2 and §12.4). Bob's Remove of alice is stored at every member, and alice
// then commits an Add of dave. A list that includes that Remove is invalid (§12.2), so alice leaves it out,
// which §12.4 allows, and commits the Add. bob and charlie process the Commit, dave joins from the Welcome,
// and the stored proposals are gone in the new epoch.
func TestStoredRemoveOfCommitterDoesNotBlockAddCommit(t *testing.T) {
	alice := newJoinTestMember(t, "Alice")
	bob := newJoinTestMember(t, "Bob")
	charlie := newJoinTestMember(t, "Charlie")
	dave := newJoinTestMember(t, "Dave")
	ag := createJoinTestGroup(t, alice)
	for _, u := range []joinTestMember{bob, charlie} {
		if _, err := ag.AddMember(u.kp); err != nil {
			t.Fatalf("AddMember(%s): %v", u.name, err)
		}
	}
	joined := joinThroughWelcome(t, ag, alice, bob, charlie)
	bg, cg := joined[0], joined[1]

	// Bob's Remove of alice is stored at alice, and at the members that received it.
	for _, g := range []*Group{ag, bg, cg} {
		g.proposals.AddProposal(&Proposal{
			Type:   ProposalTypeRemove,
			Remove: &RemoveProposal{Removed: ag.ownLeafIndex},
		}, bg.ownLeafIndex)
	}

	if _, err := ag.AddMember(dave.kp); err != nil {
		t.Fatalf("AddMember(Dave): %v", err)
	}
	staged, err := ag.Commit(alice.sig, alice.sig.PublicKey(), nil)
	if err != nil {
		t.Fatalf("Alice cannot commit an Add while Bob's Remove(Alice) is stored (RFC 9420 §12.4): %v", err)
	}
	var adds, removes int
	for _, p := range staged.proposals {
		switch p.Type {
		case ProposalTypeAdd:
			adds++
		case ProposalTypeRemove:
			removes++
		}
	}
	if adds != 1 || removes != 0 {
		t.Fatalf("proposals in the Commit: %d Add, %d Remove; want 1 Add and no Remove (RFC 9420 §12.2)", adds, removes)
	}

	ac := staged.AuthenticatedContent()
	joinerSecret := staged.JoinerSecret()
	if err := ag.MergeCommit(staged); err != nil {
		t.Fatalf("MergeCommit by Alice: %v", err)
	}
	welcome, err := ag.CreateWelcomeWithOpts([]*keypackages.KeyPackage{dave.kp}, alice.sig,
		WithJoinerSecret(joinerSecret), WithStagedCommit(staged))
	if err != nil {
		t.Fatalf("CreateWelcome by Alice: %v", err)
	}
	dg, err := JoinFromWelcome(welcome, dave.kp, dave.priv, nil)
	if err != nil {
		t.Fatalf("JoinFromWelcome(Dave): %v", err)
	}

	receiveCommitFrom(t, bg, "Bob", ac, ag.ownLeafIndex)
	receiveCommitFrom(t, cg, "Charlie", ac, ag.ownLeafIndex)
	assertSameExport(t, ag, bg)
	assertSameExport(t, ag, cg)
	assertSameExport(t, ag, dg)
	for name, g := range map[string]*Group{"Alice": ag, "Bob": bg, "Charlie": cg} {
		if n := len(g.proposals.Proposals); n != 0 {
			t.Errorf("%s keeps %d stored proposals after the epoch changed", name, n)
		}
	}
}
