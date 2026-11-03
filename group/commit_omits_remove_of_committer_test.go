package group

import (
	"testing"

	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/treesync"
)

// receiveCommitFrom has receiver process the Commit ac, which the member at leaf sender created.
func receiveCommitFrom(t *testing.T, receiver *Group, name string, ac *framing.AuthenticatedContent, sender LeafNodeIndex) {
	t.Helper()
	if err := receiver.ProcessReceivedCommit(ac, treesync.LeafIndex(sender), receiver.MyLeafEncryptionKey()); err != nil {
		t.Fatalf("%s processing the Commit of leaf %d: %v", name, sender, err)
	}
}

// TestCommitOmitsRemoveOfCommitterSentByOther checks that a Commit leaves out a Remove of its own committer
// that another member sent. RFC 9420 §12.4 says the committer SHOULD include the valid stored proposals as
// long as the list stays valid, and §12.2 makes a list invalid when it removes the committer. Bob's Remove of
// alice is stored at alice next to a valid Remove of bob sent by charlie. Alice's Commit must leave out Bob's
// Remove and commit Charlie's, and charlie must follow it.
func TestCommitOmitsRemoveOfCommitterSentByOther(t *testing.T) {
	alice := newJoinTestMember(t, "Alice")
	bob := newJoinTestMember(t, "Bob")
	charlie := newJoinTestMember(t, "Charlie")
	ag := createJoinTestGroup(t, alice)
	for _, u := range []joinTestMember{bob, charlie} {
		if _, err := ag.AddMember(u.kp); err != nil {
			t.Fatalf("AddMember(%s): %v", u.name, err)
		}
	}
	joined := joinThroughWelcome(t, ag, alice, bob, charlie)
	bg, cg := joined[0], joined[1]

	ag.proposals.AddProposal(&Proposal{
		Type:   ProposalTypeRemove,
		Remove: &RemoveProposal{Removed: ag.ownLeafIndex},
	}, bg.ownLeafIndex)
	ag.proposals.AddProposal(&Proposal{
		Type:   ProposalTypeRemove,
		Remove: &RemoveProposal{Removed: bg.ownLeafIndex},
	}, cg.ownLeafIndex)

	staged, err := ag.Commit(alice.sig, alice.sig.PublicKey(), nil)
	if err != nil {
		t.Fatalf("Alice cannot commit while Bob's Remove(Alice) is stored (RFC 9420 §12.4): %v", err)
	}
	var removed []LeafNodeIndex
	for _, p := range staged.proposals {
		if p.Type == ProposalTypeRemove {
			removed = append(removed, p.Remove.Removed)
		}
	}
	if len(removed) != 1 || removed[0] != bg.ownLeafIndex {
		t.Fatalf("removals in the Commit = %v, want only leaf %d (Bob): Bob's Remove of the committer must be left out (RFC 9420 §12.2)",
			removed, bg.ownLeafIndex)
	}
	ac := staged.AuthenticatedContent()
	if err := ag.MergeCommit(staged); err != nil {
		t.Fatalf("MergeCommit: %v", err)
	}
	receiveCommitFrom(t, cg, "Charlie", ac, ag.ownLeafIndex)
	assertSameExport(t, ag, cg)
}
