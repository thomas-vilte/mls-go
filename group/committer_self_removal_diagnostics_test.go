//go:build diagnostics

package group

import (
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/treesync"
)

// TestGroupRemoveMemberIsTheLeaveProposal checks how Group.RemoveMember behaves with the member's own leaf.
// Client.LeaveGroup builds the leaver's self-Remove proposal with it, so it must succeed. The proposal stays
// in the store, and a Commit by the same member is then refused with ErrInvalidProposal until the store is
// cleared. LeaveGroup deletes the local state, so the stored proposal does not outlive the leave.
func TestGroupRemoveMemberIsTheLeaveProposal(t *testing.T) {
	alice := newDiagnosticMember(t, "Alice")
	bob := newDiagnosticMember(t, "Bob")
	ag := createDiagnosticGroup(t, alice)
	if _, err := ag.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	commitAndJoin(t, ag, alice, bob)

	if _, err := ag.RemoveMember(ag.ownLeafIndex); err != nil {
		t.Fatalf("RemoveMember(own leaf) refused; Client.LeaveGroup depends on it: %v", err)
	}
	if _, err := ag.Commit(alice.sig, alice.sig.PublicKey(), nil); !errors.Is(err, ErrInvalidProposal) {
		t.Fatalf("Commit with the own Remove stored: err = %v, want ErrInvalidProposal (RFC 9420 §12.2)", err)
	}
	ag.ClearProposals()
	if _, err := ag.Commit(alice.sig, alice.sig.PublicKey(), nil); err != nil {
		t.Fatalf("Commit after ClearProposals: %v", err)
	}
}

// TestStoredRemoveOfCommitterByOtherDoesNotBlockCommit checks that a Remove of alice sent by bob, stored in
// alice's proposal store, does not stop alice from committing. RFC 9420 §12.4 says the committer SHOULD include
// the valid proposals, so alice can commit without that one.
func TestStoredRemoveOfCommitterByOtherDoesNotBlockCommit(t *testing.T) {
	alice := newDiagnosticMember(t, "Alice")
	bob := newDiagnosticMember(t, "Bob")
	charlie := newDiagnosticMember(t, "Charlie")
	ag := createDiagnosticGroup(t, alice)
	for _, u := range []diagnosticMember{bob, charlie} {
		if _, err := ag.AddMember(u.kp); err != nil {
			t.Fatalf("AddMember(%s): %v", u.name, err)
		}
	}
	joined := commitAndJoin(t, ag, alice, bob, charlie)
	bg := joined[0]

	ag.proposals.AddProposal(&Proposal{
		Type:   ProposalTypeRemove,
		Remove: &RemoveProposal{Removed: ag.ownLeafIndex},
	}, bg.ownLeafIndex)

	if _, err := ag.Commit(alice.sig, alice.sig.PublicKey(), nil); err != nil {
		t.Errorf("Alice cannot commit while Bob's Remove(Alice) is stored (RFC 9420 §12.4 SHOULD include valid proposals): %v", err)
	}
}

// TestStoredSelfRemoveIsOmittedByCommitter checks that bob, who holds alice's Remove proposal for bob,
// commits without it. RFC 9420 §12.4 says the committer SHOULD leave out a proposal that makes the list
// invalid, and a Remove of the committer does (§12.2). So bob stays in the group and alice processes his
// Commit.
func TestStoredSelfRemoveIsOmittedByCommitter(t *testing.T) {
	alice := newDiagnosticMember(t, "Alice")
	bob := newDiagnosticMember(t, "Bob")
	ag := createDiagnosticGroup(t, alice)
	if _, err := ag.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	bg := commitAndJoin(t, ag, alice, bob)[0]

	bg.proposals.AddProposal(&Proposal{
		Type:   ProposalTypeRemove,
		Remove: &RemoveProposal{Removed: bg.ownLeafIndex},
	}, ag.ownLeafIndex)

	staged, err := bg.Commit(bob.sig, bob.sig.PublicKey(), nil)
	if err != nil {
		t.Fatalf("Bob cannot commit while Alice's Remove(Bob) is stored (RFC 9420 §12.4): %v", err)
	}
	for _, p := range staged.proposals {
		if p.Type == ProposalTypeRemove {
			t.Fatal("the Commit carries a Remove, but a Remove of the committer must be omitted (RFC 9420 §12.2)")
		}
	}
	if err := bg.MergeCommit(staged); err != nil {
		t.Fatalf("MergeCommit by Bob: %v", err)
	}
	if err := ag.ProcessReceivedCommit(staged.AuthenticatedContent(), treesync.LeafIndex(bg.ownLeafIndex), ag.MyLeafEncryptionKey()); err != nil {
		t.Fatalf("Alice processing Bob's Commit: %v", err)
	}
	assertDiagnosticExportEqual(t, ag, bg)
}
