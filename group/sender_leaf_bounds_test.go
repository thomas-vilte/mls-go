package group

import (
	"testing"

	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/treesync"
)

// newSignedSenderProposal builds a PublicMessage with Alice's signature and
// membership tag, using the supplied sender leaf index.
func newSignedSenderProposal(t *testing.T, aliceGroup *Group, alice *testUser, leaf uint32) *framing.PublicMessage {
	t.Helper()
	remove := &Proposal{Type: ProposalTypeRemove, Remove: &RemoveProposal{Removed: LeafNodeIndex(1)}}
	content := framing.FramedContent{
		GroupID: aliceGroup.groupID.AsSlice(),
		Epoch:   aliceGroup.epoch.AsUint64(),
		Sender:  framing.Sender{Type: framing.SenderTypeMember, LeafIndex: leaf},
		Body:    framing.ProposalBody{Data: ProposalMarshal(remove)},
	}
	pm, err := framing.NewPublicMessage(content, alice.sigPriv, aliceGroup.groupContext.Marshal(),
		aliceGroup.epochSecrets.MembershipKey, aliceGroup.cipherSuite)
	if err != nil {
		t.Fatalf("NewPublicMessage(sender leaf %#x): %v", leaf, err)
	}
	return pm
}

// TestPublicMessageSenderLeafBounds rejects sender indices outside the tree
// while accepting a valid member index.
func TestPublicMessageSenderLeafBounds(t *testing.T) {
	aliceGroup, bobGroup, alice, _ := makeTwoMemberGroups(t)

	if err := bobGroup.VerifyPublicMessage(newSignedSenderProposal(t, aliceGroup, alice, 0)); err != nil {
		t.Fatalf("control: VerifyPublicMessage(sender leaf 0) = %v, want nil", err)
	}
	for _, leaf := range []uint32{2, 0x80000000, 0xFFFFFFFF} {
		if err := bobGroup.VerifyPublicMessage(newSignedSenderProposal(t, aliceGroup, alice, leaf)); err == nil {
			t.Errorf("VerifyPublicMessage(sender leaf %#x) accepted; want an error", leaf)
		}
	}
}

// TestPublicMessageRejectsOutOfBoundsProposal checks that a proposal from an
// out-of-bounds sender is rejected without storing it.
func TestPublicMessageRejectsOutOfBoundsProposal(t *testing.T) {
	aliceGroup, bobGroup, alice, _ := makeTwoMemberGroups(t)

	before := len(bobGroup.StoredProposals())
	if err := bobGroup.ProcessPublicMessage(newSignedSenderProposal(t, aliceGroup, alice, 0x80000000)); err == nil {
		t.Error("ProcessPublicMessage accepted a proposal from sender leaf 0x80000000")
	}
	if after := len(bobGroup.StoredProposals()); after != before {
		t.Errorf("stored proposals %d -> %d after a rejected message; want no change", before, after)
	}
}

// TestReceivedCommitSenderLeafBounds rejects sender indices that wrap onto
// another leaf and preserves the current epoch after rejection.
func TestReceivedCommitSenderLeafBounds(t *testing.T) {
	newCommit := func(t *testing.T) (*Group, *Group, *testUser, *StagedCommit) {
		t.Helper()
		aliceGroup, bobGroup, alice, _ := makeTwoMemberGroups(t)
		if _, err := aliceGroup.SelfUpdate(alice.sigPriv); err != nil {
			t.Fatalf("SelfUpdate(alice): %v", err)
		}
		sc, err := aliceGroup.Commit(alice.sigPriv, alice.sigPub, nil)
		if err != nil {
			t.Fatalf("Commit(alice): %v", err)
		}
		if err := aliceGroup.MergeCommit(sc); err != nil {
			t.Fatalf("MergeCommit(alice): %v", err)
		}
		return aliceGroup, bobGroup, alice, sc
	}

	// Control: sender leaf 0 is alice, so the commit is applied.
	_, bobControl, _, scControl := newCommit(t)
	epochBefore := bobControl.epoch.AsUint64()
	if err := bobControl.ProcessReceivedCommit(scControl.authenticatedContent, treesync.LeafIndex(0), bobControl.myLeafEncryptionKey); err != nil {
		t.Fatalf("control: ProcessReceivedCommit(sender leaf 0) = %v, want nil", err)
	}
	if got := bobControl.epoch.AsUint64(); got != epochBefore+1 {
		t.Fatalf("control: epoch %d -> %d, want %d", epochBefore, got, epochBefore+1)
	}

	// The same commit with an index that aliases leaf 0 must be rejected and leave bob unchanged.
	_, bobWrap, _, scWrap := newCommit(t)
	epochBefore = bobWrap.epoch.AsUint64()
	if err := bobWrap.ProcessReceivedCommit(scWrap.authenticatedContent, treesync.LeafIndex(0x80000000), bobWrap.myLeafEncryptionKey); err == nil {
		t.Fatal("ProcessReceivedCommit accepted a commit with sender leaf 0x80000000")
	}
	if got := bobWrap.epoch.AsUint64(); got != epochBefore {
		t.Fatalf("epoch changed %d -> %d after a rejected commit", epochBefore, got)
	}
}
