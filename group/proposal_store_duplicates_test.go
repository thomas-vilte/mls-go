package group

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
)

// TestStoreProposalIgnoresRepeatedProposalRef checks that the store keeps one entry per ProposalRef:
// two copies built from the same AuthenticatedContent (different pointers) take one entry, and the
// by-ref index keeps pointing at the stored proposal. A different AuthenticatedContent still adds an entry.
func TestStoreProposalIgnoresRepeatedProposalRef(t *testing.T) {
	aliceGroup, _, _, _ := setupTwoMemberGroup(t)
	before := len(aliceGroup.proposals.Proposals)
	stored := &Proposal{Type: ProposalTypeRemove, Remove: &RemoveProposal{Removed: 2}}
	copied := &Proposal{Type: ProposalTypeRemove, Remove: &RemoveProposal{Removed: 2}}
	acBytes := []byte("authenticated content of a Remove")

	ref := aliceGroup.StoreProposal(stored, 1, acBytes)
	aliceGroup.StoreProposal(copied, 1, acBytes)
	if got := len(aliceGroup.proposals.Proposals); got != before+1 {
		t.Fatalf("proposals stored = %d, want %d: the same ProposalRef was stored more than once", got, before+1)
	}
	if aliceGroup.proposalByRef[string(ref)] != stored {
		t.Fatal("proposalByRef does not point at the stored proposal")
	}

	aliceGroup.StoreProposal(copied, 1, []byte("a different authenticated content"))
	if got := len(aliceGroup.proposals.Proposals); got != before+2 {
		t.Fatalf("control: proposals stored = %d, want %d: different proposals must accumulate", got, before+2)
	}
}

// TestUnmarshalGroupStateKeepsOneEntryPerProposalRef checks that a state saved with the same ProposalRef
// repeated (before repeated copies were ignored) is restored with a single entry.
func TestUnmarshalGroupStateKeepsOneEntryPerProposalRef(t *testing.T) {
	aliceGroup, _, _, _ := setupTwoMemberGroup(t)
	ref := []byte("repeated ProposalRef")
	remove := &Proposal{Type: ProposalTypeRemove, Remove: &RemoveProposal{Removed: 2}}
	aliceGroup.proposals.AddProposalWithRef(remove, 1, ref)
	aliceGroup.proposals.AddProposalWithRef(remove, 1, ref)

	data, err := aliceGroup.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState: %v", err)
	}
	restored, err := UnmarshalGroupState(data)
	if err != nil {
		t.Fatalf("UnmarshalGroupState: %v", err)
	}
	copies := 0
	for _, sp := range restored.proposals.Proposals {
		if bytes.Equal(sp.Ref, ref) {
			copies++
		}
	}
	if copies != 1 {
		t.Fatalf("restored entries with the same ProposalRef = %d, want 1", copies)
	}
	if _, ok := restored.proposalByRef[string(ref)]; !ok {
		t.Fatal("proposalByRef does not index the restored proposal")
	}
}

// TestOwnProposalEchoIsRecognizedAfterRestore checks that the ProposalRef of a Remove that alice signs
// is kept as LocalRef. After the state is saved and restored, the echo that the delivery service sends
// back to alice is recognized as the same proposal: it is not stored again and the store does not change.
func TestOwnProposalEchoIsRecognizedAfterRestore(t *testing.T) {
	aliceGroup, _, alicePriv, _ := setupTwoMemberGroup(t)
	proposal, err := aliceGroup.RemoveMember(1)
	if err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	sigKey := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)
	msg, err := aliceGroup.SignProposalAsPublicMessage(proposal, sigKey)
	if err != nil {
		t.Fatalf("SignProposalAsPublicMessage: %v", err)
	}
	before := len(aliceGroup.proposals.Proposals)

	data, err := aliceGroup.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState: %v", err)
	}
	restored, err := UnmarshalGroupState(data)
	if err != nil {
		t.Fatalf("UnmarshalGroupState: %v", err)
	}
	if got := len(restored.proposals.Proposals); got != before {
		t.Fatalf("restored proposals = %d, want %d", got, before)
	}

	m, err := framing.UnmarshalMLSMessage(msg)
	if err != nil {
		t.Fatalf("UnmarshalMLSMessage: %v", err)
	}
	pm, ok := m.AsPublic()
	if !ok {
		t.Fatal("the signed proposal is not a PublicMessage")
	}
	if err := restored.ProcessPublicMessage(pm); err != nil {
		t.Fatalf("echo of the own Remove after a state restore: %v", err)
	}
	if got := len(restored.proposals.Proposals); got != before {
		t.Fatalf("the echo was stored again: proposals = %d, want %d", got, before)
	}
}

// TestUnmarshalGroupStateCollapsesLegacyOwnEcho checks that a state saved without LocalRef (by an earlier
// version) holds the own proposal and, next to it, its echo as a copy with a ProposalRef. Restoring it
// leaves one entry, and the own proposal takes the ProposalRef.
func TestUnmarshalGroupStateCollapsesLegacyOwnEcho(t *testing.T) {
	aliceGroup, _, _, _ := setupTwoMemberGroup(t)
	proposal, err := aliceGroup.RemoveMember(1)
	if err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	echoRef := []byte("ProposalRef of a legacy echo")
	aliceGroup.proposals.AddProposalWithRef(proposal, aliceGroup.ownLeafIndex, echoRef)

	data, err := aliceGroup.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState: %v", err)
	}
	restored, err := UnmarshalGroupState(data)
	if err != nil {
		t.Fatalf("UnmarshalGroupState: %v", err)
	}
	if got := len(restored.proposals.Proposals); got != 1 {
		t.Fatalf("restored proposals = %d, want 1: a legacy echo must not be restored as a copy", got)
	}
	if !bytes.Equal(restored.proposals.Proposals[0].LocalRef, echoRef) {
		t.Fatal("the own proposal did not take the ProposalRef of its legacy echo")
	}
}
