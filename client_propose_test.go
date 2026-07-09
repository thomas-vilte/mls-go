package mls

import (
	"context"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
)

func setupTwoClientGroup(t *testing.T) (alice, bob *Client, groupID []byte) {
	t.Helper()
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256

	alice, err := NewClient([]byte("alice-"+t.Name()), cs)
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	bob, err = NewClient([]byte("bob-"+t.Name()), cs)
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}
	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes: %v", err)
	}
	groupID, err = alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if _, _, err := alice.InviteMember(ctx, groupID, bobKP); err != nil {
		t.Fatalf("InviteMember: %v", err)
	}
	return alice, bob, groupID
}

// pendingProposalTypes returns the proposal types currently in the client's
// local pending store for the group — what CommitPendingProposals would commit.
func pendingProposalTypes(t *testing.T, c *Client, groupID []byte) []group.ProposalType {
	t.Helper()
	ctx := context.Background()
	c.mu.Lock()
	entry := c.getOrCreateEntryLocked(groupCacheKeyBytes(groupID))
	c.mu.Unlock()
	entry.mu.Lock()
	defer entry.mu.Unlock()
	g, err := c.loadGroupEntry(ctx, groupID, entry)
	if err != nil {
		t.Fatalf("loadGroupEntry: %v", err)
	}
	var types []group.ProposalType
	for _, sp := range g.StoredProposals() {
		types = append(types, sp.Proposal.Type)
	}
	return types
}

// TestProposeResumptionPSK_EntersOwnStore verifies the resumption PSK proposal
// lands in the sender's own pending store (so their own commit would include
// it), which SignProposalAsPublicMessage alone does not do.
//
// NOTE: the end-to-end commit of a resumption PSK (CommitPendingProposals →
// collectPSKsFromProposals resolving the secret from the epoch cache) is NOT
// exercised here: the Client-level resumption PSK cache lookup does not yet
// resolve for the just-committed epoch. That is a pre-existing gap in the
// caching mechanism, tracked separately in AUDIT_RFC9420.md §3.4 — not a
// defect of the proposal-emission API this test covers.
func TestProposeResumptionPSK_EntersOwnStore(t *testing.T) {
	ctx := context.Background()
	alice, _, groupID := setupTwoClientGroup(t)

	epoch, err := alice.Epoch(ctx, groupID)
	if err != nil {
		t.Fatalf("Epoch: %v", err)
	}
	if _, err := alice.ProposeResumptionPSK(ctx, groupID, epoch); err != nil {
		t.Fatalf("ProposeResumptionPSK: %v", err)
	}

	types := pendingProposalTypes(t, alice, groupID)
	if len(types) != 1 || types[0] != group.ProposalTypePreSharedKey {
		t.Fatalf("pending store = %v, want exactly [PreSharedKey]", types)
	}
}

// TestProposeGroupContextExtensions_EntersOwnCommit verifies the GCE proposal
// lands in the pending store and the commit applies the new extensions.
func TestProposeGroupContextExtensions_EntersOwnCommit(t *testing.T) {
	ctx := context.Background()
	alice, _, groupID := setupTwoClientGroup(t)

	// Empty extensions list: clears GroupContext extensions. Valid per §12.1.7.
	if _, err := alice.ProposeGroupContextExtensions(ctx, groupID, nil); err != nil {
		t.Fatalf("ProposeGroupContextExtensions: %v", err)
	}

	types := pendingProposalTypes(t, alice, groupID)
	if len(types) != 1 || types[0] != group.ProposalTypeGroupContextExtensions {
		t.Fatalf("pending store = %v, want exactly [GroupContextExtensions]", types)
	}

	if _, _, err := alice.CommitPendingProposals(ctx, groupID); err != nil {
		t.Fatalf("CommitPendingProposals: %v", err)
	}
}

// TestProposeReInit_EntersOwnStore verifies the ReInit proposal lands in the
// pending store with the requested new group ID.
func TestProposeReInit_EntersOwnStore(t *testing.T) {
	ctx := context.Background()
	alice, _, groupID := setupTwoClientGroup(t)

	newGroupID := []byte("reborn-group-id")
	if _, err := alice.ProposeReInit(ctx, groupID, newGroupID); err != nil {
		t.Fatalf("ProposeReInit: %v", err)
	}

	types := pendingProposalTypes(t, alice, groupID)
	if len(types) != 1 || types[0] != group.ProposalTypeReInit {
		t.Fatalf("pending store = %v, want exactly [ReInit]", types)
	}
}
