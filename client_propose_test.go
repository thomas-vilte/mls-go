package mls

import (
	"context"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/extensions"
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

// TestProposeGroupContextExtensions_ParsesRealExtensions exercises the
// non-empty extensionsBytes path (group.ParseExtensions), unlike the
// nil-extensions case covered by TestProposeGroupContextExtensions_EntersOwnCommit.
func TestProposeGroupContextExtensions_ParsesRealExtensions(t *testing.T) {
	ctx := context.Background()
	alice, _, groupID := setupTwoClientGroup(t)

	ext := extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("app-id")}
	extBytes := ext.Marshal()

	if _, err := alice.ProposeGroupContextExtensions(ctx, groupID, extBytes); err != nil {
		t.Fatalf("ProposeGroupContextExtensions: %v", err)
	}

	types := pendingProposalTypes(t, alice, groupID)
	if len(types) != 1 || types[0] != group.ProposalTypeGroupContextExtensions {
		t.Fatalf("pending store = %v, want exactly [GroupContextExtensions]", types)
	}
}

// TestProposeGroupContextExtensions_InvalidBytes verifies malformed
// extensionsBytes are rejected with a parse error, not silently ignored.
func TestProposeGroupContextExtensions_InvalidBytes(t *testing.T) {
	ctx := context.Background()
	alice, _, groupID := setupTwoClientGroup(t)

	garbage := []byte{0xFF, 0xFF, 0xFF} // claims a type + truncated VL length
	if _, err := alice.ProposeGroupContextExtensions(ctx, groupID, garbage); err == nil {
		t.Fatal("expected error for malformed extensions bytes")
	}
}

// TestClientNewProposeMethods_ClosedClient verifies the P2 branching/proposal
// methods added alongside Client.Branch all respect a closed client, matching
// the convention in TestClientClose for the pre-existing methods.
func TestClientNewProposeMethods_ClosedClient(t *testing.T) {
	ctx := context.Background()
	client, err := NewClient([]byte("closed-propose"), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	groupID := []byte("does-not-matter")
	if _, err := client.ProposeGroupContextExtensions(ctx, groupID, nil); !errors.Is(err, ErrClientClosed) {
		t.Errorf("ProposeGroupContextExtensions: expected ErrClientClosed, got %v", err)
	}
	if _, err := client.ProposeResumptionPSK(ctx, groupID, 0); !errors.Is(err, ErrClientClosed) {
		t.Errorf("ProposeResumptionPSK: expected ErrClientClosed, got %v", err)
	}
	if _, err := client.ProposeReInit(ctx, groupID, groupID); !errors.Is(err, ErrClientClosed) {
		t.Errorf("ProposeReInit: expected ErrClientClosed, got %v", err)
	}
	if _, _, err := client.ResumptionPSK(ctx, groupID); !errors.Is(err, ErrClientClosed) {
		t.Errorf("ResumptionPSK: expected ErrClientClosed, got %v", err)
	}
	if _, _, _, err := client.Branch(ctx, groupID, nil); !errors.Is(err, ErrClientClosed) {
		t.Errorf("Branch: expected ErrClientClosed, got %v", err)
	}
}

// TestClientNewProposeMethods_UnknownGroup verifies each method surfaces
// ErrGroupNotFound (via loadGroupEntry) for a group the client never joined.
func TestClientNewProposeMethods_UnknownGroup(t *testing.T) {
	ctx := context.Background()
	client, err := NewClient([]byte("unknown-group-propose"), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	groupID := []byte("never-joined-this-group")
	if _, err := client.ProposeGroupContextExtensions(ctx, groupID, nil); !errors.Is(err, ErrGroupNotFound) {
		t.Errorf("ProposeGroupContextExtensions: expected ErrGroupNotFound, got %v", err)
	}
	if _, err := client.ProposeResumptionPSK(ctx, groupID, 0); !errors.Is(err, ErrGroupNotFound) {
		t.Errorf("ProposeResumptionPSK: expected ErrGroupNotFound, got %v", err)
	}
	if _, err := client.ProposeReInit(ctx, groupID, groupID); !errors.Is(err, ErrGroupNotFound) {
		t.Errorf("ProposeReInit: expected ErrGroupNotFound, got %v", err)
	}
	if _, _, err := client.ResumptionPSK(ctx, groupID); !errors.Is(err, ErrGroupNotFound) {
		t.Errorf("ResumptionPSK: expected ErrGroupNotFound, got %v", err)
	}
	if _, _, _, err := client.Branch(ctx, groupID, nil); !errors.Is(err, ErrGroupNotFound) {
		t.Errorf("Branch: expected ErrGroupNotFound, got %v", err)
	}
}

// TestClientNewProposeMethods_CanceledContext verifies the same methods
// respect an already-canceled context before touching any locks.
func TestClientNewProposeMethods_CanceledContext(t *testing.T) {
	client, err := NewClient([]byte("canceled-propose"), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	groupID := []byte("does-not-matter")
	if _, err := client.ProposeGroupContextExtensions(ctx, groupID, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("ProposeGroupContextExtensions: expected context.Canceled, got %v", err)
	}
	if _, err := client.ProposeResumptionPSK(ctx, groupID, 0); !errors.Is(err, context.Canceled) {
		t.Errorf("ProposeResumptionPSK: expected context.Canceled, got %v", err)
	}
	if _, err := client.ProposeReInit(ctx, groupID, groupID); !errors.Is(err, context.Canceled) {
		t.Errorf("ProposeReInit: expected context.Canceled, got %v", err)
	}
	if _, _, err := client.ResumptionPSK(ctx, groupID); !errors.Is(err, context.Canceled) {
		t.Errorf("ResumptionPSK: expected context.Canceled, got %v", err)
	}
	if _, _, _, err := client.Branch(ctx, groupID, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("Branch: expected context.Canceled, got %v", err)
	}
}
