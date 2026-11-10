package mls

import (
	"bytes"
	"context"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
)

// TestSelfUpdateCommitsWithPathAndNoProposals checks that Client.SelfUpdate does not send an Update proposal
// of its own, because the committer may not include its own Update (RFC 9420 §12.2, §12.4). It commits with no
// proposals and an UpdatePath, which rotates the sender's leaf. The other member processes that commit and reaches
// the same epoch, so the group keeps working afterwards.
func TestSelfUpdateCommitsWithPathAndNoProposals(t *testing.T) {
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256
	alice, err := NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("creating alice client: %v", err)
	}
	bob, err := NewClient([]byte("bob"), cs)
	if err != nil {
		t.Fatalf("creating bob client: %v", err)
	}
	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("creating bob key package: %v", err)
	}
	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}
	_, bobWelcome, err := alice.InviteMember(ctx, groupID, bobKP)
	if err != nil {
		t.Fatalf("inviting bob: %v", err)
	}
	bobGroupID, err := bob.JoinGroup(ctx, bobWelcome)
	if err != nil {
		t.Fatalf("bob joining group: %v", err)
	}

	// The default cache strategy reloads the group from storage on every operation, so each state is
	// read again after the operation that changes it.
	before := loadGroupForTest(t, alice, groupID)
	oldLeafKey := append([]byte(nil), before.MyLeafEncryptionKey()...)
	oldEpoch := before.Epoch().AsUint64()

	commit, err := alice.SelfUpdate(ctx, groupID)
	if err != nil {
		t.Fatalf("alice SelfUpdate: %v", err)
	}

	// The commit covers no proposals and carries an UpdatePath (RFC 9420 §12.4.1).
	mlsMsg, err := framing.UnmarshalMLSMessage(commit)
	if err != nil {
		t.Fatalf("UnmarshalMLSMessage(SelfUpdate commit): %v", err)
	}
	pm, ok := mlsMsg.AsPublic()
	if !ok {
		t.Fatal("SelfUpdate commit is not a PublicMessage")
	}
	body, ok := pm.Content.Body.(framing.CommitBody)
	if !ok {
		t.Fatal("SelfUpdate commit has no commit body")
	}
	parsed, err := group.UnmarshalCommit(body.Data)
	if err != nil {
		t.Fatalf("UnmarshalCommit(SelfUpdate commit): %v", err)
	}
	if len(parsed.Proposals) != 0 {
		t.Fatalf("SelfUpdate commit covers %d proposals, want none", len(parsed.Proposals))
	}
	if parsed.Path == nil {
		t.Fatal("SelfUpdate commit has no UpdatePath")
	}

	// The sender's own leaf is rotated and the epoch advances.
	after := loadGroupForTest(t, alice, groupID)
	if bytes.Equal(oldLeafKey, after.MyLeafEncryptionKey()) {
		t.Fatal("alice's leaf key did not change after SelfUpdate")
	}
	if got := after.Epoch().AsUint64(); got != oldEpoch+1 {
		t.Fatalf("alice epoch after SelfUpdate = %d, want %d", got, oldEpoch+1)
	}

	// The other member processes the commit and reaches the same epoch, and messages cross both ways.
	if err := bob.ProcessCommit(ctx, bobGroupID, commit); err != nil {
		t.Fatalf("bob processing alice's SelfUpdate commit: %v", err)
	}
	bobAfter := loadGroupForTest(t, bob, bobGroupID)
	if got := bobAfter.Epoch().AsUint64(); got != oldEpoch+1 {
		t.Fatalf("bob epoch after processing SelfUpdate commit = %d, want %d", got, oldEpoch+1)
	}
	sent, err := alice.SendMessage(ctx, groupID, []byte("after self update"))
	if err != nil {
		t.Fatalf("alice sending post-update message: %v", err)
	}
	received, err := bob.ReceiveMessage(ctx, bobGroupID, sent)
	if err != nil {
		t.Fatalf("bob receiving post-update message: %v", err)
	}
	if string(received.Plaintext) != "after self update" {
		t.Fatalf("unexpected plaintext after SelfUpdate: %q", received.Plaintext)
	}
}
