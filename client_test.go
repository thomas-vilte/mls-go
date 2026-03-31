package mls

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

func TestClientBasicFlow(t *testing.T) {
	t.Parallel()
	cs := ciphersuite.MLS128DHKEMP256
	alice, err := NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("creating alice client: %v", err)
	}
	bob, err := NewClient([]byte("bob"), cs)
	if err != nil {
		t.Fatalf("creating bob client: %v", err)
	}
	ctx := context.Background()
	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("creating bob key package: %v", err)
	}
	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}
	_, welcome, err := alice.InviteMember(ctx, groupID, bobKP)
	if err != nil {
		t.Fatalf("inviting bob: %v", err)
	}
	bobGroupID, err := bob.JoinGroup(ctx, welcome)
	if err != nil {
		t.Fatalf("bob joining group: %v", err)
	}
	if !bytes.Equal(groupID, bobGroupID) {
		t.Fatalf("group IDs differ: alice=%x bob=%x", groupID, bobGroupID)
	}
	aliceMsg, err := alice.SendMessage(ctx, groupID, []byte("hello bob"))
	if err != nil {
		t.Fatalf("alice sending message: %v", err)
	}
	gotByBob, err := bob.ReceiveMessage(ctx, bobGroupID, aliceMsg)
	if err != nil {
		t.Fatalf("bob receiving message: %v", err)
	}
	if string(gotByBob) != "hello bob" {
		t.Fatalf("unexpected plaintext for bob: %q", gotByBob)
	}
	bobMsg, err := bob.SendMessage(ctx, bobGroupID, []byte("hello alice"))
	if err != nil {
		t.Fatalf("bob sending message: %v", err)
	}
	gotByAlice, err := alice.ReceiveMessage(ctx, groupID, bobMsg)
	if err != nil {
		t.Fatalf("alice receiving message: %v", err)
	}
	if string(gotByAlice) != "hello alice" {
		t.Fatalf("unexpected plaintext for alice: %q", gotByAlice)
	}
}
func TestClientProcessCommitForExistingMember(t *testing.T) {
	t.Parallel()
	cs := ciphersuite.MLS128DHKEMP256
	alice, err := NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("creating alice client: %v", err)
	}
	bob, err := NewClient([]byte("bob"), cs)
	if err != nil {
		t.Fatalf("creating bob client: %v", err)
	}
	charlie, err := NewClient([]byte("charlie"), cs)
	if err != nil {
		t.Fatalf("creating charlie client: %v", err)
	}
	ctx := context.Background()
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
	charlieKP, err := charlie.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("creating charlie key package: %v", err)
	}
	commit, charlieWelcome, err := alice.InviteMember(ctx, groupID, charlieKP)
	if err != nil {
		t.Fatalf("inviting charlie: %v", err)
	}
	if err := bob.ProcessCommit(ctx, bobGroupID, commit); err != nil {
		t.Fatalf("bob processing commit: %v", err)
	}
	charlieGroupID, err := charlie.JoinGroup(ctx, charlieWelcome)
	if err != nil {
		t.Fatalf("charlie joining group: %v", err)
	}
	if !bytes.Equal(groupID, bobGroupID) {
		t.Fatalf("alice and bob group IDs differ: alice=%x bob=%x", groupID, bobGroupID)
	}
	if !bytes.Equal(groupID, charlieGroupID) {
		t.Fatalf("alice and charlie group IDs differ: alice=%x charlie=%x", groupID, charlieGroupID)
	}
	msg, err := alice.SendMessage(ctx, groupID, []byte("welcome charlie"))
	if err != nil {
		t.Fatalf("alice sending message: %v", err)
	}
	gotByBob, err := bob.ReceiveMessage(ctx, bobGroupID, msg)
	if err != nil {
		t.Fatalf("bob receiving post-commit message: %v", err)
	}
	if string(gotByBob) != "welcome charlie" {
		t.Fatalf("unexpected plaintext for bob: %q", gotByBob)
	}
	gotByCharlie, err := charlie.ReceiveMessage(ctx, charlieGroupID, msg)
	if err != nil {
		t.Fatalf("charlie receiving post-join message: %v", err)
	}
	if string(gotByCharlie) != "welcome charlie" {
		t.Fatalf("unexpected plaintext for charlie: %q", gotByCharlie)
	}
}
func TestClientJoinGroupWithoutPendingKeyPackage(t *testing.T) {
	t.Parallel()
	cs := ciphersuite.MLS128DHKEMP256
	alice, err := NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("creating alice client: %v", err)
	}
	bob, err := NewClient([]byte("bob"), cs)
	if err != nil {
		t.Fatalf("creating bob client: %v", err)
	}
	charlie, err := NewClient([]byte("charlie"), cs)
	if err != nil {
		t.Fatalf("creating charlie client: %v", err)
	}
	ctx := context.Background()
	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("creating bob key package: %v", err)
	}
	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}
	_, welcome, err := alice.InviteMember(ctx, groupID, bobKP)
	if err != nil {
		t.Fatalf("inviting bob: %v", err)
	}
	if _, err := charlie.JoinGroup(ctx, welcome); !errors.Is(err, ErrNoPendingKeyPackage) {
		t.Fatalf("expected ErrNoPendingKeyPackage, got %v", err)
	}
}

func TestClientJoinGroupMatchesEarlierPendingKeyPackage(t *testing.T) {
	t.Parallel()
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

	bobKP1, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("creating first bob key package: %v", err)
	}
	if _, err := bob.FreshKeyPackageBytes(ctx); err != nil {
		t.Fatalf("creating second bob key package: %v", err)
	}

	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}
	_, welcome, err := alice.InviteMember(ctx, groupID, bobKP1)
	if err != nil {
		t.Fatalf("inviting bob with first key package: %v", err)
	}

	joinedGroupID, err := bob.JoinGroup(ctx, welcome)
	if err != nil {
		t.Fatalf("joining with earlier pending key package: %v", err)
	}
	if !bytes.Equal(groupID, joinedGroupID) {
		t.Fatalf("group IDs differ: alice=%x bob=%x", groupID, joinedGroupID)
	}
	if len(bob.pendingKPs) != 1 {
		t.Fatalf("pending key package count = %d, want 1", len(bob.pendingKPs))
	}
}
