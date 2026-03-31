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
	if string(gotByBob.Plaintext) != "hello bob" {
		t.Fatalf("unexpected plaintext for bob: %q", gotByBob.Plaintext)
	}
	if string(gotByBob.SenderIdentity) != "alice" {
		t.Fatalf("unexpected sender identity for bob: %q", gotByBob.SenderIdentity)
	}
	bobMsg, err := bob.SendMessage(ctx, bobGroupID, []byte("hello alice"))
	if err != nil {
		t.Fatalf("bob sending message: %v", err)
	}
	gotByAlice, err := alice.ReceiveMessage(ctx, groupID, bobMsg)
	if err != nil {
		t.Fatalf("alice receiving message: %v", err)
	}
	if string(gotByAlice.Plaintext) != "hello alice" {
		t.Fatalf("unexpected plaintext for alice: %q", gotByAlice.Plaintext)
	}
	if string(gotByAlice.SenderIdentity) != "bob" {
		t.Fatalf("unexpected sender identity for alice: %q", gotByAlice.SenderIdentity)
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
	if string(gotByBob.Plaintext) != "welcome charlie" {
		t.Fatalf("unexpected plaintext for bob: %q", gotByBob.Plaintext)
	}
	gotByCharlie, err := charlie.ReceiveMessage(ctx, charlieGroupID, msg)
	if err != nil {
		t.Fatalf("charlie receiving post-join message: %v", err)
	}
	if string(gotByCharlie.Plaintext) != "welcome charlie" {
		t.Fatalf("unexpected plaintext for charlie: %q", gotByCharlie.Plaintext)
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

func TestClientSendMessageWithAADAndReceiveMetadata(t *testing.T) {
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

	aad := []byte("visible-metadata")
	msg, err := alice.SendMessageWithAAD(ctx, groupID, []byte("hello with aad"), aad)
	if err != nil {
		t.Fatalf("alice sending message with aad: %v", err)
	}
	received, err := bob.ReceiveMessage(ctx, bobGroupID, msg)
	if err != nil {
		t.Fatalf("bob receiving message with aad: %v", err)
	}
	if string(received.Plaintext) != "hello with aad" {
		t.Fatalf("unexpected plaintext: %q", received.Plaintext)
	}
	if !bytes.Equal(received.AuthenticatedData, aad) {
		t.Fatalf("unexpected authenticated data: %x", received.AuthenticatedData)
	}
	if string(received.SenderIdentity) != "alice" {
		t.Fatalf("unexpected sender identity: %q", received.SenderIdentity)
	}
}

func TestClientListMembersAndGroupSecrets(t *testing.T) {
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
	if _, err := bob.JoinGroup(ctx, welcome); err != nil {
		t.Fatalf("bob joining group: %v", err)
	}

	members, err := alice.ListMembers(ctx, groupID)
	if err != nil {
		t.Fatalf("listing members: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("member count = %d, want 2", len(members))
	}
	var sawAlice, sawBob bool
	for _, member := range members {
		switch string(member.Identity) {
		case "alice":
			sawAlice = true
		case "bob":
			sawBob = true
		}
		if len(member.SigningKey) == 0 {
			t.Fatalf("member %q has empty signing key", member.Identity)
		}
	}
	if !sawAlice || !sawBob {
		t.Fatalf("members missing alice or bob: %+v", members)
	}

	exported, err := alice.Export(ctx, groupID, "test", []byte("ctx"), 32)
	if err != nil {
		t.Fatalf("exporting secret: %v", err)
	}
	if len(exported) != 32 {
		t.Fatalf("export length = %d, want 32", len(exported))
	}
	epochAuth, err := alice.EpochAuthenticator(ctx, groupID)
	if err != nil {
		t.Fatalf("epoch authenticator: %v", err)
	}
	if len(epochAuth) == 0 {
		t.Fatal("epoch authenticator is empty")
	}
	groupInfo, err := alice.GroupInfo(ctx, groupID)
	if err != nil {
		t.Fatalf("group info: %v", err)
	}
	if len(groupInfo) == 0 {
		t.Fatal("group info is empty")
	}
}

func TestClientSelfUpdate(t *testing.T) {
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

	selfUpdateCommit, err := bob.SelfUpdate(ctx, bobGroupID)
	if err != nil {
		t.Fatalf("bob self update: %v", err)
	}
	if err := alice.ProcessCommit(ctx, groupID, selfUpdateCommit); err != nil {
		t.Fatalf("alice processing bob self update: %v", err)
	}
	msg, err := alice.SendMessage(ctx, groupID, []byte("post-update"))
	if err != nil {
		t.Fatalf("alice sending post-update message: %v", err)
	}
	received, err := bob.ReceiveMessage(ctx, bobGroupID, msg)
	if err != nil {
		t.Fatalf("bob receiving post-update message: %v", err)
	}
	if string(received.Plaintext) != "post-update" {
		t.Fatalf("unexpected plaintext after self update: %q", received.Plaintext)
	}
}

func TestClientRemoveMember(t *testing.T) {
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
	charlie, err := NewClient([]byte("charlie"), cs)
	if err != nil {
		t.Fatalf("creating charlie client: %v", err)
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
	charlieKP, err := charlie.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("creating charlie key package: %v", err)
	}
	commit, charlieWelcome, err := alice.InviteMember(ctx, groupID, charlieKP)
	if err != nil {
		t.Fatalf("inviting charlie: %v", err)
	}
	if err := bob.ProcessCommit(ctx, bobGroupID, commit); err != nil {
		t.Fatalf("bob processing charlie commit: %v", err)
	}
	if _, err := charlie.JoinGroup(ctx, charlieWelcome); err != nil {
		t.Fatalf("charlie joining group: %v", err)
	}

	removeCommit, err := alice.RemoveMember(ctx, groupID, []byte("charlie"))
	if err != nil {
		t.Fatalf("alice removing charlie: %v", err)
	}
	if err := bob.ProcessCommit(ctx, bobGroupID, removeCommit); err != nil {
		t.Fatalf("bob processing remove commit: %v", err)
	}
	bobMembers, err := bob.ListMembers(ctx, bobGroupID)
	if err != nil {
		t.Fatalf("bob listing members after removal: %v", err)
	}
	if len(bobMembers) != 2 {
		t.Fatalf("member count after removal = %d, want 2", len(bobMembers))
	}
	for _, member := range bobMembers {
		if string(member.Identity) == "charlie" {
			t.Fatal("charlie should not remain in member list after removal")
		}
	}
}

func TestClientLeaveGroup(t *testing.T) {
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

	leaveCommit, err := bob.LeaveGroup(ctx, bobGroupID)
	if err != nil {
		t.Fatalf("bob leaving group: %v", err)
	}
	if leaveCommit != nil {
		t.Fatalf("leave commit = %x, want nil for local leave", leaveCommit)
	}
	if _, err := bob.SendMessage(ctx, bobGroupID, []byte("still here?")); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("expected ErrGroupNotFound after leave, got %v", err)
	}
}
