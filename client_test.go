package mls

import (
	"bytes"
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
	bobKP, err := bob.FreshKeyPackageBytes()
	if err != nil {
		t.Fatalf("creating bob key package: %v", err)
	}
	groupID, err := alice.CreateGroup()
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}
	_, welcome, err := alice.InviteMember(groupID, bobKP)
	if err != nil {
		t.Fatalf("inviting bob: %v", err)
	}
	bobGroupID, err := bob.JoinGroup(welcome)
	if err != nil {
		t.Fatalf("bob joining group: %v", err)
	}
	if !bytes.Equal(groupID, bobGroupID) {
		t.Fatalf("group IDs differ: alice=%x bob=%x", groupID, bobGroupID)
	}
	aliceMsg, err := alice.SendMessage(groupID, []byte("hello bob"))
	if err != nil {
		t.Fatalf("alice sending message: %v", err)
	}
	gotByBob, err := bob.ReceiveMessage(bobGroupID, aliceMsg)
	if err != nil {
		t.Fatalf("bob receiving message: %v", err)
	}
	if string(gotByBob) != "hello bob" {
		t.Fatalf("unexpected plaintext for bob: %q", gotByBob)
	}
	bobMsg, err := bob.SendMessage(bobGroupID, []byte("hello alice"))
	if err != nil {
		t.Fatalf("bob sending message: %v", err)
	}
	gotByAlice, err := alice.ReceiveMessage(groupID, bobMsg)
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
	bobKP, err := bob.FreshKeyPackageBytes()
	if err != nil {
		t.Fatalf("creating bob key package: %v", err)
	}
	groupID, err := alice.CreateGroup()
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}
	_, bobWelcome, err := alice.InviteMember(groupID, bobKP)
	if err != nil {
		t.Fatalf("inviting bob: %v", err)
	}
	bobGroupID, err := bob.JoinGroup(bobWelcome)
	if err != nil {
		t.Fatalf("bob joining group: %v", err)
	}
	charlieKP, err := charlie.FreshKeyPackageBytes()
	if err != nil {
		t.Fatalf("creating charlie key package: %v", err)
	}
	commit, charlieWelcome, err := alice.InviteMember(groupID, charlieKP)
	if err != nil {
		t.Fatalf("inviting charlie: %v", err)
	}
	if err := bob.ProcessCommit(bobGroupID, commit); err != nil {
		t.Fatalf("bob processing commit: %v", err)
	}
	charlieGroupID, err := charlie.JoinGroup(charlieWelcome)
	if err != nil {
		t.Fatalf("charlie joining group: %v", err)
	}
	if !bytes.Equal(groupID, bobGroupID) {
		t.Fatalf("alice and bob group IDs differ: alice=%x bob=%x", groupID, bobGroupID)
	}
	if !bytes.Equal(groupID, charlieGroupID) {
		t.Fatalf("alice and charlie group IDs differ: alice=%x charlie=%x", groupID, charlieGroupID)
	}
	msg, err := alice.SendMessage(groupID, []byte("welcome charlie"))
	if err != nil {
		t.Fatalf("alice sending message: %v", err)
	}
	gotByBob, err := bob.ReceiveMessage(bobGroupID, msg)
	if err != nil {
		t.Fatalf("bob receiving post-commit message: %v", err)
	}
	if string(gotByBob) != "welcome charlie" {
		t.Fatalf("unexpected plaintext for bob: %q", gotByBob)
	}
	gotByCharlie, err := charlie.ReceiveMessage(charlieGroupID, msg)
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
	bobKP, err := bob.FreshKeyPackageBytes()
	if err != nil {
		t.Fatalf("creating bob key package: %v", err)
	}
	groupID, err := alice.CreateGroup()
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}
	_, welcome, err := alice.InviteMember(groupID, bobKP)
	if err != nil {
		t.Fatalf("inviting bob: %v", err)
	}
	if _, err := charlie.JoinGroup(welcome); !errors.Is(err, ErrNoPendingKeyPackage) {
		t.Fatalf("expected ErrNoPendingKeyPackage, got %v", err)
	}
}
