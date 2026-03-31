package mls

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/group"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

type rejectingValidator struct {
	rejectIdentity string
}

type countingStore struct {
	*memorystore.Store
	loadCalls int
}

func newCountingStore() *countingStore {
	return &countingStore{Store: memorystore.NewStore()}
}

func (s *countingStore) LoadGroupState(ctx context.Context, groupID *group.GroupID) ([]byte, error) {
	s.loadCalls++
	return s.Store.LoadGroupState(ctx, groupID)
}

func (v rejectingValidator) ValidateCredential(_ context.Context, cred *credentials.Credential) error {
	if cred == nil {
		return nil
	}
	if string(cred.Identity) == v.rejectIdentity {
		return fmt.Errorf("identity %q rejected", v.rejectIdentity)
	}
	return nil
}

func awaitEventType(t *testing.T, ch <-chan GroupEvent, want EventType) GroupEvent {
	t.Helper()
	timeout := time.After(2 * time.Second)
	for {
		select {
		case event := <-ch:
			if event.Type == want {
				return event
			}
		case <-timeout:
			t.Fatalf("timed out waiting for event type %d", want)
		}
	}
}

func awaitEventTypes(t *testing.T, ch <-chan GroupEvent, wants ...EventType) map[EventType]GroupEvent {
	t.Helper()
	remaining := make(map[EventType]struct{}, len(wants))
	seen := make(map[EventType]GroupEvent, len(wants))
	for _, want := range wants {
		remaining[want] = struct{}{}
	}
	timeout := time.After(2 * time.Second)
	for len(remaining) > 0 {
		select {
		case event := <-ch:
			if _, ok := remaining[event.Type]; ok {
				seen[event.Type] = event
				delete(remaining, event.Type)
			}
		case <-timeout:
			t.Fatalf("timed out waiting for events: %+v", remaining)
		}
	}
	return seen
}

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

func TestClientClose(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	client, err := NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("creating client: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("closing client: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("closing client twice: %v", err)
	}
	if _, err := client.FreshKeyPackageBytes(ctx); !errors.Is(err, ErrClientClosed) {
		t.Fatalf("expected ErrClientClosed, got %v", err)
	}
	if _, err := client.CreateGroup(ctx); !errors.Is(err, ErrClientClosed) {
		t.Fatalf("expected ErrClientClosed from CreateGroup, got %v", err)
	}
}

func TestClientErrorHelpers(t *testing.T) {
	t.Parallel()
	err := fmt.Errorf("wrapping: %w", &group.ErrEpochMismatch{Got: 2, Want: 1})
	if !IsEpochMismatch(err) {
		t.Fatalf("expected IsEpochMismatch=true, got err=%v", err)
	}
	var epochErr *ErrEpochMismatch
	if !errors.As(err, &epochErr) {
		t.Fatalf("expected errors.As(..., *ErrEpochMismatch), got %v", err)
	}

	err = fmt.Errorf("wrapping: %w", &group.ErrGroupIDMismatch{Got: []byte{1}, Want: []byte{2}})
	if !IsGroupIDMismatch(err) {
		t.Fatalf("expected IsGroupIDMismatch=true, got err=%v", err)
	}

	err = fmt.Errorf("wrapping: %w", &group.ErrInvalidSignature{Context: "commit"})
	if !IsInvalidSignature(err) {
		t.Fatalf("expected IsInvalidSignature=true, got err=%v", err)
	}

	err = fmt.Errorf("wrapping: %w", &group.ErrUnknownMember{LeafIndex: 7})
	if !IsUnknownMember(err) {
		t.Fatalf("expected IsUnknownMember=true, got err=%v", err)
	}

	err = fmt.Errorf("wrapping: %w", &group.ErrDecryptionFailed{Reason: "message"})
	if !IsDecryptionFailed(err) {
		t.Fatalf("expected IsDecryptionFailed=true, got err=%v", err)
	}
}

func TestClientWithStorageOption(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := memorystore.NewStore()
	client, err := NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256, WithStorage(store, store))
	if err != nil {
		t.Fatalf("creating client with custom storage: %v", err)
	}
	groupID, err := client.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}
	state, err := store.LoadGroupState(ctx, group.NewGroupID(groupID))
	if err != nil {
		t.Fatalf("loading group state from injected store: %v", err)
	}
	if len(state) == 0 {
		t.Fatal("expected injected store to persist non-empty group state")
	}
}

func TestClientWithCredentialValidatorRejectsInvite(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	alice, err := NewClient(
		[]byte("alice"),
		ciphersuite.MLS128DHKEMP256,
		WithCredentialValidator(rejectingValidator{rejectIdentity: "bob"}),
	)
	if err != nil {
		t.Fatalf("creating alice client: %v", err)
	}
	bob, err := NewClient([]byte("bob"), ciphersuite.MLS128DHKEMP256)
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
	if _, _, err := alice.InviteMember(ctx, groupID, bobKP); err == nil {
		t.Fatal("expected InviteMember to fail credential validation")
	}
}

func TestClientWithCredentialValidatorRejectsJoin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	alice, err := NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("creating alice client: %v", err)
	}
	bob, err := NewClient(
		[]byte("bob"),
		ciphersuite.MLS128DHKEMP256,
		WithCredentialValidator(rejectingValidator{rejectIdentity: "alice"}),
	)
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
	if _, err := bob.JoinGroup(ctx, welcome); err == nil {
		t.Fatal("expected JoinGroup to fail credential validation")
	}
}

func TestClientWithPaddingSizeOption(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	alice, err := NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256, WithPaddingSize(64))
	if err != nil {
		t.Fatalf("creating alice client: %v", err)
	}
	bob, err := NewClient([]byte("bob"), ciphersuite.MLS128DHKEMP256, WithPaddingSize(64))
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
	aliceGroup, err := alice.loadGroupLocked(ctx, groupID)
	if err != nil {
		t.Fatalf("loading alice group: %v", err)
	}
	bobGroup, err := bob.loadGroupLocked(ctx, bobGroupID)
	if err != nil {
		t.Fatalf("loading bob group: %v", err)
	}
	if aliceGroup.PaddingSize() != 64 {
		t.Fatalf("alice padding size = %d, want 64", aliceGroup.PaddingSize())
	}
	if bobGroup.PaddingSize() != 64 {
		t.Fatalf("bob padding size = %d, want 64", bobGroup.PaddingSize())
	}
}

func TestClientWithCacheNoneLoadsEveryRead(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCountingStore()
	writer, err := NewClient([]byte("writer"), ciphersuite.MLS128DHKEMP256, WithStorage(store, store))
	if err != nil {
		t.Fatalf("creating writer client: %v", err)
	}
	groupID, err := writer.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}
	store.loadCalls = 0
	reader, err := NewClient([]byte("reader"), ciphersuite.MLS128DHKEMP256, WithStorage(store, store), WithCacheStrategy(CacheNone))
	if err != nil {
		t.Fatalf("creating reader client: %v", err)
	}
	if _, err := reader.ListMembers(ctx, groupID); err != nil {
		t.Fatalf("first ListMembers: %v", err)
	}
	if _, err := reader.ListMembers(ctx, groupID); err != nil {
		t.Fatalf("second ListMembers: %v", err)
	}
	if store.loadCalls != 2 {
		t.Fatalf("load calls = %d, want 2 for CacheNone", store.loadCalls)
	}
}

func TestClientWithCacheAlwaysCachesLoadedGroup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCountingStore()
	writer, err := NewClient([]byte("writer"), ciphersuite.MLS128DHKEMP256, WithStorage(store, store))
	if err != nil {
		t.Fatalf("creating writer client: %v", err)
	}
	groupID, err := writer.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}
	store.loadCalls = 0
	reader, err := NewClient([]byte("reader"), ciphersuite.MLS128DHKEMP256, WithStorage(store, store), WithCacheStrategy(CacheAlways))
	if err != nil {
		t.Fatalf("creating reader client: %v", err)
	}
	if _, err := reader.ListMembers(ctx, groupID); err != nil {
		t.Fatalf("first ListMembers: %v", err)
	}
	if _, err := reader.ListMembers(ctx, groupID); err != nil {
		t.Fatalf("second ListMembers: %v", err)
	}
	if store.loadCalls != 1 {
		t.Fatalf("load calls = %d, want 1 for CacheAlways", store.loadCalls)
	}
	if _, ok := reader.cachedGroups[groupCacheKeyBytes(groupID)]; !ok {
		t.Fatal("expected group to be present in cache")
	}
}

func TestClientCommitPendingProposalsWithTwoAdds(t *testing.T) {
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
	dave, err := NewClient([]byte("dave"), cs)
	if err != nil {
		t.Fatalf("creating dave client: %v", err)
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
	daveKP, err := dave.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("creating dave key package: %v", err)
	}
	if _, err := alice.ProposeAddMember(ctx, groupID, charlieKP); err != nil {
		t.Fatalf("proposing charlie add: %v", err)
	}
	if _, err := alice.ProposeAddMember(ctx, groupID, daveKP); err != nil {
		t.Fatalf("proposing dave add: %v", err)
	}

	commit, welcome, err := alice.CommitPendingProposals(ctx, groupID)
	if err != nil {
		t.Fatalf("committing pending proposals: %v", err)
	}
	if len(welcome) == 0 {
		t.Fatal("expected welcome bytes for add proposals")
	}
	if err := bob.ProcessCommit(ctx, bobGroupID, commit); err != nil {
		t.Fatalf("bob processing batched commit: %v", err)
	}
	charlieGroupID, err := charlie.JoinGroup(ctx, welcome)
	if err != nil {
		t.Fatalf("charlie joining from batched welcome: %v", err)
	}
	daveGroupID, err := dave.JoinGroup(ctx, welcome)
	if err != nil {
		t.Fatalf("dave joining from batched welcome: %v", err)
	}
	if !bytes.Equal(groupID, charlieGroupID) || !bytes.Equal(groupID, daveGroupID) {
		t.Fatal("joined group IDs do not match creator group")
	}
	members, err := alice.ListMembers(ctx, groupID)
	if err != nil {
		t.Fatalf("listing members after batched add: %v", err)
	}
	if len(members) != 4 {
		t.Fatalf("member count = %d, want 4", len(members))
	}
}

func TestClientCommitPendingProposalsRemove(t *testing.T) {
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

	proposalBytes, err := alice.ProposeRemoveMember(ctx, groupID, []byte("charlie"))
	if err != nil {
		t.Fatalf("proposing remove member: %v", err)
	}
	if len(proposalBytes) == 0 {
		t.Fatal("expected signed proposal bytes")
	}
	commit, welcome, err := alice.CommitPendingProposals(ctx, groupID)
	if err != nil {
		t.Fatalf("committing remove proposal: %v", err)
	}
	if len(welcome) != 0 {
		t.Fatalf("unexpected welcome bytes for remove-only commit: %x", welcome)
	}
	if err := bob.ProcessCommit(ctx, bobGroupID, commit); err != nil {
		t.Fatalf("bob processing remove commit: %v", err)
	}
	members, err := bob.ListMembers(ctx, bobGroupID)
	if err != nil {
		t.Fatalf("listing members after remove commit: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("member count = %d, want 2", len(members))
	}
	for _, member := range members {
		if string(member.Identity) == "charlie" {
			t.Fatal("charlie should not remain after remove commit")
		}
	}
}

func TestClientExternalJoin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256
	alice, err := NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("creating alice client: %v", err)
	}
	charlie, err := NewClient([]byte("charlie"), cs)
	if err != nil {
		t.Fatalf("creating charlie client: %v", err)
	}
	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}
	groupInfo, err := alice.GroupInfo(ctx, groupID)
	if err != nil {
		t.Fatalf("getting group info: %v", err)
	}
	charlieGroupID, commit, err := charlie.ExternalJoin(ctx, groupInfo)
	if err != nil {
		t.Fatalf("external join: %v", err)
	}
	if !bytes.Equal(groupID, charlieGroupID) {
		t.Fatalf("group IDs differ: alice=%x charlie=%x", groupID, charlieGroupID)
	}
	if err := alice.ProcessCommit(ctx, groupID, commit); err != nil {
		t.Fatalf("alice processing external commit: %v", err)
	}
	msg, err := alice.SendMessage(ctx, groupID, []byte("hello external"))
	if err != nil {
		t.Fatalf("alice sending message: %v", err)
	}
	received, err := charlie.ReceiveMessage(ctx, charlieGroupID, msg)
	if err != nil {
		t.Fatalf("charlie receiving external-join message: %v", err)
	}
	if string(received.Plaintext) != "hello external" {
		t.Fatalf("unexpected plaintext: %q", received.Plaintext)
	}
	if string(received.SenderIdentity) != "alice" {
		t.Fatalf("unexpected sender identity: %q", received.SenderIdentity)
	}
	members, err := alice.ListMembers(ctx, groupID)
	if err != nil {
		t.Fatalf("listing members after external join: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("member count = %d, want 2", len(members))
	}
}

func TestClientEventHandlerInviteAndReceive(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	events := make(chan GroupEvent, 8)
	cs := ciphersuite.MLS128DHKEMP256
	alice, err := NewClient([]byte("alice"), cs, WithEventHandler(func(event GroupEvent) {
		events <- event
	}))
	if err != nil {
		t.Fatalf("creating alice client: %v", err)
	}
	bob, err := NewClient([]byte("bob"), cs, WithEventHandler(func(event GroupEvent) {
		events <- event
	}))
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
	seen := awaitEventTypes(t, events, EventMemberJoined, EventEpochAdvanced)
	joinEvent := seen[EventMemberJoined]
	if string(joinEvent.MemberIdentity) != "bob" {
		t.Fatalf("member joined identity = %q, want bob", joinEvent.MemberIdentity)
	}
	if !bytes.Equal(joinEvent.GroupID, groupID) {
		t.Fatalf("member joined group id mismatch")
	}
	bobGroupID, err := bob.JoinGroup(ctx, welcome)
	if err != nil {
		t.Fatalf("bob joining group: %v", err)
	}
	msg, err := alice.SendMessage(ctx, groupID, []byte("hello events"))
	if err != nil {
		t.Fatalf("alice sending message: %v", err)
	}
	received, err := bob.ReceiveMessage(ctx, bobGroupID, msg)
	if err != nil {
		t.Fatalf("bob receiving message: %v", err)
	}
	if string(received.Plaintext) != "hello events" {
		t.Fatalf("unexpected plaintext: %q", received.Plaintext)
	}
	messageEvent := awaitEventType(t, events, EventMessageReceived)
	if string(messageEvent.MemberIdentity) != "alice" {
		t.Fatalf("message event identity = %q, want alice", messageEvent.MemberIdentity)
	}
	if !bytes.Equal(messageEvent.GroupID, bobGroupID) {
		t.Fatalf("message event group id mismatch")
	}
}

func TestClientEventHandlerSelfUpdateAndRemove(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	events := make(chan GroupEvent, 16)
	cs := ciphersuite.MLS128DHKEMP256
	alice, err := NewClient([]byte("alice"), cs, WithEventHandler(func(event GroupEvent) {
		events <- event
	}))
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
	_, err = bob.JoinGroup(ctx, bobWelcome)
	if err != nil {
		t.Fatalf("bob joining group: %v", err)
	}
	_ = awaitEventTypes(t, events, EventMemberJoined, EventEpochAdvanced)

	if _, err := alice.SelfUpdate(ctx, groupID); err != nil {
		t.Fatalf("alice self update: %v", err)
	}
	seen := awaitEventTypes(t, events, EventSelfUpdated, EventEpochAdvanced)
	selfUpdateEvent := seen[EventSelfUpdated]
	if string(selfUpdateEvent.MemberIdentity) != "alice" {
		t.Fatalf("self update identity = %q, want alice", selfUpdateEvent.MemberIdentity)
	}

	if _, err := alice.RemoveMember(ctx, groupID, []byte("bob")); err != nil {
		t.Fatalf("alice removing bob: %v", err)
	}
	seen = awaitEventTypes(t, events, EventMemberRemoved, EventEpochAdvanced)
	removeEvent := seen[EventMemberRemoved]
	if string(removeEvent.MemberIdentity) != "bob" {
		t.Fatalf("remove identity = %q, want bob", removeEvent.MemberIdentity)
	}
}
