package mls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/group"
	filestore "github.com/thomas-vilte/mls-go/storage/file"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

func loadGroupForTest(t *testing.T, c *Client, groupIDBytes []byte) *group.Group {
	t.Helper()
	ctx := context.Background()
	c.mu.Lock()
	entry := c.getOrCreateEntryLocked(groupCacheKeyBytes(groupIDBytes))
	c.mu.Unlock()
	entry.mu.Lock()
	defer entry.mu.Unlock()
	g, err := c.loadGroupEntry(ctx, groupIDBytes, entry)
	if err != nil {
		t.Fatalf("loadGroupForTest: %v", err)
	}
	return g
}

type rejectingValidator struct {
	rejectIdentity string
}

type countingStore struct {
	*memorystore.Store
	loadCalls int
}

type closableCountingStore struct {
	*countingStore
	closed bool
}

func newCountingStore() *countingStore {
	return &countingStore{Store: memorystore.NewStore()}
}

func (s *closableCountingStore) Close() error {
	s.closed = true
	return nil
}

func (s *countingStore) LoadGroupState(ctx context.Context, groupID *group.GroupID) ([]byte, error) {
	s.loadCalls++
	return s.Store.LoadGroupState(ctx, groupID)
}

func generateTestCertificate(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mls-go-client-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	return certDER, privKey
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

	if err := bob.LeaveGroup(ctx, bobGroupID); err != nil {
		t.Fatalf("bob leaving group: %v", err)
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

func TestClientCloseClosesInjectedStore(t *testing.T) {
	t.Parallel()
	store := &closableCountingStore{countingStore: newCountingStore()}
	client, err := NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256, WithStorage(store, store))
	if err != nil {
		t.Fatalf("creating client: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("closing client: %v", err)
	}
	if !store.closed {
		t.Fatal("expected injected closable store to be closed")
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

func TestClientGroupNotFoundWithFileStore(t *testing.T) {
	t.Parallel()
	store, err := filestore.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("creating file store: %v", err)
	}
	client, err := NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256, WithStorage(store, store))
	if err != nil {
		t.Fatalf("creating client: %v", err)
	}
	_, err = client.ListMembers(context.Background(), []byte("missing-group"))
	if !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("expected ErrGroupNotFound, got %v", err)
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
	aliceGroup := loadGroupForTest(t, alice, groupID)
	bobGroup := loadGroupForTest(t, bob, bobGroupID)
	if aliceGroup.PaddingSize() != 64 {
		t.Fatalf("alice padding size = %d, want 64", aliceGroup.PaddingSize())
	}
	if bobGroup.PaddingSize() != 64 {
		t.Fatalf("bob padding size = %d, want 64", bobGroup.PaddingSize())
	}
}

func TestClientWithX509Credential(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256
	aliceCert, alicePriv := generateTestCertificate(t)
	bobCert, bobPriv := generateTestCertificate(t)
	alice, err := NewClient([]byte(""), cs, WithX509Credential(aliceCert, alicePriv))
	if err != nil {
		t.Fatalf("creating alice x509 client: %v", err)
	}
	bob, err := NewClient([]byte(""), cs, WithX509Credential(bobCert, bobPriv))
	if err != nil {
		t.Fatalf("creating bob x509 client: %v", err)
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
	if !bytes.Equal(groupID, bobGroupID) {
		t.Fatalf("group IDs differ: alice=%x bob=%x", groupID, bobGroupID)
	}
	msg, err := alice.SendMessage(ctx, groupID, []byte("hello x509"))
	if err != nil {
		t.Fatalf("alice sending message: %v", err)
	}
	received, err := bob.ReceiveMessage(ctx, bobGroupID, msg)
	if err != nil {
		t.Fatalf("bob receiving message: %v", err)
	}
	if string(received.Plaintext) != "hello x509" {
		t.Fatalf("unexpected plaintext: %q", received.Plaintext)
	}
	if !bytes.Equal(received.SenderIdentity, aliceCert) {
		t.Fatal("sender identity should carry the sender certificate bytes")
	}
}

func TestClientWithX509CredentialRejectsEd25519Suite(t *testing.T) {
	t.Parallel()
	certDER, privKey := generateTestCertificate(t)
	if _, err := NewClient([]byte(""), ciphersuite.MLS128DHKEMX25519, WithX509Credential(certDER, privKey)); err == nil {
		t.Fatal("expected X.509 client creation to fail for Ed25519 suite")
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
	if _, ok := reader.groupEntries[groupCacheKeyBytes(groupID)]; !ok {
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

// TestClientStagedCommit_Confirm verifies the happy path of the staged commit API:
// CommitPendingProposalsStaged → ConfirmPendingCommit → new member can join.
func TestClientStagedCommit_Confirm(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256

	alice, err := NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	bob, err := NewClient([]byte("bob"), cs)
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}
	carol, err := NewClient([]byte("carol"), cs)
	if err != nil {
		t.Fatalf("NewClient(carol): %v", err)
	}

	// Alice creates group and invites Bob → epoch 1.
	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(bob): %v", err)
	}
	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	_, bobWelcome, err := alice.InviteMember(ctx, groupID, bobKP)
	if err != nil {
		t.Fatalf("InviteMember(bob): %v", err)
	}
	bobGroupID, err := bob.JoinGroup(ctx, bobWelcome)
	if err != nil {
		t.Fatalf("JoinGroup(bob): %v", err)
	}

	// Propose adding Carol; Bob receives the proposal (simulating DS fan-out).
	carolKP, err := carol.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(carol): %v", err)
	}
	aliceProposalBytes, err := alice.ProposeAddMember(ctx, groupID, carolKP)
	if err != nil {
		t.Fatalf("ProposeAddMember(carol): %v", err)
	}
	if err := bob.ProcessPublicMessage(ctx, bobGroupID, aliceProposalBytes); err != nil {
		t.Fatalf("bob ProcessPublicMessage(proposal): %v", err)
	}

	// Stage the commit — epoch must NOT advance yet.
	handle, err := alice.CommitPendingProposalsStaged(ctx, groupID)
	if err != nil {
		t.Fatalf("CommitPendingProposalsStaged: %v", err)
	}
	epochAfterStage, err := alice.Epoch(ctx, groupID)
	if err != nil {
		t.Fatalf("Epoch after stage: %v", err)
	}
	if epochAfterStage != 1 {
		t.Fatalf("epoch after stage = %d, want 1 (staged commit must not advance epoch)", epochAfterStage)
	}

	// Confirm — epoch advances to 2 and welcome for Carol is produced.
	welcomeBytes, err := alice.ConfirmPendingCommit(ctx, handle)
	if err != nil {
		t.Fatalf("ConfirmPendingCommit: %v", err)
	}
	if len(welcomeBytes) == 0 {
		t.Fatal("ConfirmPendingCommit returned empty welcome for Add proposal")
	}

	// Bob processes the commit.
	if err := bob.ProcessCommit(ctx, bobGroupID, handle.CommitBytes()); err != nil {
		t.Fatalf("bob ProcessCommit: %v", err)
	}

	// Carol joins.
	carolGroupID, err := carol.JoinGroup(ctx, welcomeBytes)
	if err != nil {
		t.Fatalf("carol JoinGroup: %v", err)
	}
	if !bytes.Equal(carolGroupID, groupID) {
		t.Fatalf("carol group ID mismatch")
	}

	// All three members must be present.
	members, err := alice.ListMembers(ctx, groupID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 3 {
		t.Fatalf("member count = %d, want 3 (alice, bob, carol)", len(members))
	}

	// Alice and Carol must share the same epoch.
	aliceEpoch, _ := alice.Epoch(ctx, groupID)
	carolEpoch, _ := carol.Epoch(ctx, carolGroupID)
	if aliceEpoch != carolEpoch {
		t.Fatalf("epoch mismatch: alice=%d carol=%d", aliceEpoch, carolEpoch)
	}
}

// TestClientStagedCommit_Discard verifies that DiscardPendingCommit rolls back
// the group to StateOperational with proposals preserved, and the group can then
// commit normally.
func TestClientStagedCommit_Discard(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256

	alice, err := NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	bob, err := NewClient([]byte("bob"), cs)
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}
	carol, err := NewClient([]byte("carol"), cs)
	if err != nil {
		t.Fatalf("NewClient(carol): %v", err)
	}

	// Alice creates group and invites Bob.
	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(bob): %v", err)
	}
	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	_, bobWelcome, err := alice.InviteMember(ctx, groupID, bobKP)
	if err != nil {
		t.Fatalf("InviteMember(bob): %v", err)
	}
	if _, err := bob.JoinGroup(ctx, bobWelcome); err != nil {
		t.Fatalf("JoinGroup(bob): %v", err)
	}

	// Propose adding Carol.
	carolKP, err := carol.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(carol): %v", err)
	}
	if _, err := alice.ProposeAddMember(ctx, groupID, carolKP); err != nil {
		t.Fatalf("ProposeAddMember(carol): %v", err)
	}

	// Stage a commit.
	handle, err := alice.CommitPendingProposalsStaged(ctx, groupID)
	if err != nil {
		t.Fatalf("CommitPendingProposalsStaged: %v", err)
	}

	// Discard it (simulating DS rejecting our commit).
	if err := alice.DiscardPendingCommit(ctx, handle); err != nil {
		t.Fatalf("DiscardPendingCommit: %v", err)
	}

	// Epoch must still be 1.
	epoch, err := alice.Epoch(ctx, groupID)
	if err != nil {
		t.Fatalf("Epoch after discard: %v", err)
	}
	if epoch != 1 {
		t.Fatalf("epoch after discard = %d, want 1", epoch)
	}

	// Proposals must still be stored so Alice can re-commit.
	aliceGroup := loadGroupForTest(t, alice, groupID)
	if len(aliceGroup.StoredProposals()) == 0 {
		t.Fatal("proposals were lost after DiscardPendingCommit")
	}

	// Alice can commit normally after discarding.
	commit, welcome, err := alice.CommitPendingProposals(ctx, groupID)
	if err != nil {
		t.Fatalf("CommitPendingProposals after discard: %v", err)
	}
	if len(welcome) == 0 {
		t.Fatal("expected welcome after re-commit")
	}
	_ = commit

	// Epoch must now be 2.
	epoch, err = alice.Epoch(ctx, groupID)
	if err != nil {
		t.Fatalf("Epoch after commit: %v", err)
	}
	if epoch != 2 {
		t.Fatalf("epoch after commit = %d, want 2", epoch)
	}

	// Carol can join with the welcome from the re-commit.
	if _, err := carol.JoinGroup(ctx, welcome); err != nil {
		t.Fatalf("carol JoinGroup after re-commit: %v", err)
	}
}

// TestClientStagedCommit_ConcurrentCommitConflict is a regression test for the
// two bugs found in the DAVE Discord bot:
//  1. CacheAlways poisoned rollback: loadGroupEntry returned the in-memory
//     post-commit group instead of the store-restored pre-commit state.
//  2. proposalByRef not rebuilt after UnmarshalGroupState: any commit by-reference
//     after state restore failed with "unknown proposal reference in commit".
//
// The test simulates the DS picking Bob's commit over Alice's while both have the
// same pending Add proposal for Carol, using CacheAlways (the mode that triggers #1).
func TestClientStagedCommit_ConcurrentCommitConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256

	// Use CacheAlways to trigger the cache-poisoning bug (#1).
	alice, err := NewClient([]byte("alice"), cs, WithCacheStrategy(CacheAlways))
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	bob, err := NewClient([]byte("bob"), cs, WithCacheStrategy(CacheAlways))
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}
	carol, err := NewClient([]byte("carol"), cs)
	if err != nil {
		t.Fatalf("NewClient(carol): %v", err)
	}

	// Alice creates group and invites Bob → epoch 1.
	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(bob): %v", err)
	}
	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	_, bobWelcome, err := alice.InviteMember(ctx, groupID, bobKP)
	if err != nil {
		t.Fatalf("InviteMember(bob): %v", err)
	}
	bobGroupID, err := bob.JoinGroup(ctx, bobWelcome)
	if err != nil {
		t.Fatalf("JoinGroup(bob): %v", err)
	}

	// Alice proposes adding Carol; Bob receives the proposal.
	carolKP, err := carol.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(carol): %v", err)
	}
	aliceProposalBytes, err := alice.ProposeAddMember(ctx, groupID, carolKP)
	if err != nil {
		t.Fatalf("ProposeAddMember(carol): %v", err)
	}
	if err := bob.ProcessPublicMessage(ctx, bobGroupID, aliceProposalBytes); err != nil {
		t.Fatalf("bob ProcessPublicMessage(proposal): %v", err)
	}

	// Both stage a commit for the same Add proposal (concurrent commit scenario).
	handleAlice, err := alice.CommitPendingProposalsStaged(ctx, groupID)
	if err != nil {
		t.Fatalf("alice CommitPendingProposalsStaged: %v", err)
	}
	handleBob, err := bob.CommitPendingProposalsStaged(ctx, bobGroupID)
	if err != nil {
		t.Fatalf("bob CommitPendingProposalsStaged: %v", err)
	}

	// DS picks Bob's commit. Alice discards hers and processes Bob's.
	if err := alice.DiscardPendingCommit(ctx, handleAlice); err != nil {
		t.Fatalf("alice DiscardPendingCommit: %v", err)
	}
	// Bug #1: with CacheAlways, alice's in-memory group was still at epoch N+1
	// (post-commit) after DiscardPendingCommit. ProcessCommit would then fail with
	// "invalid membership tag" because it tried to apply Bob's commit on top of
	// a group that was already at epoch N+1.
	if err := alice.ProcessCommit(ctx, groupID, handleBob.CommitBytes()); err != nil {
		t.Fatalf("alice ProcessCommit(bob's commit): %v — CacheAlways rollback bug may be present", err)
	}

	// Bob confirms his commit and produces the Welcome for Carol.
	welcomeBytes, err := bob.ConfirmPendingCommit(ctx, handleBob)
	if err != nil {
		t.Fatalf("bob ConfirmPendingCommit: %v", err)
	}
	if len(welcomeBytes) == 0 {
		t.Fatal("expected welcome bytes for Carol")
	}

	// Carol joins.
	carolGroupID, err := carol.JoinGroup(ctx, welcomeBytes)
	if err != nil {
		t.Fatalf("carol JoinGroup: %v", err)
	}
	if !bytes.Equal(carolGroupID, groupID) {
		t.Fatalf("carol group ID mismatch")
	}

	// Critical assertions: all three members must converge on epoch 2 with
	// identical export secrets (proving they share the same epoch key material).
	aliceEpoch, err := alice.Epoch(ctx, groupID)
	if err != nil {
		t.Fatalf("alice Epoch: %v", err)
	}
	bobEpoch, err := bob.Epoch(ctx, bobGroupID)
	if err != nil {
		t.Fatalf("bob Epoch: %v", err)
	}
	carolEpoch, err := carol.Epoch(ctx, carolGroupID)
	if err != nil {
		t.Fatalf("carol Epoch: %v", err)
	}
	if aliceEpoch != 2 || bobEpoch != 2 || carolEpoch != 2 {
		t.Fatalf("epoch mismatch: alice=%d bob=%d carol=%d, want all 2", aliceEpoch, bobEpoch, carolEpoch)
	}

	aliceExport, err := alice.Export(ctx, groupID, "test", []byte("ctx"), 32)
	if err != nil {
		t.Fatalf("alice Export: %v", err)
	}
	bobExport, err := bob.Export(ctx, bobGroupID, "test", []byte("ctx"), 32)
	if err != nil {
		t.Fatalf("bob Export: %v", err)
	}
	carolExport, err := carol.Export(ctx, carolGroupID, "test", []byte("ctx"), 32)
	if err != nil {
		t.Fatalf("carol Export: %v", err)
	}
	if !bytes.Equal(aliceExport, bobExport) {
		t.Error("alice and bob export secrets differ — epoch key material diverged")
	}
	if !bytes.Equal(aliceExport, carolExport) {
		t.Error("alice and carol export secrets differ — epoch key material diverged")
	}

	// All three must be listed as members.
	members, err := alice.ListMembers(ctx, groupID)
	if err != nil {
		t.Fatalf("alice ListMembers: %v", err)
	}
	if len(members) != 3 {
		t.Fatalf("alice sees %d members, want 3", len(members))
	}
}
