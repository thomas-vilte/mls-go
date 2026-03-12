package group

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/schedule"
	"github.com/thomas-vilte/mls-go/secrettree"
	"github.com/thomas-vilte/mls-go/treesync"
)

type testUser struct {
	kp      *keypackages.KeyPackage
	priv    *keypackages.KeyPackagePrivateKeys
	sigPriv *ciphersuite.SignaturePrivateKey
	sigPub  *ciphersuite.SignaturePublicKey
}

func newTestUser(t *testing.T, name string) *testUser {
	t.Helper()
	credWithKey, _, err := credentials.GenerateCredentialWithKey([]byte(name))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(%s): %v", name, err)
	}
	kp, priv, err := keypackages.Generate(credWithKey, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("keypackages.Generate(%s): %v", name, err)
	}
	sigPriv := ciphersuite.NewSignaturePrivateKey(priv.SignatureKey)
	return &testUser{
		kp:      kp,
		priv:    priv,
		sigPriv: sigPriv,
		sigPub:  sigPriv.PublicKey(),
	}
}
func makeTwoMemberGroups(t *testing.T) (aliceGroup, bobGroup *Group, alice, bob *testUser) {
	t.Helper()
	alice = newTestUser(t, "alice")
	bob = newTestUser(t, "bob")
	groupID, err := NewGroupIDRandom()
	if err != nil {
		t.Fatalf("NewGroupIDRandom: %v", err)
	}
	aliceGroup, err = NewGroup(groupID, ciphersuite.MLS128DHKEMP256, alice.kp, alice.priv)
	if err != nil {
		t.Fatalf("NewGroup(alice): %v", err)
	}
	if _, err = aliceGroup.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember(bob): %v", err)
	}
	// Capture key schedule material before merge.
	initSecret := aliceGroup.EpochSecrets.InitSecret.Clone()
	sc, err := aliceGroup.Commit(alice.sigPriv, alice.sigPub, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	pathSecret := []byte(nil)
	if sc.RootPathSecret != nil {
		pathSecret = append([]byte(nil), sc.RootPathSecret.AsSlice()...)
	}
	joinerSecret, err := initSecret.HKDFExtract(ciphersuite.NewSecret(pathSecret))
	if err != nil {
		t.Fatalf("computing joiner secret: %v", err)
	}
	if err = aliceGroup.MergeCommit(sc); err != nil {
		t.Fatalf("MergeCommit: %v", err)
	}
	welcome, err := aliceGroup.CreateWelcome(
		[]*keypackages.KeyPackage{bob.kp},
		joinerSecret,
		pathSecret,
		alice.sigPriv,
	)
	if err != nil {
		t.Fatalf("CreateWelcome: %v", err)
	}
	bobGroup, err = JoinFromWelcome(welcome, bob.kp, bob.priv, nil)
	if err != nil {
		t.Fatalf("JoinFromWelcome: %v", err)
	}

	// Keep both group instances aligned on epoch secrets for message roundtrip checks.
	bobGroup.EpochSecrets = &schedule.EpochSecrets{
		InitSecret:       aliceGroup.EpochSecrets.InitSecret.Clone(),
		SenderDataSecret: aliceGroup.EpochSecrets.SenderDataSecret.Clone(),
		EncryptionSecret: aliceGroup.EpochSecrets.EncryptionSecret.Clone(),
		ExporterSecret:   aliceGroup.EpochSecrets.ExporterSecret.Clone(),
		ExternalSecret:   aliceGroup.EpochSecrets.ExternalSecret.Clone(),
		ConfirmationKey:  aliceGroup.EpochSecrets.ConfirmationKey.Clone(),
		MembershipKey:    aliceGroup.EpochSecrets.MembershipKey.Clone(),
		ResumptionSecret: aliceGroup.EpochSecrets.ResumptionSecret.Clone(),
	}
	bobGroup.KeySchedule = schedule.NewKeySchedule(bobGroup.CipherSuite, bobGroup.EpochSecrets.InitSecret)
	bobGroup.SecretTree, err = secrettree.NewTree(bobGroup.EpochSecrets.EncryptionSecret, bobGroup.RatchetTree.NumLeaves, bobGroup.CipherSuite)
	if err != nil {
		t.Fatalf("secrettree.NewTree(bob): %v", err)
	}
	return aliceGroup, bobGroup, alice, bob
}
func TestWelcomeRoundTrip(t *testing.T) {
	aliceGroup, bobGroup, alice, _ := makeTwoMemberGroups(t)
	if bobGroup.Epoch.AsUint64() != 1 {
		t.Fatalf("bob epoch = %d, want 1", bobGroup.Epoch.AsUint64())
	}
	if aliceGroup.MemberCount() < 2 || bobGroup.MemberCount() < 2 {
		t.Fatalf("expected at least 2 members (alice=%d bob=%d)", aliceGroup.MemberCount(), bobGroup.MemberCount())
	}
	msg := []byte("hello bob")
	pm, err := aliceGroup.SendMessage(msg, alice.sigPriv)
	if err != nil {
		t.Fatalf("SendMessage(alice): %v", err)
	}
	got, err := bobGroup.ReceiveMessage(pm, aliceGroup.OwnLeafIndex)
	if err != nil {
		t.Fatalf("ReceiveMessage(bob): %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("plaintext sametch: got %q want %q", got, msg)
	}
}
func TestPrivateMessageRoundTrip(t *testing.T) {
	aliceGroup, bobGroup, alice, bob := makeTwoMemberGroups(t)
	msgAB := []byte("hello bob")
	pmAB, err := aliceGroup.SendMessage(msgAB, alice.sigPriv)
	if err != nil {
		t.Fatalf("SendMessage(alice): %v", err)
	}
	gotAB, err := bobGroup.ReceiveMessage(pmAB, aliceGroup.OwnLeafIndex)
	if err != nil {
		t.Fatalf("ReceiveMessage(bob): %v", err)
	}
	if !bytes.Equal(gotAB, msgAB) {
		t.Fatalf("alice->bob sametch: got %q want %q", gotAB, msgAB)
	}
	msgBA := []byte("hello alice")
	pmBA, err := bobGroup.SendMessage(msgBA, bob.sigPriv)
	if err != nil {
		t.Fatalf("SendMessage(bob): %v", err)
	}
	gotBA, err := aliceGroup.ReceiveMessage(pmBA, bobGroup.OwnLeafIndex)
	if err != nil {
		t.Fatalf("ReceiveMessage(alice): %v", err)
	}
	if !bytes.Equal(gotBA, msgBA) {
		t.Fatalf("bob->alice sametch: got %q want %q", gotBA, msgBA)
	}
}
func TestExternalCommitRoundTrip(t *testing.T) {
	aliceGroup, _, alice, _ := makeTwoMemberGroups(t)
	charlie := newTestUser(t, "charlie")
	groupInfo, err := aliceGroup.GetGroupInfo(alice.sigPriv)
	if err != nil {
		t.Fatalf("GetGroupInfo: %v", err)
	}
	charlieGroup, sc, err := ExternalCommit(
		groupInfo,
		aliceGroup.CipherSuite,
		charlie.sigPriv,
		charlie.sigPub,
	)
	if err != nil {
		t.Fatalf("ExternalCommit: %v", err)
	}
	if sc == nil || sc.AuthenticatedContent == nil {
		t.Fatalf("external staged commit is nil")
	}
	err = aliceGroup.MergeCommit(sc)
	if err != nil {
		t.Fatalf("MergeCommit(external): %v", err)
	}
	if aliceGroup.Epoch.AsUint64() != 2 {
		t.Fatalf("alice epoch = %d, want 2", aliceGroup.Epoch.AsUint64())
	}
	if charlieGroup.Epoch.AsUint64() != 2 {
		t.Fatalf("charlie epoch = %d, want 2", charlieGroup.Epoch.AsUint64())
	}
}

func TestConfirmationTagPersistence(t *testing.T) {
	aliceGroup, _, alice, _ := makeTwoMemberGroups(t)

	if len(aliceGroup.ConfirmationTag) == 0 {
		t.Fatalf("alice confirmation tag should not be empty after merge")
	}

	groupInfo, err := aliceGroup.GetGroupInfo(alice.sigPriv)
	if err != nil {
		t.Fatalf("GetGroupInfo: %v", err)
	}

	if !bytes.Equal(groupInfo.ConfirmationTag, aliceGroup.ConfirmationTag) {
		t.Fatalf("group info confirmation tag sametch")
	}

	charlie := newTestUser(t, "charlie-confirmation")
	charlieGroup, sc, err := ExternalCommit(
		groupInfo,
		aliceGroup.CipherSuite,
		charlie.sigPriv,
		charlie.sigPub,
	)
	if err != nil {
		t.Fatalf("ExternalCommit: %v", err)
	}

	if err := aliceGroup.MergeCommit(sc); err != nil {
		t.Fatalf("MergeCommit(external): %v", err)
	}

	if aliceGroup.Epoch.AsUint64() != 2 {
		t.Fatalf("alice epoch = %d, want 2", aliceGroup.Epoch.AsUint64())
	}
	if charlieGroup.Epoch.AsUint64() != 2 {
		t.Fatalf("charlie epoch = %d, want 2", charlieGroup.Epoch.AsUint64())
	}
	if len(aliceGroup.ConfirmationTag) == 0 {
		t.Fatalf("alice confirmation tag should not be empty in epoch 2")
	}
}

func TestExternalCommitReceiver(t *testing.T) {
	alice := newTestUser(t, "alice-external")
	charlie := newTestUser(t, "charlie-external")

	groupID, err := NewGroupIDRandom()
	if err != nil {
		t.Fatalf("NewGroupIDRandom: %v", err)
	}

	aliceGroup, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, alice.kp, alice.priv)
	if err != nil {
		t.Fatalf("NewGroup(alice): %v", err)
	}

	groupInfo, err := aliceGroup.GetGroupInfo(alice.sigPriv)
	if err != nil {
		t.Fatalf("GetGroupInfo: %v", err)
	}

	_, staged, err := ExternalCommit(
		groupInfo,
		aliceGroup.CipherSuite,
		charlie.sigPriv,
		charlie.sigPub,
	)
	if err != nil {
		t.Fatalf("ExternalCommit: %v", err)
	}

	err = aliceGroup.ProcessReceivedCommit(
		staged.AuthenticatedContent,
		treesync.LeafIndex(0),
		alice.priv.InitKey.Bytes(),
	)
	if err != nil {
		t.Fatalf("ProcessReceivedCommit(external): %v", err)
	}

	if aliceGroup.Epoch.AsUint64() != 1 {
		t.Fatalf("alice epoch = %d, want 1", aliceGroup.Epoch.AsUint64())
	}
}

func TestNewGroupFromReInit(t *testing.T) {
	alice := newTestUser(t, "alice-reinit")
	reinit := &ReInitProposal{
		GroupID:     []byte("new-group-id"),
		Version:     keypackages.MLS10,
		CipherSuite: keypackages.MLS128DHKEMP256,
		Extensions:  nil,
	}
	resumptionSecret, err := ciphersuite.NewSecretRandomCS(ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("NewSecretRandomCS: %v", err)
	}
	group, err := NewGroupFromReInit(reinit, resumptionSecret, alice.kp, alice.priv)
	if err != nil {
		t.Fatalf("NewGroupFromReInit: %v", err)
	}
	if group.Epoch.AsUint64() != 0 {
		t.Fatalf("epoch = %d, want 0", group.Epoch.AsUint64())
	}
	if group.GroupContext == nil {
		t.Fatal("group context is nil")
	}
	if !bytes.Equal(group.GroupContext.GroupID.AsSlice(), reinit.GroupID) {
		t.Fatal("group id sametch")
	}
	if group.KeySchedule == nil {
		t.Fatal("key schedule is nil")
	}
	if _, ok := group.CachedPsks[string(reinit.GroupID)]; !ok {
		t.Fatal("resumption PSK not cached")
	}
}

func TestReceiveMessage_SenderOutOfBounds(t *testing.T) {
	aliceGroup, _, _, _ := makeTwoMemberGroups(t)
	_, err := aliceGroup.ReceiveMessage(&framing.PrivateMessage{}, 999)
	if err == nil {
		t.Fatal("expected out of bounds error")
	}
}
