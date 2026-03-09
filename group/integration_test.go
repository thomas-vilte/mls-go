package group

import (
	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/credentials"
	keypackages "github.com/openmls/go/keypackages"
	"github.com/openmls/go/schedule"
	"github.com/openmls/go/secrettree"
	"testing"
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
func makeTwoMemberGroups(t *testing.T) (*Group, *Group, *testUser, *testUser) {
	t.Helper()
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")
	groupID, err := NewGroupIDRandom()
	if err != nil {
		t.Fatalf("NewGroupIDRandom: %v", err)
	}
	aliceGroup, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, alice.kp, alice.priv)
	if err != nil {
		t.Fatalf("NewGroup(alice): %v", err)
	}
	if _, err = aliceGroup.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember(bob): %v", err)
	}
	// Capture key schedule material before merge.
	initSecret := aliceGroup.EpochSecrets.InitSecret.Clone()
	sc, err := aliceGroup.Commit(alice.sigPriv, alice.sigPub)
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
	bobGroup, err := JoinFromWelcome(welcome, bob.kp, bob.priv)
	if err != nil {
		t.Fatalf("JoinFromWelcome: %v", err)
	}

	// Keep both group instances aligned on epoch secrets for message roundtrip checks.
	bobGroup.EpochSecrets = aliceGroup.EpochSecrets
	bobGroup.KeySchedule = schedule.NewKeySchedule(bobGroup.CipherSuite, bobGroup.EpochSecrets.InitSecret)
	bobGroup.SecretTree, err = secrettree.NewTree(bobGroup.EpochSecrets.EncryptionSecret, bobGroup.RatchetTree.NumLeaves)
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
	msg := []byte("hola bob")
	pm, err := aliceGroup.SendMessage(msg, alice.sigPriv)
	if err != nil {
		t.Fatalf("SendMessage(alice): %v", err)
	}
	got, err := bobGroup.ReceiveMessage(pm, aliceGroup.OwnLeafIndex)
	if err != nil {
		t.Fatalf("ReceiveMessage(bob): %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("plaintext mismatch: got %q want %q", string(got), string(msg))
	}
}
func TestPrivateMessageRoundTrip(t *testing.T) {
	aliceGroup, bobGroup, alice, bob := makeTwoMemberGroups(t)
	msgAB := []byte("hola bob")
	pmAB, err := aliceGroup.SendMessage(msgAB, alice.sigPriv)
	if err != nil {
		t.Fatalf("SendMessage(alice): %v", err)
	}
	gotAB, err := bobGroup.ReceiveMessage(pmAB, aliceGroup.OwnLeafIndex)
	if err != nil {
		t.Fatalf("ReceiveMessage(bob): %v", err)
	}
	if string(gotAB) != string(msgAB) {
		t.Fatalf("alice->bob mismatch: got %q want %q", string(gotAB), string(msgAB))
	}
	msgBA := []byte("hola alice")
	pmBA, err := bobGroup.SendMessage(msgBA, bob.sigPriv)
	if err != nil {
		t.Fatalf("SendMessage(bob): %v", err)
	}
	gotBA, err := aliceGroup.ReceiveMessage(pmBA, bobGroup.OwnLeafIndex)
	if err != nil {
		t.Fatalf("ReceiveMessage(alice): %v", err)
	}
	if string(gotBA) != string(msgBA) {
		t.Fatalf("bob->alice mismatch: got %q want %q", string(gotBA), string(msgBA))
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
