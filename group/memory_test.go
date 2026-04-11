package group

import (
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	keypackages "github.com/thomas-vilte/mls-go/keypackages"
)

// TestMemoryZeroing_AfterCommit verifies that after a commit the old epoch's
// secrets are moved into EpochHistory (not discarded) and that the group
// advances to a fresh set of EpochSecrets.
func TestMemoryZeroing_AfterCommit(t *testing.T) {
	// Create group with Alice
	cred1, _, _ := credentials.GenerateCredentialWithKey([]byte("alice"))
	kp1, priv1, _ := keypackages.Generate(cred1, keypackages.MLS128DHKEMP256)
	groupID, _ := NewGroupIDRandom()
	aliceGroup, _ := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kp1, priv1)

	// Create KeyPackage for Bob
	cred2, _, _ := credentials.GenerateCredentialWithKey([]byte("bob"))
	kp2, _, _ := keypackages.Generate(cred2, keypackages.MLS128DHKEMP256)

	// Keep a reference to epoch 0 secrets
	oldSecrets := aliceGroup.epochSecrets

	// Alice adds Bob and commits
	_, _ = aliceGroup.AddMember(kp2)
	sigPriv := ciphersuite.NewSignaturePrivateKey(priv1.SignatureKey)
	sigPub := sigPriv.PublicKey()
	sc, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		t.Fatalf("creating commit: %v", err)
	}

	// On MergeCommit, old secrets are moved to EpochHistory.
	if err := aliceGroup.MergeCommit(sc); err != nil {
		t.Fatalf("merging commit: %v", err)
	}

	// Old epoch (0) must be cached in EpochHistory.
	if aliceGroup.epochHistory == nil {
		t.Fatal("EpochHistory is nil after commit")
	}
	if _, ok := aliceGroup.epochHistory[0]; !ok {
		t.Fatal("epoch 0 not cached in EpochHistory")
	}

	// New EpochSecrets must differ from the old ones.
	newSecrets := aliceGroup.epochSecrets
	if newSecrets == oldSecrets {
		t.Fatal("EpochSecrets pointer unchanged after commit")
	}
	if newSecrets.SenderDataSecret == nil {
		t.Fatal("new SenderDataSecret is nil")
	}
}
