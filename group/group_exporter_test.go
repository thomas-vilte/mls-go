package group

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// TestExport_Basic verifies that Export derives consistent keys (RFC 9420 §8.5).
func TestExport_Basic(t *testing.T) {
	// Create group with Alice
	cred1, _, err := credentials.GenerateCredentialWithKey([]byte("alice"))
	if err != nil {
		t.Fatalf("generating alice credential: %v", err)
	}
	kp1, priv1, err := keypackages.Generate(cred1, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating alice key package: %v", err)
	}

	groupID, _ := NewGroupIDRandom()
	aliceGroup, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kp1, priv1)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}

	// Export with same label and context must give same result
	label := "test-label"
	context := []byte("test-context")
	length := 32

	key1, err := aliceGroup.Export(label, context, length)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	if len(key1) != length {
		t.Errorf("Export length = %d, want %d", len(key1), length)
	}

	// Second export with same parameters must give equal result
	key2, err := aliceGroup.Export(label, context, length)
	if err != nil {
		t.Fatalf("Export second call failed: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Error("Export should be deterministic")
	}

	// Export with different label must give different result
	key3, _ := aliceGroup.Export("different-label", context, length)
	if bytes.Equal(key1, key3) {
		t.Error("Different label should produce different key")
	}
}

// TestExport_WhenNotOperational verifies that Export fails if the group is not operational.
func TestExport_WhenNotOperational(t *testing.T) {
	cred, _, err := credentials.GenerateCredentialWithKey([]byte("alice"))
	if err != nil {
		t.Fatalf("generating credential: %v", err)
	}
	kp, priv, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating key package: %v", err)
	}

	groupID, _ := NewGroupIDRandom()
	group, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kp, priv)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}

	// Create un commit pendiente cambia el estado
	cred2, _, _ := credentials.GenerateCredentialWithKey([]byte("bob"))
	kp2, _, _ := keypackages.Generate(cred2, keypackages.MLS128DHKEMP256)
	if _, err := group.AddMember(kp2); err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}
	sigPriv := ciphersuite.NewSignaturePrivateKey(priv.SignatureKey)
	sigPub := sigPriv.PublicKey()
	if _, err := group.Commit(sigPriv, sigPub, nil); err != nil {
		t.Fatalf("Commit failed: %v", err)
	} // State changes to PendingCommit

	// Export should fail because the group is in PendingCommit
	_, err = group.Export("label", nil, 32)
	if err == nil {
		t.Error("Export should fail when group is not operational")
	}
}

// TestExport_AfterCommit verifies that Export works after a commit.
func TestExport_AfterCommit(t *testing.T) {
	// Create group with Alice
	cred1, _, err := credentials.GenerateCredentialWithKey([]byte("alice"))
	if err != nil {
		t.Fatalf("generating alice credential: %v", err)
	}
	kp1, priv1, err := keypackages.Generate(cred1, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating alice key package: %v", err)
	}

	groupID, _ := NewGroupIDRandom()
	aliceGroup, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kp1, priv1)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}

	// Create KeyPackage for Bob
	cred2, _, err := credentials.GenerateCredentialWithKey([]byte("bob"))
	if err != nil {
		t.Fatalf("generating bob credential: %v", err)
	}
	kp2, _, err := keypackages.Generate(cred2, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating bob key package: %v", err)
	}

	// Add Bob and commit
	_, _ = aliceGroup.AddMember(kp2)
	sigPriv := ciphersuite.NewSignaturePrivateKey(priv1.SignatureKey)
	sigPub := sigPriv.PublicKey()
	sc, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		t.Fatalf("creating commit: %v", err)
	}
	if err := aliceGroup.MergeCommit(sc); err != nil {
		t.Fatalf("merging commit: %v", err)
	}

	// Export should work after the commit
	key, err := aliceGroup.Export("media-key", []byte("context"), 32)
	if err != nil {
		t.Fatalf("Export after commit failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("Export length = %d, want 32", len(key))
	}
}
