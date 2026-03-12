package group

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	keypackages "github.com/thomas-vilte/mls-go/keypackages"
)

func TestStateSerialization_RoundTrip(t *testing.T) {
	// 1. Crear grupo con un par de miembros
	credAlice, _, _ := credentials.GenerateCredentialWithKey([]byte("alice"))
	kpAlice, privAlice, _ := keypackages.Generate(credAlice, keypackages.MLS128DHKEMP256)
	groupID, _ := NewGroupIDRandom()
	aliceGroup, _ := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kpAlice, privAlice)

	credBob, _, _ := credentials.GenerateCredentialWithKey([]byte("bob"))
	kpBob, _, _ := keypackages.Generate(credBob, keypackages.MLS128DHKEMP256)

	if _, err := aliceGroup.AddMember(kpBob); err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}
	sigPriv := ciphersuite.NewSignaturePrivateKey(privAlice.SignatureKey)
	sigPub := sigPriv.PublicKey()
	sc, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}
	if err := aliceGroup.MergeCommit(sc); err != nil {
		t.Fatalf("MergeCommit failed: %v", err)
	}

	// We save some additional state to test that it is exported
	aliceGroup.CachedPsks["test-psk"] = []byte{1, 2, 3, 4}

	// 2. Serialize state
	data, err := aliceGroup.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState failed: %v", err)
	}

	// 3. Deserialize state
	restoredGroup, err := UnmarshalGroupState(data)
	if err != nil {
		t.Fatalf("UnmarshalGroupState failed: %v", err)
	}

	// 4. Verify everything matches
	if restoredGroup.Epoch.AsUint64() != aliceGroup.Epoch.AsUint64() {
		t.Errorf("Epoch mismatch: got %d, want %d", restoredGroup.Epoch.AsUint64(), aliceGroup.Epoch.AsUint64())
	}

	if !bytes.Equal(restoredGroup.GroupID.AsSlice(), aliceGroup.GroupID.AsSlice()) {
		t.Errorf("GroupID mismatch")
	}

	if restoredGroup.CipherSuite != aliceGroup.CipherSuite {
		t.Errorf("CipherSuite mismatch")
	}

	if restoredGroup.OwnLeafIndex != aliceGroup.OwnLeafIndex {
		t.Errorf("OwnLeafIndex mismatch")
	}

	if !bytes.Equal(restoredGroup.InterimTranscriptHash, aliceGroup.InterimTranscriptHash) {
		t.Errorf("InterimTranscriptHash mismatch")
	}

	if !bytes.Equal(restoredGroup.EpochSecrets.InitSecret.AsSlice(), aliceGroup.EpochSecrets.InitSecret.AsSlice()) {
		t.Errorf("InitSecret mismatch")
	}

	if !bytes.Equal(restoredGroup.CachedPsks["test-psk"], []byte{1, 2, 3, 4}) {
		t.Errorf("CachedPsks mismatch")
	}

	if restoredGroup.RatchetTree.NumLeaves != aliceGroup.RatchetTree.NumLeaves {
		t.Errorf("RatchetTree.NumLeaves mismatch: got %d, want %d", restoredGroup.RatchetTree.NumLeaves, aliceGroup.RatchetTree.NumLeaves)
	}

	if restoredGroup.state != StateOperational {
		t.Errorf("state mismatch: got %d, want %d", restoredGroup.state, StateOperational)
	}
}

func TestStateSerialization_RestoredGroupCanOperate(t *testing.T) {
	// Create Alice's group and add Bob.
	credAlice, _, _ := credentials.GenerateCredentialWithKey([]byte("alice"))
	kpAlice, privAlice, _ := keypackages.Generate(credAlice, keypackages.MLS128DHKEMP256)
	groupID, _ := NewGroupIDRandom()
	aliceGroup, _ := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kpAlice, privAlice)

	credBob, _, _ := credentials.GenerateCredentialWithKey([]byte("bob"))
	kpBob, _, _ := keypackages.Generate(credBob, keypackages.MLS128DHKEMP256)
	if _, err := aliceGroup.AddMember(kpBob); err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}

	sigPriv := ciphersuite.NewSignaturePrivateKey(privAlice.SignatureKey)
	sigPub := sigPriv.PublicKey()
	sc, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}
	if err := aliceGroup.MergeCommit(sc); err != nil {
		t.Fatalf("MergeCommit failed: %v", err)
	}

	// Serialize and restore.
	data, err := aliceGroup.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState: %v", err)
	}
	restoredGroup, err := UnmarshalGroupState(data)
	if err != nil {
		t.Fatalf("UnmarshalGroupState: %v", err)
	}

	// The restored group must be able to send a message.
	pm, err := restoredGroup.SendMessage([]byte("hello after restore"), sigPriv)
	if err != nil {
		t.Fatalf("restored group SendMessage: %v", err)
	}

	// The original group (same epoch secrets, SecretTree also at gen 0) must
	// be able to decrypt the message sent by the restored group.
	plaintext, err := aliceGroup.ReceiveMessage(pm, 0)
	if err != nil {
		t.Fatalf("original group ReceiveMessage: %v", err)
	}
	if string(plaintext) != "hello after restore" {
		t.Errorf("plaintext mismatch: got %q, want %q", plaintext, "hello after restore")
	}

	// Both groups must derive the same export secret.
	keyA, err := aliceGroup.Export("test", []byte("ctx"), 32)
	if err != nil {
		t.Fatalf("original Export: %v", err)
	}
	keyR, err := restoredGroup.Export("test", []byte("ctx"), 32)
	if err != nil {
		t.Fatalf("restored Export: %v", err)
	}
	if !bytes.Equal(keyA, keyR) {
		t.Error("Export key mismatch between original and restored group")
	}
}

func TestStateSerialization_FailsIfNotOperational(t *testing.T) {
	cred, _, _ := credentials.GenerateCredentialWithKey([]byte("alice"))
	kp, priv, _ := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
	groupID, _ := NewGroupIDRandom()
	group, _ := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kp, priv)

	credBob, _, _ := credentials.GenerateCredentialWithKey([]byte("bob"))
	kpBob, _, _ := keypackages.Generate(credBob, keypackages.MLS128DHKEMP256)

	if _, err := group.AddMember(kpBob); err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}
	sigPriv := ciphersuite.NewSignaturePrivateKey(priv.SignatureKey)
	sigPub := sigPriv.PublicKey()
	// After commit, state changes to StatePendingCommit
	if _, err := group.Commit(sigPriv, sigPub, nil); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	_, err := group.MarshalState()
	if err == nil {
		t.Error("MarshalState should fail when group is not operational")
	}
}
