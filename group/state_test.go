package group

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/keypackages"
)

func TestStateSerialization_RoundTrip(t *testing.T) {
	// Create a group with a couple of members
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
	aliceGroup.cachedPsks["test-psk"] = []byte{1, 2, 3, 4}

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
	if restoredGroup.epoch.AsUint64() != aliceGroup.epoch.AsUint64() {
		t.Errorf("Epoch mismatch: got %d, want %d", restoredGroup.epoch.AsUint64(), aliceGroup.epoch.AsUint64())
	}

	if !bytes.Equal(restoredGroup.groupID.AsSlice(), aliceGroup.groupID.AsSlice()) {
		t.Errorf("GroupID mismatch")
	}

	if restoredGroup.cipherSuite != aliceGroup.cipherSuite {
		t.Errorf("CipherSuite mismatch")
	}

	if restoredGroup.ownLeafIndex != aliceGroup.ownLeafIndex {
		t.Errorf("OwnLeafIndex mismatch")
	}

	if !bytes.Equal(restoredGroup.interimTranscriptHash, aliceGroup.interimTranscriptHash) {
		t.Errorf("InterimTranscriptHash mismatch")
	}

	if !bytes.Equal(restoredGroup.epochSecrets.InitSecret.AsSlice(), aliceGroup.epochSecrets.InitSecret.AsSlice()) {
		t.Errorf("InitSecret mismatch")
	}

	if !bytes.Equal(restoredGroup.cachedPsks["test-psk"], []byte{1, 2, 3, 4}) {
		t.Errorf("CachedPsks mismatch")
	}

	if restoredGroup.ratchetTree.NumLeaves != aliceGroup.ratchetTree.NumLeaves {
		t.Errorf("RatchetTree.NumLeaves mismatch: got %d, want %d", restoredGroup.ratchetTree.NumLeaves, aliceGroup.ratchetTree.NumLeaves)
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

func TestUnmarshalGroupState_FailsOnTreeHashMismatch(t *testing.T) {
	credAlice, _, _ := credentials.GenerateCredentialWithKey([]byte("alice"))
	kpAlice, privAlice, _ := keypackages.Generate(credAlice, keypackages.MLS128DHKEMP256)
	groupID, _ := NewGroupIDRandom()
	aliceGroup, _ := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kpAlice, privAlice)

	data, err := aliceGroup.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState failed: %v", err)
	}

	var state GroupStateData
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	gc, err := UnmarshalGroupContext(state.GroupContext)
	if err != nil {
		t.Fatalf("UnmarshalGroupContext: %v", err)
	}
	gc.TreeHash[0] ^= 0xFF
	state.GroupContext = gc.Marshal()

	tampered, err := json.Marshal(&state)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	_, err = UnmarshalGroupState(tampered)
	if err == nil {
		t.Fatal("UnmarshalGroupState should fail with mismatched tree hash")
	}
	if !errors.Is(err, ErrTreeHashMismatch) {
		t.Fatalf("UnmarshalGroupState error = %v, want ErrTreeHashMismatch", err)
	}
}

// TestUnmarshalGroupState_RebuildsProposalByRef is a regression test for a bug
// where UnmarshalGroupState restored stored proposals into g.proposals (the slice)
// but not into g.proposalByRef (the lookup map). Any commit received after a
// state restore would fail with "unknown proposal reference in commit" because
// the by-ref index was always initialized empty.
func TestUnmarshalGroupState_RebuildsProposalByRef(t *testing.T) {
	aliceGroup, _, alicePriv, _ := setupTwoMemberGroup(t)

	// Add a third member (Carol) so we have a pending proposal to store.
	carolCred, _, err := credentials.GenerateCredentialWithKey([]byte("Carol"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(Carol): %v", err)
	}
	carolKP, carolPriv, err := keypackages.Generate(carolCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage(Carol): %v", err)
	}

	// Add Carol as a pending proposal (but do NOT commit yet).
	if _, err := aliceGroup.AddMember(carolKP); err != nil {
		t.Fatalf("AddMember(Carol): %v", err)
	}

	// Verify a proposal is stored before serialization.
	if len(aliceGroup.proposals.Proposals) == 0 {
		t.Fatal("expected at least 1 stored proposal before serialization")
	}

	// AddMember stores proposals inline without a ProposalRef hash (only the
	// network-receive path via ProcessPublicMessage → StoreProposal →
	// ComputeProposalRef populates Ref). Assign a synthetic ref to simulate
	// that path so we can verify that UnmarshalGroupState rebuilds the
	// proposalByRef lookup index from the serialized proposals.
	fakeRef := make([]byte, 32)
	copy(fakeRef, "regression-proposalbyref-rebuild")
	aliceGroup.proposals.Proposals[0].Ref = fakeRef
	aliceGroup.proposalByRef[string(fakeRef)] = aliceGroup.proposals.Proposals[0].Proposal
	ref := fakeRef

	// Serialize.
	data, err := aliceGroup.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState: %v", err)
	}

	// Deserialize.
	restored, err := UnmarshalGroupState(data)
	if err != nil {
		t.Fatalf("UnmarshalGroupState: %v", err)
	}

	// The proposalByRef index must have been rebuilt.
	if _, ok := restored.proposalByRef[string(ref)]; !ok {
		t.Fatalf("proposalByRef does not contain the restored proposal ref — regression: UnmarshalGroupState does not rebuild proposalByRef index")
	}

	// The restored group must be able to create a commit that references the
	// stored proposal by hash (the operation that was failing in production).
	aliceSigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)
	aliceSigPub := aliceSigPriv.PublicKey()
	sc, err := restored.Commit(aliceSigPriv, aliceSigPub, nil)
	if err != nil {
		t.Fatalf("Commit on restored group failed: %v — proposalByRef index may not be rebuilt correctly", err)
	}
	if err := restored.MergeCommit(sc); err != nil {
		t.Fatalf("MergeCommit on restored group: %v", err)
	}

	// Verify Carol can join using the Welcome produced from the restored group.
	joinerSecret := sc.JoinerSecret()
	welcome, err := restored.CreateWelcomeWithOptions([]*keypackages.KeyPackage{carolKP}, CreateWelcomeOptions{
		JoinerSecret:  joinerSecret,
		SignerPrivKey: aliceSigPriv,
		StagedCommit:  sc,
	})
	if err != nil {
		t.Fatalf("CreateWelcomeWithOptions: %v", err)
	}
	carolGroup, err := JoinFromWelcome(welcome, carolKP, carolPriv, nil)
	if err != nil {
		t.Fatalf("JoinFromWelcome(Carol): %v", err)
	}
	if carolGroup.epoch.AsUint64() != restored.epoch.AsUint64() {
		t.Errorf("epoch mismatch: carol=%d alice=%d", carolGroup.epoch.AsUint64(), restored.epoch.AsUint64())
	}
}

func TestUnmarshalGroupState_FailsOnOwnLeafOutOfBounds(t *testing.T) {
	credAlice, _, _ := credentials.GenerateCredentialWithKey([]byte("alice"))
	kpAlice, privAlice, _ := keypackages.Generate(credAlice, keypackages.MLS128DHKEMP256)
	groupID, _ := NewGroupIDRandom()
	aliceGroup, _ := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kpAlice, privAlice)

	data, err := aliceGroup.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState failed: %v", err)
	}

	var state GroupStateData
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	state.OwnLeafIndex += 10

	tampered, err := json.Marshal(&state)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	_, err = UnmarshalGroupState(tampered)
	if err == nil {
		t.Fatal("UnmarshalGroupState should fail with out-of-bounds own leaf")
	}
	if !errors.Is(err, ErrInvalidGroupState) {
		t.Fatalf("UnmarshalGroupState error = %v, want ErrInvalidGroupState", err)
	}
}

func TestUnmarshalGroupState_FailsOnConfirmationTagMismatch(t *testing.T) {
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

	data, err := aliceGroup.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState failed: %v", err)
	}

	var state GroupStateData
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	state.ConfirmationTag[0] ^= 0xFF

	tampered, err := json.Marshal(&state)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	_, err = UnmarshalGroupState(tampered)
	if err == nil {
		t.Fatal("UnmarshalGroupState should fail with confirmation tag mismatch")
	}
	if !errors.Is(err, ErrConfirmationTagMismatch) {
		t.Fatalf("UnmarshalGroupState error = %v, want ErrConfirmationTagMismatch", err)
	}
}
