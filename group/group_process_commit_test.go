package group

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/schedule"
	"github.com/thomas-vilte/mls-go/treesync"
)

// Helper: creates a 2-member group for Commit tests
func setupTwoMemberGroup(t *testing.T) (aliceGroup, bobGroup *Group, alicePriv, bobPriv *keypackages.KeyPackagePrivateKeys) {
	t.Helper()

	// Alice creates the group
	aliceCred, _, err := credentials.GenerateCredentialWithKey([]byte("Alice"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(Alice): %v", err)
	}

	aliceKP, alicePriv, err := keypackages.Generate(aliceCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage(Alice): %v", err)
	}

	groupID, err := NewGroupIDRandom()
	if err != nil {
		t.Fatalf("NewGroupIDRandom: %v", err)
	}

	aliceGroup, err = NewGroup(groupID, ciphersuite.MLS128DHKEMP256, aliceKP, alicePriv)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}

	// Bob joins
	bobCred, _, err := credentials.GenerateCredentialWithKey([]byte("Bob"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(Bob): %v", err)
	}

	var bobKP *keypackages.KeyPackage
	bobKP, bobPriv, err = keypackages.Generate(bobCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage(Bob): %v", err)
	}

	if _, err := aliceGroup.AddMember(bobKP); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	// Alice commits the add proposal.
	aliceSigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)
	aliceSigPub := aliceSigPriv.PublicKey()

	stagedCommit, err := aliceGroup.Commit(aliceSigPriv, aliceSigPub, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if err := aliceGroup.MergeCommit(stagedCommit); err != nil {
		t.Fatalf("MergeCommit: %v", err)
	}

	// Create Welcome for Bob using the real joiner_secret from the StagedCommit (RFC 9420 §8).
	joinerSecret := stagedCommit.JoinerSecret()

	welcome, err := aliceGroup.CreateWelcomeWithOptions([]*keypackages.KeyPackage{bobKP}, CreateWelcomeOptions{
		JoinerSecret:  joinerSecret,
		SignerPrivKey: aliceSigPriv,
		StagedCommit:  stagedCommit,
	})
	if err != nil {
		t.Fatalf("CreateWelcome: %v", err)
	}

	bobGroup, err = JoinFromWelcome(welcome, bobKP, bobPriv, nil)
	if err != nil {
		t.Fatalf("JoinFromWelcome: %v", err)
	}

	// Synchronize Bob's epoch secrets with Alice
	bobGroup.epochSecrets = &schedule.EpochSecrets{
		InitSecret:       aliceGroup.epochSecrets.InitSecret.Clone(),
		SenderDataSecret: aliceGroup.epochSecrets.SenderDataSecret.Clone(),
		EncryptionSecret: aliceGroup.epochSecrets.EncryptionSecret.Clone(),
		ExporterSecret:   aliceGroup.epochSecrets.ExporterSecret.Clone(),
		ExternalSecret:   aliceGroup.epochSecrets.ExternalSecret.Clone(),
		ConfirmationKey:  aliceGroup.epochSecrets.ConfirmationKey.Clone(),
		MembershipKey:    aliceGroup.epochSecrets.MembershipKey.Clone(),
		ResumptionSecret: aliceGroup.epochSecrets.ResumptionSecret.Clone(),
	}

	return aliceGroup, bobGroup, alicePriv, bobPriv
}

func TestCreateWelcomeWithOptions(t *testing.T) {
	aliceGroup, _, alicePriv, _ := setupTwoMemberGroup(t)
	bobCred, _, err := credentials.GenerateCredentialWithKey([]byte("Bob2"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(Bob2): %v", err)
	}
	bobKP, bobPriv, err := keypackages.Generate(bobCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage(Bob2): %v", err)
	}

	aliceSigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)
	aliceSigPub := aliceSigPriv.PublicKey()

	// Add Bob and commit so we have a real joiner_secret for the Welcome.
	if _, err := aliceGroup.AddMember(bobKP); err != nil {
		t.Fatalf("AddMember(Bob2): %v", err)
	}
	sc, err := aliceGroup.Commit(aliceSigPriv, aliceSigPub, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	joinerSecret := sc.JoinerSecret()
	if err := aliceGroup.MergeCommit(sc); err != nil {
		t.Fatalf("MergeCommit: %v", err)
	}

	welcomeFromOptions, err := aliceGroup.CreateWelcomeWithOptions([]*keypackages.KeyPackage{bobKP}, CreateWelcomeOptions{
		JoinerSecret:  joinerSecret,
		SignerPrivKey: aliceSigPriv,
		StagedCommit:  sc,
	})
	if err != nil {
		t.Fatalf("CreateWelcomeWithOptions: %v", err)
	}

	if len(welcomeFromOptions.Marshal()) == 0 {
		t.Fatal("CreateWelcomeWithOptions() returned an empty Welcome")
	}

	joinedGroup, err := JoinFromWelcome(welcomeFromOptions, bobKP, bobPriv, nil)
	if err != nil {
		t.Fatalf("JoinFromWelcome(CreateWelcomeWithOptions): %v", err)
	}
	if joinedGroup == nil {
		t.Fatal("JoinFromWelcome(CreateWelcomeWithOptions) returned nil group")
	}
}

// TestProcessCommit_Valid verifies that a valid commit is processed correctly
func TestProcessCommit_Valid(t *testing.T) {
	aliceGroup, bobGroup, alicePriv, _ := setupTwoMemberGroup(t)

	// Save Bob's previous state
	oldEpoch := bobGroup.epoch.AsUint64()
	oldTreeHash := bobGroup.ratchetTree.TreeHash()

	// Alice generates a new commit (Add proposal of a third member)
	aliceSigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)
	aliceSigPub := aliceSigPriv.PublicKey()

	// Create third member
	charlieCred, _, err := credentials.GenerateCredentialWithKey([]byte("Charlie"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(Charlie): %v", err)
	}

	charlieKP, _, err := keypackages.Generate(charlieCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage(Charlie): %v", err)
	}

	// Alice adds Charlie
	_, err = aliceGroup.AddMember(charlieKP)
	if err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	// Alice commits the add proposal.
	stagedCommit, err := aliceGroup.Commit(aliceSigPriv, aliceSigPub, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Bob processes the received commit
	err = bobGroup.ProcessCommit(stagedCommit)
	if err != nil {
		t.Fatalf("ProcessCommit failed: %v", err)
	}

	// Verify that the epoch increased
	if bobGroup.epoch.AsUint64() != oldEpoch+1 {
		t.Errorf("Epoch should increment from %d to %d, got %d", oldEpoch, oldEpoch+1, bobGroup.epoch.AsUint64())
	}

	// Verify that the TreeHash changed
	if bytes.Equal(bobGroup.ratchetTree.TreeHash(), oldTreeHash) {
		t.Error("TreeHash should change after commit")
	}

	// Verify that the epoch secrets are not nil
	if bobGroup.epochSecrets == nil {
		t.Error("EpochSecrets should not be nil after commit")
	}
	if bobGroup.epochSecrets.EncryptionSecret == nil {
		t.Error("EncryptionSecret should not be nil after commit")
	}

	// Verify that the proposal was applied (Charlie should be in the group)
	if bobGroup.MemberCount() != 3 {
		t.Errorf("MemberCount should be 3 after adding Charlie, got %d", bobGroup.MemberCount())
	}
}

// TestProcessCommit_WrongEpoch verifies that a commit with incorrect epoch fails.
func TestProcessCommit_WrongEpoch(t *testing.T) {
	aliceGroup, bobGroup, alicePriv, _ := setupTwoMemberGroup(t)

	aliceSigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)
	aliceSigPub := aliceSigPriv.PublicKey()

	charlieCred, _, err := credentials.GenerateCredentialWithKey([]byte("CharlieWrongEpoch"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey: %v", err)
	}

	charlieKP, _, err := keypackages.Generate(charlieCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage: %v", err)
	}

	if _, err := aliceGroup.AddMember(charlieKP); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	stagedCommit, err := aliceGroup.Commit(aliceSigPriv, aliceSigPub, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	stagedCommit.authenticatedContent.Content.Epoch++

	err = bobGroup.ProcessCommit(stagedCommit)
	if err == nil {
		t.Fatal("ProcessCommit should fail with wrong epoch")
	}

	var epochErr *ErrEpochMismatch
	if !errors.As(err, &epochErr) {
		t.Fatalf("ProcessCommit error = %v, want ErrEpochMismatch", err)
	}
	if epochErr.Got != stagedCommit.authenticatedContent.Content.Epoch {
		t.Fatalf("ErrEpochMismatch.Got = %d, want %d", epochErr.Got, stagedCommit.authenticatedContent.Content.Epoch)
	}
	if epochErr.Want != bobGroup.groupContext.Epoch.AsUint64() {
		t.Fatalf("ErrEpochMismatch.Want = %d, want %d", epochErr.Want, bobGroup.groupContext.Epoch.AsUint64())
	}
}

// TestProcessCommit_CorruptedUpdatePath verifies that a commit with corrupted UpdatePath fails
func TestProcessCommit_CorruptedUpdatePath(t *testing.T) {
	aliceGroup, bobGroup, alicePriv, _ := setupTwoMemberGroup(t)

	// Create a valid commit (first add a proposal)
	aliceSigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)
	aliceSigPub := aliceSigPriv.PublicKey()

	// Add third member to have a proposal
	charlieCred, _, err := credentials.GenerateCredentialWithKey([]byte("Charlie3"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey: %v", err)
	}

	charlieKP, _, err := keypackages.Generate(charlieCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage: %v", err)
	}

	if _, err := aliceGroup.AddMember(charlieKP); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	stagedCommit, err := aliceGroup.Commit(aliceSigPriv, aliceSigPub, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Corrupt the UpdatePath if it exists
	if stagedCommit.commit.Path != nil && len(stagedCommit.commit.Path.Nodes) > 0 {
		// Save original
		original := make([]byte, len(stagedCommit.commit.Path.Nodes[0].EncryptionKey))
		copy(original, stagedCommit.commit.Path.Nodes[0].EncryptionKey)

		// Corrupt a byte
		stagedCommit.commit.Path.Nodes[0].EncryptionKey[0] ^= 0xFF

		// Bob tries to process
		err = bobGroup.ProcessCommit(stagedCommit)
		if err != nil {
			t.Logf("ProcessCommit correctly detected corrupted UpdatePath: %v", err)
		} else {
			t.Error("ProcessCommit should fail with corrupted UpdatePath")
		}

		// Restore for cleanup
		copy(stagedCommit.commit.Path.Nodes[0].EncryptionKey, original)
	} else {
		t.Skip("Commit has no UpdatePath nodes to corrupt")
	}
}

// TestUpdateMember_Valid verifies that UpdateMember generates a valid proposal
func TestUpdateMember_Valid(t *testing.T) {
	aliceGroup, _, alicePriv, _ := setupTwoMemberGroup(t)

	// Save the original encryption key
	oldLeaf := aliceGroup.ratchetTree.GetLeaf(treesync.LeafIndex(aliceGroup.ownLeafIndex))
	if oldLeaf == nil || oldLeaf.LeafData == nil {
		t.Fatal("Own leaf not found")
	}
	oldEncryptionKey := make([]byte, len(oldLeaf.LeafData.EncryptionKey))
	copy(oldEncryptionKey, oldLeaf.LeafData.EncryptionKey)

	// Generate new LeafNode
	newEncryptionKey := make([]byte, len(oldEncryptionKey))
	if _, err := rand.Read(newEncryptionKey); err != nil {
		t.Fatalf("Generating random key: %v", err)
	}

	newLeafNode := &treesync.LeafNodeData{
		EncryptionKey: newEncryptionKey,
		SignatureKey:  oldLeaf.LeafData.SignatureKey,
		Credential:    oldLeaf.LeafData.Credential,
		Capabilities:  oldLeaf.LeafData.Capabilities,
		Lifetime:      oldLeaf.LeafData.Lifetime,
	}

	// Create Update proposal
	updateProposal, err := aliceGroup.UpdateMember(newLeafNode, alicePriv)
	if err != nil {
		t.Fatalf("UpdateMember failed: %v", err)
	}

	// Verify that the proposal was created
	if updateProposal == nil {
		t.Fatal("UpdateMember should return non-nil proposal")
	}

	if updateProposal.Type != ProposalTypeUpdate {
		t.Errorf("Proposal type should be Update (%d), got %d", ProposalTypeUpdate, updateProposal.Type)
	}

	if updateProposal.Update == nil {
		t.Fatal("Update proposal body should not be nil")
	}

	// Verify that the encryption key changed
	if bytes.Equal(oldLeaf.LeafData.EncryptionKey, updateProposal.Update.LeafNode.EncryptionKey) {
		t.Error("UpdateMember should generate new encryption key")
	}

	// Verify that the proposal was stored
	if aliceGroup.proposals == nil || len(aliceGroup.proposals.Proposals) == 0 {
		t.Error("Update proposal should be stored in proposal store")
	}
}

// TestUpdateMember_NilCredential verifies that UpdateMember fails with nil credential
func TestUpdateMember_NilCredential(t *testing.T) {
	aliceGroup, _, _, _ := setupTwoMemberGroup(t)

	// Try UpdateMember with nil LeafNode
	_, err := aliceGroup.UpdateMember(nil, nil)
	if err == nil {
		t.Error("UpdateMember should fail with nil LeafNode")
	}

	// Create valid LeafNode but with nil private keys
	leaf := aliceGroup.ratchetTree.GetLeaf(treesync.LeafIndex(aliceGroup.ownLeafIndex))
	if leaf == nil || leaf.LeafData == nil {
		t.Fatal("Own leaf not found")
	}

	newLeafNode := &treesync.LeafNodeData{
		EncryptionKey: leaf.LeafData.EncryptionKey,
		SignatureKey:  leaf.LeafData.SignatureKey,
		Credential:    leaf.LeafData.Credential,
		Capabilities:  leaf.LeafData.Capabilities,
		Lifetime:      leaf.LeafData.Lifetime,
	}

	_, err = aliceGroup.UpdateMember(newLeafNode, nil)
	if err == nil {
		t.Error("UpdateMember should fail with nil private keys")
	}
}

// TestGetMember_Valid verifies that GetMember returns the correct member
func TestGetMember_Valid(t *testing.T) {
	aliceGroup, bobGroup, _, _ := setupTwoMemberGroup(t)

	// Get Alice
	aliceMember, ok := aliceGroup.GetMember(aliceGroup.ownLeafIndex)
	if !ok {
		t.Fatal("GetMember should return true for own leaf")
	}
	if aliceMember == nil {
		t.Fatal("GetMember should return non-nil member")
	}
	if !aliceMember.Active {
		t.Error("Alice member should be active")
	}

	// Get Bob from Alice's perspective
	// Bob should be at index 1 (after the Add + Commit)
	var bobIdx LeafNodeIndex
	for idx := range aliceGroup.members {
		if idx != aliceGroup.ownLeafIndex {
			bobIdx = idx
			break
		}
	}

	bobMember, ok := aliceGroup.GetMember(bobIdx)
	if !ok {
		t.Fatal("GetMember should return true for Bob's leaf")
	}
	if bobMember == nil {
		t.Fatal("GetMember should return non-nil member for Bob")
	}
	if !bobMember.Active {
		t.Error("Bob member should be active")
	}

	// Verify from Bob too
	bobMemberFromBob, ok := bobGroup.GetMember(bobGroup.ownLeafIndex)
	if !ok {
		t.Error("GetMember should return true for own leaf (Bob)")
	}
	if bobMemberFromBob == nil {
		t.Error("GetMember should return non-nil member for Bob (from Bob's group)")
	}
}

// TestGetMember_OutOfRange verifies that GetMember handles out-of-range indices
func TestGetMember_OutOfRange(t *testing.T) {
	aliceGroup, _, _, _ := setupTwoMemberGroup(t)

	// Very large index
	_, ok := aliceGroup.GetMember(9999)
	if ok {
		t.Error("GetMember should return false for out-of-range index")
	}

	// Negative index (converted to large uint32)
	_, ok = aliceGroup.GetMember(LeafNodeIndex(0xFFFFFFFF))
	if ok {
		t.Error("GetMember should return false for invalid index")
	}
}

// TestGetMembers_Count verifies that GetMembers returns the correct count
func TestGetMembers_Count(t *testing.T) {
	aliceGroup, bobGroup, _, _ := setupTwoMemberGroup(t)

	// There should be 2 members
	aliceMembers := aliceGroup.GetMembers()
	if len(aliceMembers) != 2 {
		t.Errorf("GetMembers should return 2 members, got %d", len(aliceMembers))
	}

	bobMembers := bobGroup.GetMembers()
	if len(bobMembers) != 2 {
		t.Errorf("GetMembers should return 2 members (Bob), got %d", len(bobMembers))
	}

	// Verify that all returned members are active
	for _, member := range aliceMembers {
		if !member.Active {
			t.Error("GetMembers should only return active members")
		}
	}
}

// TestValidateAddProposal_DuplicateKey verifies that KeyPackages with same InitKey cannot be added
func TestValidateAddProposal_DuplicateKey(t *testing.T) {
	aliceGroup, _, alicePriv, _ := setupTwoMemberGroup(t)
	aliceSigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)
	aliceSigPub := aliceSigPriv.PublicKey()

	charlieCred, _, err := credentials.GenerateCredentialWithKey([]byte("CharlieDupInitA"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(CharlieDupInitA): %v", err)
	}
	charlieKP, _, err := keypackages.Generate(charlieCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage(CharlieDupInitA): %v", err)
	}

	daveCred, _, err := credentials.GenerateCredentialWithKey([]byte("CharlieDupInitB"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(CharlieDupInitB): %v", err)
	}
	daveKP, _, err := keypackages.Generate(daveCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage(CharlieDupInitB): %v", err)
	}

	// Force the second KeyPackage to reuse the first InitKey.
	daveKP.InitKey = append([]byte(nil), charlieKP.InitKey...)

	if _, err := aliceGroup.AddMember(charlieKP); err != nil {
		t.Fatalf("AddMember(first): %v", err)
	}
	stagedCommit, err := aliceGroup.Commit(aliceSigPriv, aliceSigPub, nil)
	if err != nil {
		t.Fatalf("Commit(first add): %v", err)
	}
	if err := aliceGroup.MergeCommit(stagedCommit); err != nil {
		t.Fatalf("MergeCommit(first add): %v", err)
	}

	if _, err := aliceGroup.AddMember(daveKP); err == nil {
		t.Fatal("AddMember should fail for duplicate InitKey")
	} else if !errors.Is(err, ErrInvalidProposal) {
		t.Fatalf("AddMember error = %v, want ErrInvalidProposal", err)
	}
}

// TestValidateUpdateProposal_InvalidLeafNode verifies that UpdateProposal with invalid LeafNode fails
func TestValidateUpdateProposal_InvalidLeafNode(t *testing.T) {
	aliceGroup, _, _, _ := setupTwoMemberGroup(t)

	// Create UpdateProposal with empty LeafNode (without EncryptionKey)
	invalidLeafNode := &treesync.LeafNodeData{
		EncryptionKey: nil, // This should be invalid
		SignatureKey:  nil,
		Credential:    nil,
	}

	_, err := aliceGroup.UpdateMember(invalidLeafNode, nil)
	if err == nil {
		t.Error("UpdateMember should fail with invalid LeafNode (nil EncryptionKey)")
	}
}

// TestGroupContext_MarshalUnmarshal verifies GroupContext roundtrip
func TestGroupContext_MarshalUnmarshal(t *testing.T) {
	aliceGroup, _, _, _ := setupTwoMemberGroup(t)

	// Marshal
	data := aliceGroup.groupContext.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal should return non-empty data")
	}

	// Unmarshal
	gc2, err := UnmarshalGroupContext(data)
	if err != nil {
		t.Fatalf("UnmarshalGroupContext failed: %v", err)
	}

	// Verify fields
	if !bytes.Equal(gc2.GroupID.AsSlice(), aliceGroup.groupContext.GroupID.AsSlice()) {
		t.Error("GroupID should match after roundtrip")
	}

	if gc2.Epoch != aliceGroup.groupContext.Epoch {
		t.Errorf("Epoch should match: got %d, want %d", gc2.Epoch, aliceGroup.groupContext.Epoch)
	}

	// Verify that the TreeHash is the same
	if !bytes.Equal(gc2.TreeHash, aliceGroup.groupContext.TreeHash) {
		t.Error("TreeHash should match after roundtrip")
	}
}
