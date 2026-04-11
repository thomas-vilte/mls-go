package group

import (
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/treesync"
)

// TestMergeCommit_InvalidSignature verifies that MergeCommit rejects commits with an invalid signature.
// Phase 1.1: signature verification for received commits.
func TestMergeCommit_InvalidSignature(t *testing.T) {
	// Create group with Alice
	aliceCred, _, err := credentials.GenerateCredentialWithKey([]byte("alice"))
	if err != nil {
		t.Fatalf("generating alice credential: %v", err)
	}

	aliceKeyPackage, alicePrivKeys, err := keypackages.Generate(aliceCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating alice key package: %v", err)
	}

	groupID, _ := NewGroupIDRandom()
	aliceGroup, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, aliceKeyPackage, alicePrivKeys)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}

	// Create KeyPackage for Bob
	bobCred, _, err := credentials.GenerateCredentialWithKey([]byte("bob"))
	if err != nil {
		t.Fatalf("generating bob credential: %v", err)
	}

	bobKeyPackage, _, err := keypackages.Generate(bobCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating bob key package: %v", err)
	}

	// Alice creates a commit that adds Bob.
	_, _ = aliceGroup.AddMember(bobKeyPackage)
	sigPriv := ciphersuite.NewSignaturePrivateKey(alicePrivKeys.SignatureKey)
	sigPub := sigPriv.PublicKey()
	stagedCommit, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		t.Fatalf("creating commit: %v", err)
	}

	// Corrupt the signature by flipping one byte.
	if len(stagedCommit.authenticatedContent.Auth.Signature.AsSlice()) > 0 {
		sigBytes := stagedCommit.authenticatedContent.Auth.Signature.AsSlice()
		sigBytes[0] ^= 0xFF
	}

	// MergeCommit must fail because the signature is invalid.
	err = aliceGroup.MergeCommit(stagedCommit)
	if err == nil {
		t.Error("MergeCommit should fail with invalid signature")
	}
}

// TestMergeCommit_WrongSigner verifies that MergeCommit rejects commits signed by the wrong member.
func TestMergeCommit_WrongSigner(t *testing.T) {
	// Create group with Alice
	aliceCred, _, err := credentials.GenerateCredentialWithKey([]byte("alice"))
	if err != nil {
		t.Fatalf("generating alice credential: %v", err)
	}

	aliceKeyPackage, alicePrivKeys, err := keypackages.Generate(aliceCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating alice key package: %v", err)
	}

	groupID, _ := NewGroupIDRandom()
	aliceGroup, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, aliceKeyPackage, alicePrivKeys)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}

	// Create KeyPackage for Bob
	bobCred, _, err := credentials.GenerateCredentialWithKey([]byte("bob"))
	if err != nil {
		t.Fatalf("generating bob credential: %v", err)
	}

	bobKeyPackage, bobPrivKeys, err := keypackages.Generate(bobCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating bob key package: %v", err)
	}

	// Alice adds Bob.
	_, _ = aliceGroup.AddMember(bobKeyPackage)
	sigPriv := ciphersuite.NewSignaturePrivateKey(alicePrivKeys.SignatureKey)
	sigPub := sigPriv.PublicKey()
	stagedCommit, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		t.Fatalf("creating commit: %v", err)
	}

	if err := aliceGroup.MergeCommit(stagedCommit); err != nil {
		t.Fatalf("merging commit: %v", err)
	}

	// Bob is now a member. Create a commit signed by Bob but claiming sender = Alice (0).
	charlieCred, _, err := credentials.GenerateCredentialWithKey([]byte("charlie"))
	if err != nil {
		t.Fatalf("generating charlie credential: %v", err)
	}

	charlieKeyPackage, _, err := keypackages.Generate(charlieCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating charlie key package: %v", err)
	}

	// Bob creates a commit. The sender is Bob.
	_, _ = aliceGroup.AddMember(charlieKeyPackage)
	bobSigPriv := ciphersuite.NewSignaturePrivateKey(bobPrivKeys.SignatureKey)
	bobSigPub := bobSigPriv.PublicKey()
	stagedCommit2, err := aliceGroup.Commit(bobSigPriv, bobSigPub, nil)
	if err != nil {
		t.Fatalf("creating commit: %v", err)
	}

	// RFC §12.4.1: Validate GroupID and epoch before any costly work.
	// This must fail signature verification.
	stagedCommit2.authenticatedContent.Content.Sender.LeafIndex = 0

	// MergeCommit must fail because the signature does not match the sender.
	err = aliceGroup.MergeCommit(stagedCommit2)
	if err == nil {
		t.Error("MergeCommit should fail with wrong signer")
	}
}

// TestMergeCommit_EpochMismatch verifies that MergeCommit rejects commits with the wrong epoch.
func TestMergeCommit_EpochMismatch(t *testing.T) {
	// Create group with Alice
	aliceCred, _, err := credentials.GenerateCredentialWithKey([]byte("alice"))
	if err != nil {
		t.Fatalf("generating alice credential: %v", err)
	}

	aliceKeyPackage, alicePrivKeys, err := keypackages.Generate(aliceCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating alice key package: %v", err)
	}

	groupID, _ := NewGroupIDRandom()
	aliceGroup, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, aliceKeyPackage, alicePrivKeys)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}

	// Create KeyPackage for Bob
	bobCred, _, err := credentials.GenerateCredentialWithKey([]byte("bob"))
	if err != nil {
		t.Fatalf("generating bob credential: %v", err)
	}

	bobKeyPackage, _, err := keypackages.Generate(bobCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating bob key package: %v", err)
	}

	// Alice creates a commit that adds Bob.
	_, _ = aliceGroup.AddMember(bobKeyPackage)
	sigPriv := ciphersuite.NewSignaturePrivateKey(alicePrivKeys.SignatureKey)
	sigPub := sigPriv.PublicKey()
	stagedCommit, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		t.Fatalf("creating commit: %v", err)
	}

	// Save the current epoch.
	currentEpoch := aliceGroup.groupContext.Epoch.AsUint64()

	// Case 1: commit with a future epoch (current + 1).
	stagedCommit.authenticatedContent.Content.Epoch = currentEpoch + 1
	err = aliceGroup.MergeCommit(stagedCommit)
	if err == nil {
		t.Error("MergeCommit should fail with future epoch")
	}

	// Case 2: commit with a past epoch (current - 1, replay simulation).
	stagedCommit.authenticatedContent.Content.Epoch = currentEpoch - 1
	err = aliceGroup.MergeCommit(stagedCommit)
	if err == nil {
		t.Error("MergeCommit should fail with past epoch (replay)")
	}

	// Case 3: a commit with the correct epoch must succeed.
	stagedCommit.authenticatedContent.Content.Epoch = currentEpoch
	err = aliceGroup.MergeCommit(stagedCommit)
	if err != nil {
		t.Errorf("MergeCommit should succeed with correct epoch: %v", err)
	}
}

// TestMergeCommit_WrongGroupID verifies that MergeCommit rejects commits with the wrong GroupID.
func TestMergeCommit_WrongGroupID(t *testing.T) {
	// Create group with Alice
	aliceCred, _, err := credentials.GenerateCredentialWithKey([]byte("alice"))
	if err != nil {
		t.Fatalf("generating alice credential: %v", err)
	}

	aliceKeyPackage, alicePrivKeys, err := keypackages.Generate(aliceCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating alice key package: %v", err)
	}

	groupID, _ := NewGroupIDRandom()
	aliceGroup, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, aliceKeyPackage, alicePrivKeys)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}

	// Create KeyPackage for Bob
	bobCred, _, err := credentials.GenerateCredentialWithKey([]byte("bob"))
	if err != nil {
		t.Fatalf("generating bob credential: %v", err)
	}

	bobKeyPackage, _, err := keypackages.Generate(bobCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating bob key package: %v", err)
	}

	// Alice creates a commit that adds Bob.
	_, _ = aliceGroup.AddMember(bobKeyPackage)
	sigPriv := ciphersuite.NewSignaturePrivateKey(alicePrivKeys.SignatureKey)
	sigPub := sigPriv.PublicKey()
	stagedCommit, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		t.Fatalf("creating commit: %v", err)
	}

	// change GroupID
	stagedCommit.authenticatedContent.Content.GroupID = []byte("wrong-group")

	// MergeCommit must fail because the GroupID is wrong.
	err = aliceGroup.MergeCommit(stagedCommit)
	if err == nil {
		t.Error("MergeCommit should fail with wrong GroupID")
	}
}

// TestProcessReceivedCommit_WrongGroupID verifies that ProcessReceivedCommit rejects commits with the wrong GroupID.
func TestProcessReceivedCommit_WrongGroupID(t *testing.T) {
	// Create group with Alice
	aliceCred, _, err := credentials.GenerateCredentialWithKey([]byte("alice"))
	if err != nil {
		t.Fatalf("generating alice credential: %v", err)
	}

	aliceKeyPackage, alicePrivKeys, err := keypackages.Generate(aliceCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating alice key package: %v", err)
	}

	groupID, _ := NewGroupIDRandom()
	aliceGroup, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, aliceKeyPackage, alicePrivKeys)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}

	// Create KeyPackage for Bob
	bobCred, _, err := credentials.GenerateCredentialWithKey([]byte("bob"))
	if err != nil {
		t.Fatalf("generating bob credential: %v", err)
	}

	bobKeyPackage, bobPrivKeys, err := keypackages.Generate(bobCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating bob key package: %v", err)
	}

	// Alice adds Bob.
	_, _ = aliceGroup.AddMember(bobKeyPackage)
	sigPriv := ciphersuite.NewSignaturePrivateKey(alicePrivKeys.SignatureKey)
	sigPub := sigPriv.PublicKey()
	stagedCommit, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		t.Fatalf("creating commit: %v", err)
	}

	if err := aliceGroup.MergeCommit(stagedCommit); err != nil {
		t.Fatalf("merging commit: %v", err)
	}

	// Create other group (simulate cross-group attack)
	otherCred, _, err := credentials.GenerateCredentialWithKey([]byte("other"))
	if err != nil {
		t.Fatalf("generating other credential: %v", err)
	}

	otherKeyPackage, otherPrivKeys, err := keypackages.Generate(otherCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating other key package: %v", err)
	}

	otherGroupID, _ := NewGroupIDRandom()
	otherGroup, err := NewGroup(otherGroupID, ciphersuite.MLS128DHKEMP256, otherKeyPackage, otherPrivKeys)
	if err != nil {
		t.Fatalf("creating other group: %v", err)
	}

	// Create commit en other-group
	charlieCred, _, err := credentials.GenerateCredentialWithKey([]byte("charlie"))
	if err != nil {
		t.Fatalf("generating charlie credential: %v", err)
	}

	charlieKeyPackage, _, err := keypackages.Generate(charlieCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating charlie key package: %v", err)
	}

	_, _ = otherGroup.AddMember(charlieKeyPackage)
	otherSigPriv := ciphersuite.NewSignaturePrivateKey(otherPrivKeys.SignatureKey)
	otherSigPub := otherSigPriv.PublicKey()
	stagedCommit2, err := otherGroup.Commit(otherSigPriv, otherSigPub, nil)
	if err != nil {
		t.Fatalf("creating commit in other group: %v", err)
	}

	// Processing the other-group commit in aliceGroup must fail.
	err = aliceGroup.ProcessReceivedCommit(
		stagedCommit2.authenticatedContent,
		treesync.LeafIndex(aliceGroup.ownLeafIndex),
		bobPrivKeys.InitKey.Bytes(),
	)
	if err == nil {
		t.Error("ProcessReceivedCommit should fail with wrong GroupID")
	}
}

// TestProcessReceivedCommit_EpochMismatch verifies that ProcessReceivedCommit rejects commits with the wrong epoch.
func TestProcessReceivedCommit_EpochMismatch(t *testing.T) {
	// Create group with Alice
	aliceCred, _, err := credentials.GenerateCredentialWithKey([]byte("alice"))
	if err != nil {
		t.Fatalf("generating alice credential: %v", err)
	}

	aliceKeyPackage, alicePrivKeys, err := keypackages.Generate(aliceCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating alice key package: %v", err)
	}

	groupID, _ := NewGroupIDRandom()
	aliceGroup, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, aliceKeyPackage, alicePrivKeys)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}

	// Create KeyPackage for Bob
	bobCred, _, err := credentials.GenerateCredentialWithKey([]byte("bob"))
	if err != nil {
		t.Fatalf("generating bob credential: %v", err)
	}

	bobKeyPackage, bobPrivKeys, err := keypackages.Generate(bobCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating bob key package: %v", err)
	}

	// Alice adds Bob.
	_, _ = aliceGroup.AddMember(bobKeyPackage)
	sigPriv := ciphersuite.NewSignaturePrivateKey(alicePrivKeys.SignatureKey)
	sigPub := sigPriv.PublicKey()
	stagedCommit, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		t.Fatalf("creating commit: %v", err)
	}

	if err := aliceGroup.MergeCommit(stagedCommit); err != nil {
		t.Fatalf("merging commit: %v", err)
	}

	// Bob now processes a commit with the wrong epoch.
	// Create a commit with a future epoch.
	charlieCred, _, err := credentials.GenerateCredentialWithKey([]byte("charlie"))
	if err != nil {
		t.Fatalf("generating charlie credential: %v", err)
	}

	charlieKeyPackage, _, err := keypackages.Generate(charlieCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating charlie key package: %v", err)
	}

	_, _ = aliceGroup.AddMember(charlieKeyPackage)
	sigPriv2 := ciphersuite.NewSignaturePrivateKey(alicePrivKeys.SignatureKey)
	sigPub2 := sigPriv2.PublicKey()
	stagedCommit2, err := aliceGroup.Commit(sigPriv2, sigPub2, nil)
	if err != nil {
		t.Fatalf("creating second commit: %v", err)
	}

	// Corrupt the epoch.
	stagedCommit2.authenticatedContent.Content.Epoch = 999

	// Bob processing the commit must fail because of the epoch.
	err = aliceGroup.ProcessReceivedCommit(
		stagedCommit2.authenticatedContent,
		treesync.LeafIndex(aliceGroup.ownLeafIndex),
		bobPrivKeys.InitKey.Bytes(),
	)
	if err == nil {
		t.Error("ProcessReceivedCommit should fail with wrong epoch")
	}

	var epochErr *ErrEpochMismatch
	if !errors.As(err, &epochErr) {
		t.Fatalf("ProcessReceivedCommit error = %v, want ErrEpochMismatch", err)
	}
	if epochErr.Got != 999 {
		t.Fatalf("ErrEpochMismatch.Got = %d, want 999", epochErr.Got)
	}
	if epochErr.Want != aliceGroup.groupContext.Epoch.AsUint64() {
		t.Fatalf("ErrEpochMismatch.Want = %d, want %d", epochErr.Want, aliceGroup.groupContext.Epoch.AsUint64())
	}
}
