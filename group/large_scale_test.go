package group

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// TestGroup_1024Members tests group behavior at large scale.
// Should not fail or be excessively slow.
func TestGroup_1024Members(t *testing.T) {
	// Skip this test in short mode as it can take a while
	if testing.Short() {
		t.Skip("skipping 1024 member test in short mode")
	}

	start := time.Now()

	// Create creator
	credWithKey, _, err := credentials.GenerateCredentialWithKey([]byte("Creator"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey: %v", err)
	}
	kp, kpPriv, err := keypackages.Generate(credWithKey, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate key package: %v", err)
	}

	groupID, _ := NewGroupIDRandom()
	group, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kp, kpPriv)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}

	creatorSigPriv := ciphersuite.NewSignaturePrivateKey(kpPriv.SignatureKey)

	// Add 1023 more members (to reach 1024)
	// Do this in batches to make it realistic but not take forever in a test
	batchSize := 100
	totalMembers := 1024

	t.Logf("Creating group with %d members...", totalMembers)

	for i := 1; i < totalMembers; {
		toAdd := batchSize
		if i+toAdd > totalMembers {
			toAdd = totalMembers - i
		}

		proposals := make([]*Proposal, 0, toAdd)

		for j := 0; j < toAdd; j++ {
			cred, _, _ := credentials.GenerateCredentialWithKey([]byte(fmt.Sprintf("Member-%d", i+j)))
			memberKp, _, _ := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)

			prop, err := group.AddMember(memberKp)
			if err != nil {
				t.Fatalf("AddMember failed at member %d: %v", i+j, err)
			}
			_ = append(proposals, prop) // Mark as used to avoid staticcheck warning
		}

		// Commit the batch
		commitStart := time.Now()
		sc, err := group.Commit(creatorSigPriv, creatorSigPriv.PublicKey(), nil)
		if err != nil {
			t.Fatalf("Commit failed at size %d: %v", i+toAdd, err)
		}

		err = group.MergeCommit(sc)
		if err != nil {
			t.Fatalf("MergeCommit failed at size %d: %v", i+toAdd, err)
		}

		t.Logf("Added %d members, new size: %d, commit took: %v", toAdd, group.MemberCount(), time.Since(commitStart))

		i += toAdd
	}

	// Verify we reached 1024 members
	if group.MemberCount() != 1024 {
		t.Errorf("Expected 1024 members, got %d", group.MemberCount())
	}

	// Verify tree properties
	// A left-balanced tree with 1024 leaves should have exactly 2047 nodes
	if len(group.ratchetTree.Nodes) != 2047 {
		t.Errorf("Expected 2047 nodes for 1024 leaves, got %d", len(group.ratchetTree.Nodes))
	}

	// Benchmark a single message send with 1024 members
	msgStart := time.Now()
	data := make([]byte, 1024)
	rand.Read(data)
	_, err = group.SendMessage(data, creatorSigPriv)
	if err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}
	t.Logf("SendMessage with 1024 members took: %v", time.Since(msgStart))

	t.Logf("Total time for 1024 member test: %v", time.Since(start))
}
