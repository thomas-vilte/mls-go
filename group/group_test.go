package group

import (
	"testing"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/credentials"
	"github.com/openmls/go/framing"
	keypackages "github.com/openmls/go/keypackages"
	"github.com/openmls/go/treesync"
)

func TestGroupCreation(t *testing.T) {
	// Create a KeyPackage
	credWithKey, _, err := credentials.GenerateCredentialWithKey([]byte("TestUser"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}

	keyPackage, kpPrivKeys, err := keypackages.Generate(credWithKey, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage failed: %v", err)
	}

	// Create group
	groupID, err := NewGroupIDRandom()
	if err != nil {
		t.Fatalf("NewGroupIDRandom failed: %v", err)
	}

	group, err := NewGroup(
		groupID,
		ciphersuite.MLS128DHKEMP256,
		keyPackage,
		kpPrivKeys,
	)
	if err != nil {
		t.Fatalf("NewGroup failed: %v", err)
	}

	// Verify group state
	if group.GroupID == nil {
		t.Error("GroupID should not be nil")
	}
	if group.Epoch.AsUint64() != 0 {
		t.Errorf("Epoch should be 0, got %d", group.Epoch.AsUint64())
	}
	if group.RatchetTree == nil {
		t.Error("RatchetTree should not be nil")
	}
	if group.EpochSecrets == nil {
		t.Error("EpochSecrets should not be nil")
	}
	if group.MemberCount() != 1 {
		t.Errorf("Should have 1 member, got %d", group.MemberCount())
	}
}

func TestGroupAddMember(t *testing.T) {
	// Create initial group
	credWithKey, _, err := credentials.GenerateCredentialWithKey([]byte("Creator"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}

	keyPackage, kpPrivKeys, err := keypackages.Generate(credWithKey, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage failed: %v", err)
	}

	groupID, _ := NewGroupIDRandom()
	group, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, keyPackage, kpPrivKeys)
	if err != nil {
		t.Fatalf("NewGroup failed: %v", err)
	}

	// Create new member's KeyPackage
	newCred, _, err := credentials.GenerateCredentialWithKey([]byte("NewMember"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}

	newKeyPackage, _, err := keypackages.Generate(newCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage failed: %v", err)
	}

	// Add member
	proposal, err := group.AddMember(newKeyPackage)
	if err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}

	//nolint:staticcheck // nil check is necessary here
	if proposal == nil {
		t.Error("Proposal should not be nil")
	}
	//nolint:staticcheck // proposal is guaranteed non-nil after check above
	if proposal.Type != ProposalTypeAdd {
		t.Errorf("Proposal type should be Add, got %d", proposal.Type)
	}

	// Verify proposal was stored
	if len(group.Proposals.Proposals) != 1 {
		t.Errorf("Should have 1 proposal, got %d", len(group.Proposals.Proposals))
	}
}

func TestGroupRemoveMember(t *testing.T) {
	// Create initial group
	credWithKey, _, err := credentials.GenerateCredentialWithKey([]byte("Creator"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}

	keyPackage, kpPrivKeys, err := keypackages.Generate(credWithKey, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage failed: %v", err)
	}

	groupID, _ := NewGroupIDRandom()
	group, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, keyPackage, kpPrivKeys)
	if err != nil {
		t.Fatalf("NewGroup failed: %v", err)
	}

	// Remove member (leaf 0)
	proposal, err := group.RemoveMember(NewLeafNodeIndex(0))
	if err != nil {
		t.Fatalf("RemoveMember failed: %v", err)
	}

	//nolint:staticcheck // nil check is necessary here
	if proposal == nil {
		t.Error("Proposal should not be nil")
	}
	//nolint:staticcheck // proposal is guaranteed non-nil after check above
	if proposal.Type != ProposalTypeRemove {
		t.Errorf("Proposal type should be Remove, got %d", proposal.Type)
	}
}

func TestGroupCommit(t *testing.T) {
	// Create initial group
	credWithKey, _, err := credentials.GenerateCredentialWithKey([]byte("Creator"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}

	keyPackage, kpPrivKeys, err := keypackages.Generate(credWithKey, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage failed: %v", err)
	}

	groupID, _ := NewGroupIDRandom()
	group, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, keyPackage, kpPrivKeys)
	if err != nil {
		t.Fatalf("NewGroup failed: %v", err)
	}

	// Add a proposal
	newCred, _, _ := credentials.GenerateCredentialWithKey([]byte("NewMember"))
	newKeyPackage, _, _ := keypackages.Generate(newCred, keypackages.MLS128DHKEMP256)
	_, _ = group.AddMember(newKeyPackage)

	// Commit
	sigPriv := ciphersuite.NewSignaturePrivateKey(kpPrivKeys.SignatureKey)
	sigPub := sigPriv.PublicKey()
	stagedCommit, err := group.Commit(sigPriv, sigPub, nil)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	if stagedCommit == nil {
		t.Error("StagedCommit should not be nil")
	}
	if group.State() != StatePendingCommit {
		t.Errorf("Group state should be StatePendingCommit, got %d", group.State())
	}

	// Merge commit
	err = group.MergeCommit(stagedCommit)
	if err != nil {
		t.Fatalf("MergeCommit failed: %v", err)
	}

	if group.State() != StateOperational {
		t.Errorf("Group state should be StateOperational, got %d", group.State())
	}
	if group.Epoch.AsUint64() != 1 {
		t.Errorf("Epoch should be 1 after commit, got %d", group.Epoch.AsUint64())
	}
}

func TestProposalStore(t *testing.T) {
	ps := NewProposalStore()

	if ps == nil {
		t.Fatal("NewProposalStore returned nil")
	}

	// Add proposal
	proposal := &Proposal{Type: ProposalTypeAdd}
	ps.AddProposal(proposal, NewLeafNodeIndex(0))

	if len(ps.Proposals) != 1 {
		t.Errorf("Should have 1 proposal, got %d", len(ps.Proposals))
	}

	// Clear
	ps.Clear()

	if len(ps.Proposals) != 0 {
		t.Errorf("Should have 0 proposals after clear, got %d", len(ps.Proposals))
	}
}

func TestGroupState(t *testing.T) {
	// Create initial group
	credWithKey, _, err := credentials.GenerateCredentialWithKey([]byte("Creator"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}

	keyPackage, kpPrivKeys, err := keypackages.Generate(credWithKey, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage failed: %v", err)
	}

	groupID, _ := NewGroupIDRandom()
	group, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, keyPackage, kpPrivKeys)
	if err != nil {
		t.Fatalf("NewGroup failed: %v", err)
	}

	// Verify initial state
	if group.State() != StateOperational {
		t.Errorf("Initial state should be StateOperational, got %d", group.State())
	}

	// Create commit to change state
	newCred, _, _ := credentials.GenerateCredentialWithKey([]byte("NewMember"))
	newKeyPackage, _, _ := keypackages.Generate(newCred, keypackages.MLS128DHKEMP256)
	_, _ = group.AddMember(newKeyPackage)
	sigPriv := ciphersuite.NewSignaturePrivateKey(kpPrivKeys.SignatureKey)
	sigPub := sigPriv.PublicKey()
	_, _ = group.Commit(sigPriv, sigPub, nil)

	if group.State() != StatePendingCommit {
		t.Errorf("State should be StatePendingCommit, got %d", group.State())
	}
}

func TestProcessPublicMessage_StoresProposal(t *testing.T) {
	credWithKey, _, err := credentials.GenerateCredentialWithKey([]byte("Creator"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}

	keyPackage, kpPrivKeys, err := keypackages.Generate(credWithKey, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage failed: %v", err)
	}

	groupID, _ := NewGroupIDRandom()
	group, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, keyPackage, kpPrivKeys)
	if err != nil {
		t.Fatalf("NewGroup failed: %v", err)
	}

	proposal := NewRemoveProposal(group.OwnLeafIndex)
	pmContent := framing.FramedContent{
		GroupID: group.GroupID.AsSlice(),
		Epoch:   group.Epoch.AsUint64(),
		Sender:  framing.Sender{Type: framing.SenderTypeMember, LeafIndex: uint32(group.OwnLeafIndex)},
		Body:    framing.ProposalBody{Data: ProposalMarshal(proposal)},
	}

	sigPriv := ciphersuite.NewSignaturePrivateKey(kpPrivKeys.SignatureKey)
	pm, err := framing.NewPublicMessage(
		pmContent,
		sigPriv,
		group.GroupContext.Marshal(),
		group.EpochSecrets.MembershipKey,
		group.CipherSuite,
	)
	if err != nil {
		t.Fatalf("NewPublicMessage failed: %v", err)
	}

	if err := group.ProcessPublicMessage(pm); err != nil {
		t.Fatalf("ProcessPublicMessage failed: %v", err)
	}

	if len(group.Proposals.Proposals) != 1 {
		t.Fatalf("stored proposals = %d, want 1", len(group.Proposals.Proposals))
	}
}

func TestProcessPublicMessage_RejectsCommitWithPath(t *testing.T) {
	credWithKey, _, err := credentials.GenerateCredentialWithKey([]byte("Creator"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}

	keyPackage, kpPrivKeys, err := keypackages.Generate(credWithKey, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage failed: %v", err)
	}

	groupID, _ := NewGroupIDRandom()
	group, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, keyPackage, kpPrivKeys)
	if err != nil {
		t.Fatalf("NewGroup failed: %v", err)
	}

	pmContent := framing.FramedContent{
		GroupID: group.GroupID.AsSlice(),
		Epoch:   group.Epoch.AsUint64(),
		Sender:  framing.Sender{Type: framing.SenderTypeMember, LeafIndex: uint32(group.OwnLeafIndex)},
		Body: framing.CommitBody{Data: (&Commit{
			Path: &UpdatePath{LeafNode: &treesync.LeafNodeData{
				EncryptionKey:  []byte{1},
				SignatureKey:   keyPackage.LeafNode.SignatureKey,
				Credential:     keyPackage.LeafNode.Credential,
				Capabilities:   &treesync.LeafNodeCapabilities{},
				Lifetime:       &treesync.LeafNodeLifetime{},
				LeafNodeSource: 3,
				Signature:      []byte{1},
			}},
		}).Marshal()},
	}

	sigPriv := ciphersuite.NewSignaturePrivateKey(kpPrivKeys.SignatureKey)
	pm, err := framing.NewPublicMessage(
		pmContent,
		sigPriv,
		group.GroupContext.Marshal(),
		group.EpochSecrets.MembershipKey,
		group.CipherSuite,
	)
	if err != nil {
		t.Fatalf("NewPublicMessage failed: %v", err)
	}

	err = group.ProcessPublicMessage(pm)
	if err == nil {
		t.Fatal("expected error for commit with path")
	}
}
