package group

import (
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/treesync"
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
	if group.groupID == nil {
		t.Error("GroupID should not be nil")
	}
	if group.epoch.AsUint64() != 0 {
		t.Errorf("Epoch should be 0, got %d", group.epoch.AsUint64())
	}
	if group.ratchetTree == nil {
		t.Error("RatchetTree should not be nil")
	}
	if group.epochSecrets == nil {
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
	if len(group.proposals.Proposals) != 1 {
		t.Errorf("Should have 1 proposal, got %d", len(group.proposals.Proposals))
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
	if group.epoch.AsUint64() != 1 {
		t.Errorf("Epoch should be 1 after commit, got %d", group.epoch.AsUint64())
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

	proposal := NewRemoveProposal(group.ownLeafIndex)
	pmContent := framing.FramedContent{
		GroupID: group.groupID.AsSlice(),
		Epoch:   group.epoch.AsUint64(),
		Sender:  framing.Sender{Type: framing.SenderTypeMember, LeafIndex: uint32(group.ownLeafIndex)},
		Body:    framing.ProposalBody{Data: ProposalMarshal(proposal)},
	}

	sigPriv := ciphersuite.NewSignaturePrivateKey(kpPrivKeys.SignatureKey)
	pm, err := framing.NewPublicMessage(
		pmContent,
		sigPriv,
		group.groupContext.Marshal(),
		group.epochSecrets.MembershipKey,
		group.cipherSuite,
	)
	if err != nil {
		t.Fatalf("NewPublicMessage failed: %v", err)
	}

	if err := group.ProcessPublicMessage(pm); err != nil {
		t.Fatalf("ProcessPublicMessage failed: %v", err)
	}

	if len(group.proposals.Proposals) != 1 {
		t.Fatalf("stored proposals = %d, want 1", len(group.proposals.Proposals))
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
		GroupID: group.groupID.AsSlice(),
		Epoch:   group.epoch.AsUint64(),
		Sender:  framing.Sender{Type: framing.SenderTypeMember, LeafIndex: uint32(group.ownLeafIndex)},
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
		group.groupContext.Marshal(),
		group.epochSecrets.MembershipKey,
		group.cipherSuite,
	)
	if err != nil {
		t.Fatalf("NewPublicMessage failed: %v", err)
	}

	err = group.ProcessPublicMessage(pm)
	if err == nil {
		t.Fatal("expected error for commit with path")
	}
}

// TestProcessPrivateMessage_Proposal tests processing a proposal sent as PrivateMessage.
func TestProcessPrivateMessage_Proposal(t *testing.T) {
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

	// Create Remove proposal (simpler than Add for testing)
	removeProposal := NewRemoveProposal(group.ownLeafIndex)

	// Encrypt proposal as PrivateMessage
	sigPrivKey := ciphersuite.NewSignaturePrivateKey(kpPrivKeys.SignatureKey)
	content := framing.FramedContent{
		GroupID:           group.groupID.AsSlice(),
		Epoch:             group.epoch.AsUint64(),
		Sender:            framing.Sender{Type: framing.SenderTypeMember, LeafIndex: uint32(group.ownLeafIndex)},
		AuthenticatedData: []byte{},
		Body:              framing.ProposalBody{Data: ProposalMarshal(removeProposal)},
	}

	pm, err := framing.Encrypt(framing.EncryptParams{
		Content:          content,
		SenderLeafIndex:  uint32(group.ownLeafIndex),
		CipherSuite:      group.cipherSuite,
		PaddingSize:      0,
		SenderDataSecret: group.epochSecrets.SenderDataSecret,
		SecretTree:       group.secretTree,
		SigKey:           sigPrivKey,
		GroupContext:     group.groupContext.Marshal(),
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Process the PrivateMessage
	if err := group.ProcessPrivateMessage(pm); err != nil {
		t.Fatalf("ProcessPrivateMessage failed: %v", err)
	}

	// Verify proposal was stored
	if len(group.proposals.Proposals) == 0 {
		t.Error("proposal was not stored")
	}
}

// TestProcessPrivateMessage_AddProposal tests processing an Add proposal sent as PrivateMessage.
// This test verifies that ProcessPrivateMessage can handle complex proposals like Add.
func TestProcessPrivateMessage_AddProposal(t *testing.T) {
	// Skip this test for now - there's a known issue with Add proposal parsing in PrivateMessage
	// The issue is in the proposal body decoder for Add proposals which fails to correctly
	// determine the body boundaries when the KeyPackage is large.
	// t.Skip()

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

	// Create a new member to add
	newCred, _, err := credentials.GenerateCredentialWithKey([]byte("NewMember"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}
	newKp, _, err := keypackages.Generate(newCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage failed: %v", err)
	}

	// Create Add proposal
	addProposal := NewAddProposal(newKp)

	// Encrypt proposal as PrivateMessage
	sigPrivKey := ciphersuite.NewSignaturePrivateKey(kpPrivKeys.SignatureKey)
	content := framing.FramedContent{
		GroupID:           group.groupID.AsSlice(),
		Epoch:             group.epoch.AsUint64(),
		Sender:            framing.Sender{Type: framing.SenderTypeMember, LeafIndex: uint32(group.ownLeafIndex)},
		AuthenticatedData: []byte{},
		Body:              framing.ProposalBody{Data: ProposalMarshal(addProposal)},
	}

	pm, err := framing.Encrypt(framing.EncryptParams{
		Content:          content,
		SenderLeafIndex:  uint32(group.ownLeafIndex),
		CipherSuite:      group.cipherSuite,
		PaddingSize:      0,
		SenderDataSecret: group.epochSecrets.SenderDataSecret,
		SecretTree:       group.secretTree,
		SigKey:           sigPrivKey,
		GroupContext:     group.groupContext.Marshal(),
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Process the PrivateMessage
	if err := group.ProcessPrivateMessage(pm); err != nil {
		t.Fatalf("ProcessPrivateMessage failed: %v", err)
	}

	// Verify proposal was stored
	if len(group.proposals.Proposals) == 0 {
		t.Error("proposal was not stored")
	}
}

// TestProcessPrivateMessage_Commit verifies that un commit enviado como PrivateMessage
// es procesado correctamente: el receptor descifra, verifica la firma, aplica el commit
// y avanza al siguiente epoch.
func TestProcessPrivateMessage_Commit(t *testing.T) {
	aliceGroup, bobGroup, alice, _ := makeTwoMemberGroups(t)

	// Alice agrega a charlie para que haya un UpdatePath no trivial.
	charlie := newTestUser(t, "charlie-pm-commit")
	if _, err := aliceGroup.AddMember(charlie.kp); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	// Alice crea el commit en epoch 1.
	sc, err := aliceGroup.CommitWithFormat(alice.sigPriv, alice.sigPub, nil, framing.WireFormatPrivateMessage)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Cifrar el commit como PrivateMessage usando los secrets de epoch 1 de alice.
	// Tanto alice como bob comparten los sames EpochSecrets y SecretTree (ver makeTwoMemberGroups).
	pm, err := framing.Encrypt(framing.EncryptParams{
		AuthContent:      sc.authenticatedContent,
		SenderLeafIndex:  uint32(aliceGroup.ownLeafIndex),
		CipherSuite:      aliceGroup.cipherSuite,
		PaddingSize:      0,
		SenderDataSecret: aliceGroup.epochSecrets.SenderDataSecret,
		SecretTree:       aliceGroup.secretTree,
	})
	if err != nil {
		t.Fatalf("Encrypt commit as PrivateMessage: %v", err)
	}

	// Alice mergea su propio commit → epoch 2.
	if err := aliceGroup.MergeCommit(sc); err != nil {
		t.Fatalf("MergeCommit(alice): %v", err)
	}
	if aliceGroup.epoch.AsUint64() != 2 {
		t.Fatalf("alice epoch = %d, want 2", aliceGroup.epoch.AsUint64())
	}

	// Bob procesa el commit via PrivateMessage → también debe avanzar a epoch 2.
	if err := bobGroup.ProcessPrivateMessage(pm); err != nil {
		t.Fatalf("ProcessPrivateMessage(bob): %v", err)
	}
	if bobGroup.epoch.AsUint64() != 2 {
		t.Fatalf("bob epoch = %d, want 2", bobGroup.epoch.AsUint64())
	}
}

// TestProcessPrivateMessage_WrongEpoch verifies that mensajes de otra época son rechazados.
func TestProcessPrivateMessage_WrongEpoch(t *testing.T) {
	aliceGroup, _, alice, _ := makeTwoMemberGroups(t)

	// Create un mensaje válido en epoch 1, pero luego falsificar la época en el wire.
	content := framing.FramedContent{
		GroupID:           aliceGroup.groupID.AsSlice(),
		Epoch:             aliceGroup.epoch.AsUint64(),
		Sender:            framing.Sender{Type: framing.SenderTypeMember, LeafIndex: uint32(aliceGroup.ownLeafIndex)},
		AuthenticatedData: []byte{},
		Body:              framing.ProposalBody{Data: ProposalMarshal(NewRemoveProposal(aliceGroup.ownLeafIndex))},
	}
	pm, err := framing.Encrypt(framing.EncryptParams{
		Content:          content,
		SenderLeafIndex:  uint32(aliceGroup.ownLeafIndex),
		CipherSuite:      aliceGroup.cipherSuite,
		PaddingSize:      0,
		SenderDataSecret: aliceGroup.epochSecrets.SenderDataSecret,
		SecretTree:       aliceGroup.secretTree,
		SigKey:           alice.sigPriv,
		GroupContext:     aliceGroup.groupContext.Marshal(),
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Alterar la época en los fields en claro del PrivateMessage.
	pm.Epoch = 99

	if err := aliceGroup.ProcessPrivateMessage(pm); err == nil {
		t.Fatal("expected error for wrong epoch, got nil")
	}
}

// TestProcessPrivateMessage_InvalidSignature verifies that mensajes con firma inválida
// son rechazados. El contenido se cifra con una clave de firma diferente a la del sender
// en el árbol, por lo que la verificación de FramedContentTBS fails.
func TestProcessPrivateMessage_InvalidSignature(t *testing.T) {
	aliceGroup, bobGroup, _, _ := makeTwoMemberGroups(t)

	// Create una clave de firma impostora (no corresponde a ningún miembro del árbol).
	impostor := newTestUser(t, "impostor")

	// Create un proposal desde el punto de vista de alice (leaf 0), pero firmado
	// con la clave del impostor. El árbol de bob tiene la clave pública de alice
	// en leaf 0, por lo que la verificación failsrá.
	content := framing.FramedContent{
		GroupID:           bobGroup.groupID.AsSlice(),
		Epoch:             bobGroup.epoch.AsUint64(),
		Sender:            framing.Sender{Type: framing.SenderTypeMember, LeafIndex: uint32(aliceGroup.ownLeafIndex)},
		AuthenticatedData: []byte{},
		Body:              framing.ProposalBody{Data: ProposalMarshal(NewRemoveProposal(aliceGroup.ownLeafIndex))},
	}
	pm, err := framing.Encrypt(framing.EncryptParams{
		Content:          content,
		SenderLeafIndex:  uint32(aliceGroup.ownLeafIndex),
		CipherSuite:      bobGroup.cipherSuite,
		PaddingSize:      0,
		SenderDataSecret: bobGroup.epochSecrets.SenderDataSecret,
		SecretTree:       bobGroup.secretTree,
		SigKey:           impostor.sigPriv, // firma inválida
		GroupContext:     bobGroup.groupContext.Marshal(),
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if err := bobGroup.ProcessPrivateMessage(pm); err == nil {
		t.Fatal("expected signature verification failure, got nil")
	}
}

// TestProcessPrivateMessage_NilMessage tests that nil message returns error.
func TestProcessPrivateMessage_NilMessage(t *testing.T) {
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

	if err := group.ProcessPrivateMessage(nil); err == nil {
		t.Error("expected error for nil message")
	}
}

// TestProcessPrivateMessage_NoSecrets tests error when secrets not available.
func TestProcessPrivateMessage_NoSecrets(t *testing.T) {
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

	// Clear secrets
	group.epochSecrets.SenderDataSecret = nil

	pm := &framing.PrivateMessage{
		GroupID: group.groupID.AsSlice(),
		Epoch:   group.epoch.AsUint64(),
	}

	if err := group.ProcessPrivateMessage(pm); err == nil {
		t.Error("expected error when secrets not available")
	}
}
