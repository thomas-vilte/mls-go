package group

import (
	"strings"
	"testing"

	"github.com/mls-go/ciphersuite"
	"github.com/mls-go/credentials"
	"github.com/mls-go/keypackages"
	"github.com/mls-go/treesync"
)

func createTestGroup(t *testing.T) (*Group, *keypackages.KeyPackage) {
	cred, _, err := credentials.GenerateCredentialWithKey([]byte("test"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}
	kp, kpPrivKeys, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage failed: %v", err)
	}

	groupID, err := NewGroupIDRandom()
	if err != nil {
		t.Fatalf("NewGroupIDRandom failed: %v", err)
	}
	group, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kp, kpPrivKeys)
	if err != nil {
		t.Fatalf("NewGroup failed: %v", err)
	}
	return group, kp
}

// createValidUpdateProposal creates a valid Update proposal with correct signature.
func createValidUpdateProposal(t *testing.T, g *Group, sender LeafNodeIndex) *Proposal {
	cred, _, err := credentials.GenerateCredentialWithKey([]byte("updater"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}

	// Create un nuevo LeafNode para el Update
	leafNode := &keypackages.LeafNode{
		EncryptionKey:     []byte("new-encryption-key-32bytes-long"),
		SignatureKey:      cred.SignatureKey,
		Credential:        cred.Credential,
		Capabilities:      keypackages.DefaultCapabilities(),
		Lifetime:          nil, // No lifetime para Update
		Extensions:        []keypackages.Extension{},
		LeafNodeSource:    2, // update
		ParentHash:        []byte("parent-hash"),
		SignatureKeyBytes: nil,
	}

	// Convertir a treesync.LeafNodeData para firmar
	lnData := keyPackageLeafToTreeSync(leafNode)

	// Firmar con el contexto del grupo
	tbs := lnData.MarshalTBSWithContext(g.GroupContext.GroupID.AsSlice(), uint32(sender))
	sigPrivKey := ciphersuite.NewSignaturePrivateKey(cred.PrivateKey)
	sig, err := ciphersuite.SignWithLabel(sigPrivKey, "LeafNodeTBS", tbs)
	if err != nil {
		t.Fatalf("SignWithLabel failed: %v", err)
	}
	leafNode.Signature = sig.AsSlice()

	return NewUpdateProposal(leafNode)
}

func TestProposalFilter_ValidateSingleProposal(t *testing.T) {
	group, kp := createTestGroup(t)
	group.Members[1] = &Member{LeafIndex: 1, Active: true}
	_, _ = group.RatchetTree.AddLeaf(treesync.LeafNodeData{
		EncryptionKey: []byte{1},
		SignatureKey:  kp.LeafNode.SignatureKey,
		Credential:    kp.LeafNode.Credential,
		Capabilities:  toTreeSyncCapabilities(kp.LeafNode.Capabilities),
		Signature:     []byte{1},
	})

	pf := NewProposalFilter(
		group.GroupContext,
		group.OwnLeafIndex,
		group.Members,
		group.CipherSuite,
		group.RatchetTree,
	)

	tests := []struct {
		name      string
		proposal  FilteredProposal
		wantError bool
	}{
		{
			name: "valid add proposal",
			proposal: FilteredProposal{
				Proposal: NewAddProposal(kp),
				Sender:   1,
			},
			wantError: false,
		},
		{
			name: "committer cannot update itself",
			proposal: FilteredProposal{
				Proposal: NewUpdateProposal(kp.LeafNode),
				Sender:   group.OwnLeafIndex,
			},
			wantError: true,
		},
		{
			name: "cannot remove committer",
			proposal: FilteredProposal{
				Proposal: NewRemoveProposal(group.OwnLeafIndex),
				Sender:   1,
			},
			wantError: true,
		},
		{
			name: "valid update from other member",
			proposal: FilteredProposal{
				Proposal: createValidUpdateProposal(t, group, 1),
				Sender:   1,
			},
			wantError: false,
		},
	}

	// Create capabilities que soporten todos los tipos de proposals
	allCapabilities := &keypackages.Capabilities{
		ProtocolVersions: []keypackages.ProtocolVersion{keypackages.MLS10},
		CipherSuites:     []keypackages.CipherSuite{keypackages.MLS128DHKEMP256},
		Extensions:       []uint16{},
		Proposals:        []uint16{1, 2, 3, 4, 5, 6, 7}, // Todos los tipos de proposals
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pf.validateSingleProposal(tt.proposal, allCapabilities)
			if tt.wantError && err == nil {
				t.Errorf("expected error but got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestProposalFilter_CheckDuplicates(t *testing.T) {
	group, kp := createTestGroup(t)
	group.Members[1] = &Member{LeafIndex: 1, Active: true}
	group.Members[2] = &Member{LeafIndex: 2, Active: true}
	_, _ = group.RatchetTree.AddLeaf(treesync.LeafNodeData{
		EncryptionKey: []byte{1}, SignatureKey: kp.LeafNode.SignatureKey, Credential: kp.LeafNode.Credential,
		Capabilities: toTreeSyncCapabilities(kp.LeafNode.Capabilities), Signature: []byte{1},
	})
	_, _ = group.RatchetTree.AddLeaf(treesync.LeafNodeData{
		EncryptionKey: []byte{2}, SignatureKey: kp.LeafNode.SignatureKey, Credential: kp.LeafNode.Credential,
		Capabilities: toTreeSyncCapabilities(kp.LeafNode.Capabilities), Signature: []byte{1},
	})

	pf := NewProposalFilter(
		group.GroupContext,
		group.OwnLeafIndex,
		group.Members,
		group.CipherSuite,
		group.RatchetTree,
	)

	tests := []struct {
		name      string
		proposals []FilteredProposal
		wantError bool
	}{
		{
			name: "duplicate update from same sender",
			proposals: []FilteredProposal{
				{Proposal: NewUpdateProposal(kp.LeafNode), Sender: 1},
				{Proposal: NewUpdateProposal(kp.LeafNode), Sender: 1},
			},
			wantError: true,
		},
		{
			name: "duplicate remove for same index",
			proposals: []FilteredProposal{
				{Proposal: NewRemoveProposal(1), Sender: 0},
				{Proposal: NewRemoveProposal(1), Sender: 0},
			},
			wantError: true,
		},
		{
			name: "duplicate add for same key package",
			proposals: []FilteredProposal{
				{Proposal: NewAddProposal(kp), Sender: 0},
				{Proposal: NewAddProposal(kp), Sender: 0},
			},
			wantError: true,
		},
		{
			name: "no duplicates - valid",
			proposals: []FilteredProposal{
				{Proposal: NewUpdateProposal(kp.LeafNode), Sender: 1},
				{Proposal: NewUpdateProposal(kp.LeafNode), Sender: 2},
				{Proposal: NewRemoveProposal(1), Sender: 0},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pf.checkDuplicates(tt.proposals)
			if tt.wantError && err == nil {
				t.Errorf("expected error but got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestProposalFilter_ValidateCombinations(t *testing.T) {
	group, kp := createTestGroup(t)

	pf := NewProposalFilter(
		group.GroupContext,
		group.OwnLeafIndex,
		group.Members,
		group.CipherSuite,
		group.RatchetTree,
	)

	tests := []struct {
		name      string
		proposals []FilteredProposal
		wantError bool
	}{
		{
			name: "reinit incompatible with add",
			proposals: []FilteredProposal{
				{Proposal: NewReInitProposal([]byte("new"), 1, keypackages.MLS128DHKEMP256, nil), Sender: 0},
				{Proposal: NewAddProposal(kp), Sender: 0},
			},
			wantError: true,
		},
		{
			name: "reinit compatible with psk",
			proposals: []FilteredProposal{
				{Proposal: NewReInitProposal([]byte("new"), 1, keypackages.MLS128DHKEMP256, nil), Sender: 0},
				{Proposal: NewPreSharedKeyProposal(1, []byte("psk")), Sender: 0},
			},
			wantError: false,
		},
		{
			name: "reinit alone is valid",
			proposals: []FilteredProposal{
				{Proposal: NewReInitProposal([]byte("new"), 1, keypackages.MLS128DHKEMP256, nil), Sender: 0},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pf.validateProposalCombinations(tt.proposals)
			if tt.wantError && err == nil {
				t.Errorf("expected error but got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestProposalFilter_SortProposals(t *testing.T) {
	group, kp := createTestGroup(t)
	committer := group.OwnLeafIndex

	pf := NewProposalFilter(
		group.GroupContext,
		committer,
		group.Members,
		group.CipherSuite,
		group.RatchetTree,
	)

	// Create proposals en orden aleatorio
	proposals := []FilteredProposal{
		{Proposal: NewAddProposal(kp), Sender: 0},
		{Proposal: NewRemoveProposal(1), Sender: 0},
		{Proposal: NewUpdateProposal(kp.LeafNode), Sender: 1},
		{Proposal: NewGroupContextExtensionsProposal(nil), Sender: 0},
		{Proposal: NewUpdateProposal(kp.LeafNode), Sender: committer}, // Committer update
		{Proposal: NewPreSharedKeyProposal(1, []byte("psk")), Sender: 0},
	}

	sorted := pf.sortProposals(proposals)

	// Imprimir orden real para debug
	t.Logf("Sorted order:")
	for i, p := range sorted {
		t.Logf("  %d: type=%d sender=%d", i, p.Proposal.Type, p.Sender)
	}

	// Verify orden RFC §12.4.2: GroupContextExtensions, Update, Remove, Add, PreSharedKey
	// Note: There are 2 Updates, so the actual order is: GCE, Update, Update, Remove, Add, PSK
	expectedOrder := []ProposalType{
		ProposalTypeGroupContextExtensions, // 7
		ProposalTypeUpdate,                 // 2
		ProposalTypeUpdate,                 // 2 (committer)
		ProposalTypeRemove,                 // 3
		ProposalTypeAdd,                    // 1
		ProposalTypePreSharedKey,           // 4
	}

	for i, expected := range expectedOrder {
		if i >= len(sorted) {
			t.Errorf("position %d: expected %v but sorted has only %d elements", i, expected, len(sorted))
			continue
		}
		if sorted[i].Proposal.Type != expected {
			t.Errorf("position %d: expected %v, got %v",
				i, expected, sorted[i].Proposal.Type)
		}
	}

	// Verify that the committer's update is at the end of the updates
	var updateIndices []int
	for i, p := range sorted {
		if p.Proposal.Type == ProposalTypeUpdate {
			updateIndices = append(updateIndices, i)
		}
	}

	// There should be 2 updates
	if len(updateIndices) != 2 {
		t.Errorf("expected 2 updates, got %d", len(updateIndices))
	} else {
		// El second update should ser del committer
		committerUpdate := sorted[updateIndices[1]]
		if committerUpdate.Sender != committer {
			t.Errorf("expected committer update at position %d, got sender %d", updateIndices[1], committerUpdate.Sender)
		}
	}
}

func TestProposalFilter_FilterAndValidateProposals(t *testing.T) {
	group, kp := createTestGroup(t)

	// Agregar un miembro first
	newCred, _, err := credentials.GenerateCredentialWithKey([]byte("new"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}
	newKp, _, err := keypackages.Generate(newCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage failed: %v", err)
	}
	if _, err := group.AddMember(newKp); err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}
	// Apply the add proposal manually so it's in members
	if err := group.applyAddProposal(&AddProposal{KeyPackage: newKp}); err != nil {
		t.Fatalf("applyAddProposal failed: %v", err)
	}
	group.Members[1] = &Member{LeafIndex: 1, Active: true}

	// Generate a third key package with unique keys for the Add proposal.
	thirdCred, _, err := credentials.GenerateCredentialWithKey([]byte("third"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey (third) failed: %v", err)
	}
	thirdKp, _, err := keypackages.Generate(thirdCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage (third) failed: %v", err)
	}

	pf := NewProposalFilter(
		group.GroupContext,
		group.OwnLeafIndex,
		group.Members,
		group.CipherSuite,
		group.RatchetTree,
	)

	// Valid proposals: Add with new key package (unique keys), Remove + Update from existing member.
	proposals := []FilteredProposal{
		{Proposal: NewAddProposal(thirdKp), Sender: 0},
		{Proposal: NewRemoveProposal(1), Sender: 0},
		{Proposal: createValidUpdateProposal(t, group, 1), Sender: 1},
	}
	_ = kp

	// Create capabilities que soporten todos los tipos de proposals
	allCapabilities := &keypackages.Capabilities{
		ProtocolVersions: []keypackages.ProtocolVersion{keypackages.MLS10},
		CipherSuites:     []keypackages.CipherSuite{keypackages.MLS128DHKEMP256},
		Extensions:       []uint16{},
		Proposals:        []uint16{1, 2, 3, 4, 5, 6, 7}, // Todos los tipos de proposals
	}

	filtered, err := pf.FilterAndValidateProposals(proposals, allCapabilities)
	if err != nil {
		t.Fatalf("FilterAndValidateProposals failed: %v", err)
	}

	// Verify orden
	expectedOrder := []ProposalType{
		ProposalTypeUpdate,
		ProposalTypeRemove,
		ProposalTypeAdd,
	}

	for i, expected := range expectedOrder {
		if filtered[i].Proposal.Type != expected {
			t.Errorf("position %d: expected %v, got %v",
				i, expected, filtered[i].Proposal.Type)
		}
	}
}

func TestProposalFilter_AddInvalidSignature(t *testing.T) {
	group, kp := createTestGroup(t)
	_ = kp

	// Create a valid KeyPackage
	cred, _, err := credentials.GenerateCredentialWithKey([]byte("newmember"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}
	newKp, _, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage failed: %v", err)
	}

	// Corromper la firma
	newKp.Signature[0] ^= 0xFF

	pf := NewProposalFilter(
		group.GroupContext,
		group.OwnLeafIndex,
		group.Members,
		group.CipherSuite,
		group.RatchetTree,
	)

	caps := &keypackages.Capabilities{
		ProtocolVersions: []keypackages.ProtocolVersion{keypackages.MLS10},
		CipherSuites:     []keypackages.CipherSuite{keypackages.MLS128DHKEMP256},
		Proposals:        []uint16{1, 2, 3, 4, 5, 6, 7},
	}

	proposals := []FilteredProposal{
		{Proposal: NewAddProposal(newKp), Sender: 0},
	}

	_, err = pf.FilterAndValidateProposals(proposals, caps)
	if err == nil {
		t.Fatal("expected error for invalid KeyPackage signature, got nil")
	}

	// Verify that the error mentions invalid signature
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("expected error to mention signature, got: %v", err)
	}
}

func TestProposalFilter_UpdateInvalidSignature(t *testing.T) {
	group, kp := createTestGroup(t)

	// Agregar un miembro existente
	cred, _, err := credentials.GenerateCredentialWithKey([]byte("existing"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}
	existingKp, _, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage failed: %v", err)
	}

	// Add the member to the tree
	group.Members[1] = &Member{LeafIndex: 1, Active: true}
	leafData := keyPackageLeafToTreeSync(existingKp.LeafNode)
	_, _ = group.RatchetTree.AddLeaf(*leafData)

	// Create an Update proposal with invalid signature LeafNode
	updateLeafNode := kp.LeafNode
	// Corromper la firma del LeafNode
	updateLeafNode.Signature[0] ^= 0xFF

	pf := NewProposalFilter(
		group.GroupContext,
		group.OwnLeafIndex,
		group.Members,
		group.CipherSuite,
		group.RatchetTree,
	)

	caps := &keypackages.Capabilities{
		ProtocolVersions: []keypackages.ProtocolVersion{keypackages.MLS10},
		CipherSuites:     []keypackages.CipherSuite{keypackages.MLS128DHKEMP256},
		Proposals:        []uint16{1, 2, 3, 4, 5, 6, 7},
	}

	proposals := []FilteredProposal{
		{Proposal: NewUpdateProposal(updateLeafNode), Sender: 1},
	}

	_, err = pf.FilterAndValidateProposals(proposals, caps)
	if err == nil {
		t.Fatal("expected error for invalid Update LeafNode signature, got nil")
	}

	// Verify that the error mentions invalid signature
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("expected error to mention signature, got: %v", err)
	}
}

func TestProposalFilter_KeyUniqueness(t *testing.T) {
	group, existingKp := createTestGroup(t)
	_ = existingKp

	mkPF := func() *ProposalFilter {
		return NewProposalFilter(
			group.GroupContext,
			group.OwnLeafIndex,
			group.Members,
			group.CipherSuite,
			group.RatchetTree,
		)
	}
	caps := &keypackages.Capabilities{
		ProtocolVersions: []keypackages.ProtocolVersion{keypackages.MLS10},
		CipherSuites:     []keypackages.CipherSuite{keypackages.MLS128DHKEMP256},
		Proposals:        []uint16{1, 2, 3, 4, 5, 6, 7},
	}

	genKP := func(name string) *keypackages.KeyPackage {
		cred, _, err := credentials.GenerateCredentialWithKey([]byte(name))
		if err != nil {
			t.Fatalf("GenerateCredentialWithKey(%q): %v", name, err)
		}
		kp, _, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
		if err != nil {
			t.Fatalf("Generate(%q): %v", name, err)
		}
		return kp
	}

	t.Run("duplicate_encryption_key_between_adds", func(t *testing.T) {
		kp1 := genKP("a")
		kp2 := genKP("b")
		// Force same encryption key
		kp2.LeafNode.EncryptionKey = kp1.LeafNode.EncryptionKey
		proposals := []FilteredProposal{
			{Proposal: NewAddProposal(kp1), Sender: 0},
			{Proposal: NewAddProposal(kp2), Sender: 0},
		}
		_, err := mkPF().FilterAndValidateProposals(proposals, caps)
		if err == nil {
			t.Fatal("expected error for duplicate encryption key, got nil")
		}
	})

	t.Run("encryption_key_already_in_tree", func(t *testing.T) {
		// existingKp has the encryption key that is already in the tree (leaf 0).
		proposals := []FilteredProposal{
			{Proposal: NewAddProposal(existingKp), Sender: 0},
		}
		_, err := mkPF().FilterAndValidateProposals(proposals, caps)
		if err == nil {
			t.Fatal("expected error for encryption key already in tree, got nil")
		}
	})

	t.Run("duplicate_init_key_between_adds", func(t *testing.T) {
		kp1 := genKP("c")
		kp2 := genKP("d")
		// Force same init key
		kp2.InitKey = kp1.InitKey
		proposals := []FilteredProposal{
			{Proposal: NewAddProposal(kp1), Sender: 0},
			{Proposal: NewAddProposal(kp2), Sender: 0},
		}
		_, err := mkPF().FilterAndValidateProposals(proposals, caps)
		if err == nil {
			t.Fatal("expected error for duplicate init key, got nil")
		}
	})

	t.Run("duplicate_signature_key_between_adds", func(t *testing.T) {
		kp1 := genKP("e")
		kp2 := genKP("f")
		// Force same signature key
		kp2.LeafNode.SignatureKey = kp1.LeafNode.SignatureKey
		kp2.LeafNode.SignatureKeyBytes = kp1.LeafNode.SignatureKeyBytes
		proposals := []FilteredProposal{
			{Proposal: NewAddProposal(kp1), Sender: 0},
			{Proposal: NewAddProposal(kp2), Sender: 0},
		}
		_, err := mkPF().FilterAndValidateProposals(proposals, caps)
		if err == nil {
			t.Fatal("expected error for duplicate signature key, got nil")
		}
	})

	t.Run("duplicate_psk_id", func(t *testing.T) {
		psk := &Proposal{
			Type: ProposalTypePreSharedKey,
			PreSharedKey: &PreSharedKeyProposal{
				PskID: PskID{ID: []byte("my-psk"), PskType: 1},
			},
		}
		proposals := []FilteredProposal{
			{Proposal: psk, Sender: 0},
			{Proposal: psk, Sender: 0},
		}
		_, err := mkPF().FilterAndValidateProposals(proposals, caps)
		if err == nil {
			t.Fatal("expected error for duplicate PSK ID, got nil")
		}
	})

	t.Run("unique_keys_valid", func(t *testing.T) {
		kp1 := genKP("g")
		kp2 := genKP("h")
		proposals := []FilteredProposal{
			{Proposal: NewAddProposal(kp1), Sender: 0},
			{Proposal: NewAddProposal(kp2), Sender: 0},
		}
		_, err := mkPF().FilterAndValidateProposals(proposals, caps)
		if err != nil {
			t.Fatalf("expected success for unique keys, got: %v", err)
		}
	})
}
