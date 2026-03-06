package group

import (
	"testing"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/credentials"
	keypackages "github.com/openmls/go/key_packages"
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

func TestProposalFilter_ValidateSingleProposal(t *testing.T) {
	group, kp := createTestGroup(t)

	pf := NewProposalFilter(
		group.GroupContext,
		group.OwnLeafIndex,
		group.Members,
		group.CipherSuite,
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
				Proposal: NewUpdateProposal(kp.LeafNode),
				Sender:   1,
			},
			wantError: false,
		},
	}

	// Crear capabilities que soporten todos los tipos de proposals
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

	pf := NewProposalFilter(
		group.GroupContext,
		group.OwnLeafIndex,
		group.Members,
		group.CipherSuite,
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
	)

	// Crear proposals en orden aleatorio
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

	// Verificar orden RFC §12.4.2: GroupContextExtensions, Update, Remove, Add, PreSharedKey
	// Nota: Hay 2 Updates, así que el orden real es: GCE, Update, Update, Remove, Add, PSK
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

	// Verificar que el update del committer está al final de los updates
	updateIndices := []int{}
	for i, p := range sorted {
		if p.Proposal.Type == ProposalTypeUpdate {
			updateIndices = append(updateIndices, i)
		}
	}

	// Debería haber 2 updates
	if len(updateIndices) != 2 {
		t.Errorf("expected 2 updates, got %d", len(updateIndices))
	} else {
		// El segundo update debería ser del committer
		committerUpdate := sorted[updateIndices[1]]
		if committerUpdate.Sender != committer {
			t.Errorf("expected committer update at position %d, got sender %d", updateIndices[1], committerUpdate.Sender)
		}
	}
}

func TestProposalFilter_FilterAndValidateProposals(t *testing.T) {
	group, kp := createTestGroup(t)

	// Agregar un miembro primero
	newCred, _, err := credentials.GenerateCredentialWithKey([]byte("new"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}
	newKp, _, err := keypackages.Generate(newCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage failed: %v", err)
	}
	_, _ = group.AddMember(newKp)
	// Aplicar el add proposal manualmente para que esté en members
	group.applyAddProposal(&AddProposal{KeyPackage: newKp})

	pf := NewProposalFilter(
		group.GroupContext,
		group.OwnLeafIndex,
		group.Members,
		group.CipherSuite,
	)

	// Proposals válidos
	proposals := []FilteredProposal{
		{Proposal: NewAddProposal(kp), Sender: 0},
		{Proposal: NewRemoveProposal(1), Sender: 0},
		{Proposal: NewUpdateProposal(kp.LeafNode), Sender: 1},
	}

	// Crear capabilities que soporten todos los tipos de proposals
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

	// Verificar orden
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
