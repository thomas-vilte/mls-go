package group

import (
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// TestTreeTruncation_DirectApply verifies that applyRemoveProposal trunca el
// árbol cuando el último leaf queda en blanco.
func TestTreeTruncation_DirectApply(t *testing.T) {
	aliceGroup, _, _, _ := setupTwoMemberGroup(t)

	before := aliceGroup.RatchetTree.NumLeaves
	if before != 2 {
		t.Fatalf("expected 2 leaves before remove, got %d", before)
	}

	err := aliceGroup.applyRemoveProposal(&RemoveProposal{Removed: LeafNodeIndex(1)})
	if err != nil {
		t.Fatalf("applyRemoveProposal: %v", err)
	}

	after := aliceGroup.RatchetTree.NumLeaves
	if after != 1 {
		t.Errorf("NumLeaves after removing last member = %d, want 1", after)
	}
}

// TestTreeTruncation_NonTrailingLeaf verifies that remover un leaf que NO es
// el último no trunca el árbol más allá del trailing blank.
func TestTreeTruncation_NonTrailingLeaf(t *testing.T) {
	// Create grupo de 3 miembros: Alice(0), Bob(1), Charlie(2).
	aliceGroup, _, alicePriv, _ := setupTwoMemberGroup(t)

	charlieCred, _, err := credentials.GenerateCredentialWithKey([]byte("Charlie-trunc"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey: %v", err)
	}
	charlieKP, _, err := keypackages.Generate(charlieCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := aliceGroup.AddMember(charlieKP); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	sigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)
	sigPub := sigPriv.PublicKey()
	sc, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := aliceGroup.MergeCommit(sc); err != nil {
		t.Fatalf("MergeCommit: %v", err)
	}

	// Tree expands to next power-of-2: 2→4 slots when adding the 3rd leaf.
	if aliceGroup.RatchetTree.NumLeaves != 4 {
		t.Fatalf("expected 4 leaves (tree expanded to power-of-2), got %d", aliceGroup.RatchetTree.NumLeaves)
	}

	// Remover Bob (leaf 1, no es el último).
	err = aliceGroup.applyRemoveProposal(&RemoveProposal{Removed: LeafNodeIndex(1)})
	if err != nil {
		t.Fatalf("applyRemoveProposal: %v", err)
	}

	// Trailing blank at leaf 3 is truncated; Charlie at leaf 2 is still present → 3 leaves remain.
	if aliceGroup.RatchetTree.NumLeaves != 3 {
		t.Errorf("NumLeaves after removing non-trailing leaf = %d, want 3", aliceGroup.RatchetTree.NumLeaves)
	}
}

// TestTreeTruncation_CommitWithRemove verifica el flujo completo de
// RemoveMember → Commit → MergeCommit y que el árbol queda con 1 leaf.
func TestTreeTruncation_CommitWithRemove(t *testing.T) {
	aliceGroup, _, alicePriv, _ := setupTwoMemberGroup(t)

	if _, err := aliceGroup.RemoveMember(LeafNodeIndex(1)); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}

	sigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)
	sigPub := sigPriv.PublicKey()
	sc, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := aliceGroup.MergeCommit(sc); err != nil {
		t.Fatalf("MergeCommit: %v", err)
	}

	if aliceGroup.RatchetTree.NumLeaves != 1 {
		t.Errorf("NumLeaves after commit with remove = %d, want 1", aliceGroup.RatchetTree.NumLeaves)
	}
	if aliceGroup.MemberCount() != 1 {
		t.Errorf("MemberCount after remove = %d, want 1", aliceGroup.MemberCount())
	}
}
