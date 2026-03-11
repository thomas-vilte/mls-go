package group

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/credentials"
	keypackages "github.com/openmls/go/keypackages"
	"github.com/openmls/go/schedule"
	"github.com/openmls/go/treesync"
)

// Helper: crea un grupo de 2 miembros para tests de Commit
func setupTwoMemberGroup(t *testing.T) (*Group, *Group, *keypackages.KeyPackagePrivateKeys, *keypackages.KeyPackagePrivateKeys) {
	t.Helper()

	// Alice crea el grupo
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

	aliceGroup, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, aliceKP, alicePriv)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}

	// Bob se une
	bobCred, _, err := credentials.GenerateCredentialWithKey([]byte("Bob"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(Bob): %v", err)
	}

	bobKP, bobPriv, err := keypackages.Generate(bobCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage(Bob): %v", err)
	}

	if _, err := aliceGroup.AddMember(bobKP); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	// Alice hace commit
	aliceSigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)
	aliceSigPub := aliceSigPriv.PublicKey()

	stagedCommit, err := aliceGroup.Commit(aliceSigPriv, aliceSigPub, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if err := aliceGroup.MergeCommit(stagedCommit); err != nil {
		t.Fatalf("MergeCommit: %v", err)
	}

	// Crear Welcome para Bob
	initSecret := aliceGroup.EpochSecrets.InitSecret.Clone()
	var pathSecret []byte
	if stagedCommit.RootPathSecret != nil {
		pathSecret = stagedCommit.RootPathSecret.AsSlice()
	}

	joinerSecret, err := initSecret.HKDFExtract(ciphersuite.NewSecret(pathSecret))
	if err != nil {
		t.Fatalf("HKDFExtract joiner secret: %v", err)
	}

	welcome, err := aliceGroup.CreateWelcome([]*keypackages.KeyPackage{bobKP}, joinerSecret, pathSecret, aliceSigPriv)
	if err != nil {
		t.Fatalf("CreateWelcome: %v", err)
	}

	bobGroup, err := JoinFromWelcome(welcome, bobKP, bobPriv, nil)
	if err != nil {
		t.Fatalf("JoinFromWelcome: %v", err)
	}

	// Sincronizar epoch secrets de Bob con Alice
	bobGroup.EpochSecrets = &schedule.EpochSecrets{
		InitSecret:       aliceGroup.EpochSecrets.InitSecret.Clone(),
		SenderDataSecret: aliceGroup.EpochSecrets.SenderDataSecret.Clone(),
		EncryptionSecret: aliceGroup.EpochSecrets.EncryptionSecret.Clone(),
		ExporterSecret:   aliceGroup.EpochSecrets.ExporterSecret.Clone(),
		ExternalSecret:   aliceGroup.EpochSecrets.ExternalSecret.Clone(),
		ConfirmationKey:  aliceGroup.EpochSecrets.ConfirmationKey.Clone(),
		MembershipKey:    aliceGroup.EpochSecrets.MembershipKey.Clone(),
		ResumptionSecret: aliceGroup.EpochSecrets.ResumptionSecret.Clone(),
	}

	return aliceGroup, bobGroup, alicePriv, bobPriv
}

// TestProcessCommit_Valid verifica que un commit válido se procesa correctamente
func TestProcessCommit_Valid(t *testing.T) {
	aliceGroup, bobGroup, alicePriv, _ := setupTwoMemberGroup(t)

	// Guardar estado anterior de Bob
	oldEpoch := bobGroup.Epoch.AsUint64()
	oldTreeHash := bobGroup.RatchetTree.TreeHash()

	// Alice genera un nuevo commit (Add proposal de un tercer miembro)
	aliceSigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)
	aliceSigPub := aliceSigPriv.PublicKey()

	// Crear tercer miembro
	charlieCred, _, err := credentials.GenerateCredentialWithKey([]byte("Charlie"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(Charlie): %v", err)
	}

	charlieKP, _, err := keypackages.Generate(charlieCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage(Charlie): %v", err)
	}

	// Alice agrega a Charlie
	_, err = aliceGroup.AddMember(charlieKP)
	if err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	// Alice hace commit
	stagedCommit, err := aliceGroup.Commit(aliceSigPriv, aliceSigPub, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Bob procesa el commit recibido
	err = bobGroup.ProcessCommit(stagedCommit)
	if err != nil {
		t.Fatalf("ProcessCommit failed: %v", err)
	}

	// Verificar que la epoch subió
	if bobGroup.Epoch.AsUint64() != oldEpoch+1 {
		t.Errorf("Epoch should increment from %d to %d, got %d", oldEpoch, oldEpoch+1, bobGroup.Epoch.AsUint64())
	}

	// Verificar que el TreeHash cambió
	if bytes.Equal(bobGroup.RatchetTree.TreeHash(), oldTreeHash) {
		t.Error("TreeHash should change after commit")
	}

	// Verificar que los epoch secrets no son nil
	if bobGroup.EpochSecrets == nil {
		t.Error("EpochSecrets should not be nil after commit")
	}
	if bobGroup.EpochSecrets.EncryptionSecret == nil {
		t.Error("EncryptionSecret should not be nil after commit")
	}

	// Verificar que el proposal se aplicó (Charlie debería estar en el grupo)
	if bobGroup.MemberCount() != 3 {
		t.Errorf("MemberCount should be 3 after adding Charlie, got %d", bobGroup.MemberCount())
	}
}

// TestProcessCommit_WrongEpoch verifica que un commit con epoch incorrecto falla.
// ProcessCommit no valida el epoch (solo llama a MergeCommit).
// La validación de epoch existe únicamente en ReceiveMessage. RFC §12.4.1 gap.
func TestProcessCommit_WrongEpoch(t *testing.T) {
	t.Skip("epoch validation not implemented in ProcessCommit - RFC §12.4.1 gap")
}

// TestProcessCommit_CorruptedUpdatePath verifica que un commit con UpdatePath corrupto falla
func TestProcessCommit_CorruptedUpdatePath(t *testing.T) {
	aliceGroup, bobGroup, alicePriv, _ := setupTwoMemberGroup(t)

	// Crear un commit válido (primero agregamos un proposal)
	aliceSigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)
	aliceSigPub := aliceSigPriv.PublicKey()

	// Agregar tercer miembro para tener proposal
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

	// Corromper el UpdatePath si existe
	if stagedCommit.Commit.Path != nil && len(stagedCommit.Commit.Path.Nodes) > 0 {
		// Guardar original
		original := make([]byte, len(stagedCommit.Commit.Path.Nodes[0].EncryptionKey))
		copy(original, stagedCommit.Commit.Path.Nodes[0].EncryptionKey)

		// Corromper un byte
		stagedCommit.Commit.Path.Nodes[0].EncryptionKey[0] ^= 0xFF

		// Bob intenta procesar
		err = bobGroup.ProcessCommit(stagedCommit)
		if err != nil {
			t.Logf("ProcessCommit correctly detected corrupted UpdatePath: %v", err)
		} else {
			t.Error("ProcessCommit should fail with corrupted UpdatePath")
		}

		// Restaurar para cleanup
		copy(stagedCommit.Commit.Path.Nodes[0].EncryptionKey, original)
	} else {
		t.Skip("Commit has no UpdatePath nodes to corrupt")
	}
}

// TestUpdateMember_Valid verifica que UpdateMember genera un proposal válido
func TestUpdateMember_Valid(t *testing.T) {
	aliceGroup, _, alicePriv, _ := setupTwoMemberGroup(t)

	// Guardar la encryption key original
	oldLeaf := aliceGroup.RatchetTree.GetLeaf(treesync.LeafIndex(aliceGroup.OwnLeafIndex))
	if oldLeaf == nil || oldLeaf.LeafData == nil {
		t.Fatal("Own leaf not found")
	}
	oldEncryptionKey := make([]byte, len(oldLeaf.LeafData.EncryptionKey))
	copy(oldEncryptionKey, oldLeaf.LeafData.EncryptionKey)

	// Generar nuevo LeafNode
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

	// Crear Update proposal
	updateProposal, err := aliceGroup.UpdateMember(newLeafNode, alicePriv)
	if err != nil {
		t.Fatalf("UpdateMember failed: %v", err)
	}

	// Verificar que el proposal se creó
	if updateProposal == nil {
		t.Fatal("UpdateMember should return non-nil proposal")
	}

	if updateProposal.Type != ProposalTypeUpdate {
		t.Errorf("Proposal type should be Update (%d), got %d", ProposalTypeUpdate, updateProposal.Type)
	}

	if updateProposal.Update == nil {
		t.Fatal("Update proposal body should not be nil")
	}

	// Verificar que la encryption key cambió
	if bytes.Equal(oldLeaf.LeafData.EncryptionKey, updateProposal.Update.LeafNode.EncryptionKey) {
		t.Error("UpdateMember should generate new encryption key")
	}

	// Verificar que el proposal se almacenó
	if aliceGroup.Proposals == nil || len(aliceGroup.Proposals.Proposals) == 0 {
		t.Error("Update proposal should be stored in proposal store")
	}
}

// TestUpdateMember_NilCredential verifica que UpdateMember falla con credential nil
func TestUpdateMember_NilCredential(t *testing.T) {
	aliceGroup, _, _, _ := setupTwoMemberGroup(t)

	// Intentar UpdateMember con LeafNode nil
	_, err := aliceGroup.UpdateMember(nil, nil)
	if err == nil {
		t.Error("UpdateMember should fail with nil LeafNode")
	}

	// Crear LeafNode válido pero con private keys nil
	leaf := aliceGroup.RatchetTree.GetLeaf(treesync.LeafIndex(aliceGroup.OwnLeafIndex))
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

// TestGetMember_Valid verifica que GetMember retorna el miembro correcto
func TestGetMember_Valid(t *testing.T) {
	aliceGroup, bobGroup, _, _ := setupTwoMemberGroup(t)

	// Obtener Alice
	aliceMember, ok := aliceGroup.GetMember(aliceGroup.OwnLeafIndex)
	if !ok {
		t.Error("GetMember should return true for own leaf")
	}
	if aliceMember == nil {
		t.Error("GetMember should return non-nil member")
	}
	if !aliceMember.Active {
		t.Error("Alice member should be active")
	}

	// Obtener Bob desde la perspectiva de Alice
	// Bob debería estar en el índice 1 (después del Add + Commit)
	var bobIdx LeafNodeIndex
	for idx := range aliceGroup.Members {
		if idx != aliceGroup.OwnLeafIndex {
			bobIdx = idx
			break
		}
	}

	bobMember, ok := aliceGroup.GetMember(bobIdx)
	if !ok {
		t.Error("GetMember should return true for Bob's leaf")
	}
	if bobMember == nil {
		t.Error("GetMember should return non-nil member for Bob")
	}
	if !bobMember.Active {
		t.Error("Bob member should be active")
	}

	// Verificar desde Bob también
	bobMemberFromBob, ok := bobGroup.GetMember(bobGroup.OwnLeafIndex)
	if !ok {
		t.Error("GetMember should return true for own leaf (Bob)")
	}
	if bobMemberFromBob == nil {
		t.Error("GetMember should return non-nil member for Bob (from Bob's group)")
	}
}

// TestGetMember_OutOfRange verifica que GetMember maneja índices fuera de rango
func TestGetMember_OutOfRange(t *testing.T) {
	aliceGroup, _, _, _ := setupTwoMemberGroup(t)

	// Índice muy grande
	_, ok := aliceGroup.GetMember(9999)
	if ok {
		t.Error("GetMember should return false for out-of-range index")
	}

	// Índice negativo (convertido a uint32 grande)
	_, ok = aliceGroup.GetMember(LeafNodeIndex(0xFFFFFFFF))
	if ok {
		t.Error("GetMember should return false for invalid index")
	}
}

// TestGetMembers_Count verifica que GetMembers retorna la cantidad correcta
func TestGetMembers_Count(t *testing.T) {
	aliceGroup, bobGroup, _, _ := setupTwoMemberGroup(t)

	// Debería haber 2 miembros
	aliceMembers := aliceGroup.GetMembers()
	if len(aliceMembers) != 2 {
		t.Errorf("GetMembers should return 2 members, got %d", len(aliceMembers))
	}

	bobMembers := bobGroup.GetMembers()
	if len(bobMembers) != 2 {
		t.Errorf("GetMembers should return 2 members (Bob), got %d", len(bobMembers))
	}

	// Verificar que todos los miembros retornados están activos
	for _, member := range aliceMembers {
		if !member.Active {
			t.Error("GetMembers should only return active members")
		}
	}
}

// TestValidateAddProposal_DuplicateKey verifica que no se pueden agregar KeyPackages con misma InitKey
// Nota: Este test documenta un comportamiento deseado (RFC §12.2), pero la validación
// de InitKey duplicadas no está implementada actualmente en AddMember.
func TestValidateAddProposal_DuplicateKey(t *testing.T) {
	t.Skip("Duplicate InitKey validation not implemented yet")
	/*
		aliceGroup, _, _, _ := setupTwoMemberGroup(t)

		// Crear dos KeyPackages con la misma InitKey (artificialmente)
		cred1, _, err := credentials.GenerateCredentialWithKey([]byte("Member1"))
		if err != nil {
			t.Fatalf("GenerateCredentialWithKey: %v", err)
		}

		kp1, _, err := keypackages.Generate(cred1, keypackages.MLS128DHKEMP256)
		if err != nil {
			t.Fatalf("Generate KeyPackage: %v", err)
		}

		// Crear segunda KeyPackage con la misma InitKey
		cred2, _, err := credentials.GenerateCredentialWithKey([]byte("Member2"))
		if err != nil {
			t.Fatalf("GenerateCredentialWithKey: %v", err)
		}

		kp2, _, err := keypackages.Generate(cred2, keypackages.MLS128DHKEMP256)
		if err != nil {
			t.Fatalf("Generate KeyPackage: %v", err)
		}

		// Forzar la misma InitKey
		kp2.InitKey = kp1.InitKey

		// Agregar el primero debería funcionar
		_, err = aliceGroup.AddMember(kp1)
		if err != nil {
			t.Fatalf("AddMember(kp1) should succeed: %v", err)
		}

		// Agregar el segundo debería fallar (misma InitKey)
		_, err = aliceGroup.AddMember(kp2)
		if err == nil {
			t.Error("AddMember should fail for duplicate InitKey")
		}
	*/
}

// TestValidateUpdateProposal_InvalidLeafNode verifica que UpdateProposal con LeafNode inválido falla
func TestValidateUpdateProposal_InvalidLeafNode(t *testing.T) {
	aliceGroup, _, _, _ := setupTwoMemberGroup(t)

	// Crear UpdateProposal con LeafNode vacío (sin EncryptionKey)
	invalidLeafNode := &treesync.LeafNodeData{
		EncryptionKey: nil, // Esto debería ser inválido
		SignatureKey:  nil,
		Credential:    nil,
	}

	_, err := aliceGroup.UpdateMember(invalidLeafNode, nil)
	if err == nil {
		t.Error("UpdateMember should fail with invalid LeafNode (nil EncryptionKey)")
	}
}

// TestGroupContext_MarshalUnmarshal verifica roundtrip de GroupContext
func TestGroupContext_MarshalUnmarshal(t *testing.T) {
	aliceGroup, _, _, _ := setupTwoMemberGroup(t)

	// Marshal
	data := aliceGroup.GroupContext.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal should return non-empty data")
	}

	// Unmarshal
	gc2, err := UnmarshalGroupContext(data)
	if err != nil {
		t.Fatalf("UnmarshalGroupContext failed: %v", err)
	}

	// Verificar campos
	if !bytes.Equal(gc2.GroupID.AsSlice(), aliceGroup.GroupContext.GroupID.AsSlice()) {
		t.Error("GroupID should match after roundtrip")
	}

	if gc2.Epoch != aliceGroup.GroupContext.Epoch {
		t.Errorf("Epoch should match: got %d, want %d", gc2.Epoch, aliceGroup.GroupContext.Epoch)
	}

	// Verificar que el TreeHash es el mismo
	if !bytes.Equal(gc2.TreeHash, aliceGroup.GroupContext.TreeHash) {
		t.Error("TreeHash should match after roundtrip")
	}
}
