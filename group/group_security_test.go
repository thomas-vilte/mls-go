package group

import (
	"testing"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/credentials"
	keypackages "github.com/openmls/go/keypackages"
	"github.com/openmls/go/treesync"
)

// TestMergeCommit_InvalidSignature verifica que MergeCommit rechaza commits con firma inválida.
// Fase 1.1: Verificación de firma en commits recibidos
func TestMergeCommit_InvalidSignature(t *testing.T) {
	// Crear grupo con Alice
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

	// Crear KeyPackage para Bob
	bobCred, _, err := credentials.GenerateCredentialWithKey([]byte("bob"))
	if err != nil {
		t.Fatalf("generating bob credential: %v", err)
	}

	bobKeyPackage, _, err := keypackages.Generate(bobCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating bob key package: %v", err)
	}

	// Alice crea commit para agregar a Bob
	_, _ = aliceGroup.AddMember(bobKeyPackage)
	sigPriv := ciphersuite.NewSignaturePrivateKey(alicePrivKeys.SignatureKey)
	sigPub := sigPriv.PublicKey()
	stagedCommit, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		t.Fatalf("creating commit: %v", err)
	}

	// Corromper la firma (flip un byte)
	if len(stagedCommit.AuthenticatedContent.Auth.Signature.AsSlice()) > 0 {
		sigBytes := stagedCommit.AuthenticatedContent.Auth.Signature.AsSlice()
		sigBytes[0] ^= 0xFF
	}

	// Intentar mergear debe fallar por firma inválida
	err = aliceGroup.MergeCommit(stagedCommit)
	if err == nil {
		t.Error("MergeCommit should fail with invalid signature")
	}
}

// TestMergeCommit_WrongSigner verifica que MergeCommit rechaza commits firmados por otro miembro.
// Fase 1.1: Verificación de firma en commits recibidos
func TestMergeCommit_WrongSigner(t *testing.T) {
	// Crear grupo con Alice
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

	// Crear KeyPackage para Bob
	bobCred, _, err := credentials.GenerateCredentialWithKey([]byte("bob"))
	if err != nil {
		t.Fatalf("generating bob credential: %v", err)
	}

	bobKeyPackage, bobPrivKeys, err := keypackages.Generate(bobCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating bob key package: %v", err)
	}

	// Alice agrega a Bob
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

	// Ahora Bob es miembro. Intentar crear un commit firmado por Bob pero con sender = Alice (0)
	charlieCred, _, err := credentials.GenerateCredentialWithKey([]byte("charlie"))
	if err != nil {
		t.Fatalf("generating charlie credential: %v", err)
	}

	charlieKeyPackage, _, err := keypackages.Generate(charlieCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating charlie key package: %v", err)
	}

	// Bob crea commit (sender será Bob)
	_, _ = aliceGroup.AddMember(charlieKeyPackage)
	bobSigPriv := ciphersuite.NewSignaturePrivateKey(bobPrivKeys.SignatureKey)
	bobSigPub := bobSigPriv.PublicKey()
	stagedCommit2, err := aliceGroup.Commit(bobSigPriv, bobSigPub, nil)
	if err != nil {
		t.Fatalf("creating commit: %v", err)
	}

	// Cambiar el sender para que parezca de Alice (0) en vez de Bob (1)
	// Esto debería hacer fallar la verificación de firma
	stagedCommit2.AuthenticatedContent.Content.Sender.LeafIndex = 0

	// Intentar mergear debe fallar porque la firma no coincide con el sender
	err = aliceGroup.MergeCommit(stagedCommit2)
	if err == nil {
		t.Error("MergeCommit should fail with wrong signer")
	}
}

// TestMergeCommit_EpochMismatch verifica que MergeCommit rechaza commits con epoch incorrecto.
// Fase 1.2: Validación de epoch
func TestMergeCommit_EpochMismatch(t *testing.T) {
	// Crear grupo con Alice
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

	// Crear KeyPackage para Bob
	bobCred, _, err := credentials.GenerateCredentialWithKey([]byte("bob"))
	if err != nil {
		t.Fatalf("generating bob credential: %v", err)
	}

	bobKeyPackage, _, err := keypackages.Generate(bobCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating bob key package: %v", err)
	}

	// Alice crea commit para agregar a Bob
	_, _ = aliceGroup.AddMember(bobKeyPackage)
	sigPriv := ciphersuite.NewSignaturePrivateKey(alicePrivKeys.SignatureKey)
	sigPub := sigPriv.PublicKey()
	stagedCommit, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		t.Fatalf("creating commit: %v", err)
	}

	// Guardar epoch actual
	currentEpoch := aliceGroup.GroupContext.Epoch.AsUint64()

	// Caso 1: Commit con epoch futuro (current + 1)
	stagedCommit.AuthenticatedContent.Content.Epoch = currentEpoch + 1
	err = aliceGroup.MergeCommit(stagedCommit)
	if err == nil {
		t.Error("MergeCommit should fail with future epoch")
	}

	// Caso 2: Commit con epoch pasado (current - 1, simulando replay)
	stagedCommit.AuthenticatedContent.Content.Epoch = currentEpoch - 1
	err = aliceGroup.MergeCommit(stagedCommit)
	if err == nil {
		t.Error("MergeCommit should fail with past epoch (replay)")
	}

	// Caso 3: Commit con epoch correcto debe funcionar
	stagedCommit.AuthenticatedContent.Content.Epoch = currentEpoch
	err = aliceGroup.MergeCommit(stagedCommit)
	if err != nil {
		t.Errorf("MergeCommit should succeed with correct epoch: %v", err)
	}
}

// TestMergeCommit_WrongGroupID verifica que MergeCommit rechaza commits con GroupID incorrecto.
// Fase 1.3: Validación de GroupID
func TestMergeCommit_WrongGroupID(t *testing.T) {
	// Crear grupo con Alice
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

	// Crear KeyPackage para Bob
	bobCred, _, err := credentials.GenerateCredentialWithKey([]byte("bob"))
	if err != nil {
		t.Fatalf("generating bob credential: %v", err)
	}

	bobKeyPackage, _, err := keypackages.Generate(bobCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating bob key package: %v", err)
	}

	// Alice crea commit para agregar a Bob
	_, _ = aliceGroup.AddMember(bobKeyPackage)
	sigPriv := ciphersuite.NewSignaturePrivateKey(alicePrivKeys.SignatureKey)
	sigPub := sigPriv.PublicKey()
	stagedCommit, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		t.Fatalf("creating commit: %v", err)
	}

	// Cambiar GroupID
	stagedCommit.AuthenticatedContent.Content.GroupID = []byte("wrong-group")

	// Intentar mergear debe fallar por GroupID incorrecto
	err = aliceGroup.MergeCommit(stagedCommit)
	if err == nil {
		t.Error("MergeCommit should fail with wrong GroupID")
	}
}

// TestProcessReceivedCommit_WrongGroupID verifica que ProcessReceivedCommit rechaza commits con GroupID incorrecto.
// Fase 1.3: Validación de GroupID en ProcessReceivedCommit
func TestProcessReceivedCommit_WrongGroupID(t *testing.T) {
	// Crear grupo con Alice
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

	// Crear KeyPackage para Bob
	bobCred, _, err := credentials.GenerateCredentialWithKey([]byte("bob"))
	if err != nil {
		t.Fatalf("generating bob credential: %v", err)
	}

	bobKeyPackage, bobPrivKeys, err := keypackages.Generate(bobCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating bob key package: %v", err)
	}

	// Alice agrega a Bob
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

	// Crear otro grupo (simulando cross-group attack)
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

	// Crear commit en other-group
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

	// Intentar procesar el commit de other-group en aliceGroup debe fallar
	err = aliceGroup.ProcessReceivedCommit(
		stagedCommit2.AuthenticatedContent,
		treesync.LeafIndex(aliceGroup.OwnLeafIndex),
		bobPrivKeys.InitKey.Bytes(),
	)
	if err == nil {
		t.Error("ProcessReceivedCommit should fail with wrong GroupID")
	}
}

// TestProcessReceivedCommit_EpochMismatch verifica que ProcessReceivedCommit rechaza commits con epoch incorrecto.
// Fase 1.2: Validación de epoch en ProcessReceivedCommit
func TestProcessReceivedCommit_EpochMismatch(t *testing.T) {
	// Crear grupo con Alice
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

	// Crear KeyPackage para Bob
	bobCred, _, err := credentials.GenerateCredentialWithKey([]byte("bob"))
	if err != nil {
		t.Fatalf("generating bob credential: %v", err)
	}

	bobKeyPackage, bobPrivKeys, err := keypackages.Generate(bobCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating bob key package: %v", err)
	}

	// Alice agrega a Bob
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

	// Ahora Bob procesa un commit con epoch incorrecto
	// Crear commit con epoch futuro
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

	// Corromper epoch
	stagedCommit2.AuthenticatedContent.Content.Epoch = 999

	// Bob intenta procesar el commit - debe fallar por epoch
	err = aliceGroup.ProcessReceivedCommit(
		stagedCommit2.AuthenticatedContent,
		treesync.LeafIndex(aliceGroup.OwnLeafIndex),
		bobPrivKeys.InitKey.Bytes(),
	)
	if err == nil {
		t.Error("ProcessReceivedCommit should fail with wrong epoch")
	}
}
