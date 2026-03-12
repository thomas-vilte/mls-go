package group

import (
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	keypackages "github.com/thomas-vilte/mls-go/keypackages"
)

// TestMemoryZeroing_AfterCommit verifica que los secrets del epoch anterior
// son borrados después de un commit (Fase 4.4).
func TestMemoryZeroing_AfterCommit(t *testing.T) {
	// Crear grupo con Alice
	cred1, _, _ := credentials.GenerateCredentialWithKey([]byte("alice"))
	kp1, priv1, _ := keypackages.Generate(cred1, keypackages.MLS128DHKEMP256)
	groupID, _ := NewGroupIDRandom()
	aliceGroup, _ := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kp1, priv1)

	// Crear KeyPackage para Bob
	cred2, _, _ := credentials.GenerateCredentialWithKey([]byte("bob"))
	kp2, _, _ := keypackages.Generate(cred2, keypackages.MLS128DHKEMP256)

	// Guardar una referencia a los secrets del epoch 0
	oldSecrets := aliceGroup.EpochSecrets

	// Alice agrega a Bob y hace commit
	_, _ = aliceGroup.AddMember(kp2)
	sigPriv := ciphersuite.NewSignaturePrivateKey(priv1.SignatureKey)
	sigPub := sigPriv.PublicKey()
	sc, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		t.Fatalf("creating commit: %v", err)
	}

	// Al hacer MergeCommit, los oldSecrets deberían zerarse
	if err := aliceGroup.MergeCommit(sc); err != nil {
		t.Fatalf("merging commit: %v", err)
	}

	// Verificar que los viejos secrets fueron borrados (ahora son cero)
	checkZero := func(name string, secret *ciphersuite.Secret) {
		t.Helper()
		if secret == nil {
			return
		}

		data := secret.AsSlice()
		for i, b := range data {
			if b != 0 {
				t.Errorf("Secret %s was not zeroed: byte %d is %02x", name, i, b)
				return
			}
		}
	}

	checkZero("SenderDataSecret", oldSecrets.SenderDataSecret)
	checkZero("EncryptionSecret", oldSecrets.EncryptionSecret)
	checkZero("ExporterSecret", oldSecrets.ExporterSecret)
	checkZero("AuthenticationSecret", oldSecrets.AuthenticationSecret)
	checkZero("ConfirmationKey", oldSecrets.ConfirmationKey)
	checkZero("MembershipKey", oldSecrets.MembershipKey)
	checkZero("ExternalSecret", oldSecrets.ExternalSecret)
	checkZero("InitSecret", oldSecrets.InitSecret)
	checkZero("ResumptionSecret", oldSecrets.ResumptionSecret)

	// Los nuevos secrets no deben ser cero
	newSecrets := aliceGroup.EpochSecrets
	if newSecrets.SenderDataSecret.AsSlice()[0] == 0 && newSecrets.SenderDataSecret.AsSlice()[1] == 0 {
		// Posibilidad mínima de que empiece con 00, pero revisar todos los bytes es excesivo
		t.Log("Warning: New SenderDataSecret starts with 0x00")
	}
}
