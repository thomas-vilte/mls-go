package group

import (
	"testing"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/credentials"
	"github.com/openmls/go/framing"
	keypackages "github.com/openmls/go/keypackages"
)

// TestSendMessage_EmptyPayload verifica que SendMessage funciona con payload vacío
func TestSendMessage_EmptyPayload(t *testing.T) {
	aliceGroup, _, alicePriv, _ := setupTwoMemberGroup(t)

	// Enviar mensaje vacío (MLS lo permite)
	aliceSigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)

	pm, err := aliceGroup.SendMessage([]byte{}, aliceSigPriv)
	if err != nil {
		t.Fatalf("SendMessage with empty payload should succeed: %v", err)
	}

	if pm == nil {
		t.Fatal("SendMessage should return non-nil PrivateMessage")
	}

	// Nota: no probamos el ReceiveMessage aquí porque requiere sincronización
	// completa de secretos entre Alice y Bob, lo cual se prueba en integration_test.go
}

// TestSendMessage_NilSignKey verifica que SendMessage falla con sigKey nil
func TestSendMessage_NilSignKey(t *testing.T) {
	aliceGroup, _, _, _ := setupTwoMemberGroup(t)

	// Intentar enviar con signature key nil
	_, err := aliceGroup.SendMessage([]byte("hola"), nil)
	if err == nil {
		t.Error("SendMessage should fail with nil signature key")
	}
}

// TestReceiveMessage_WrongSender verifica que ReceiveMessage falla con sender inválido
func TestReceiveMessage_WrongSender(t *testing.T) {
	aliceGroup, bobGroup, alicePriv, _ := setupTwoMemberGroup(t)

	// Alice envía un mensaje
	aliceSigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)

	pm, err := aliceGroup.SendMessage([]byte("hola bob"), aliceSigPriv)
	if err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}

	// Bob intenta recibir con un sender index que no existe
	_, err = bobGroup.ReceiveMessage(pm, 9999)
	if err == nil {
		t.Error("ReceiveMessage should fail with out-of-bounds sender index")
	}
}

// TestSendMessage_WrongState verifica que SendMessage falla si el grupo no está operacional
func TestSendMessage_WrongState(t *testing.T) {
	// Crear grupo pero forzar estado no operacional (solo para test)
	cred, _, err := credentials.GenerateCredentialWithKey([]byte("User"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey: %v", err)
	}

	kp, priv, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage: %v", err)
	}

	groupID, err := NewGroupIDRandom()
	if err != nil {
		t.Fatalf("NewGroupIDRandom: %v", err)
	}

	group, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kp, priv)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}

	// Forzar estado no operacional (hack para test)
	group.state = StateInactive

	// Intentar enviar mensaje
	sigPriv := ciphersuite.NewSignaturePrivateKey(priv.SignatureKey)
	_, err = group.SendMessage([]byte("hola"), sigPriv)
	if err == nil {
		t.Error("SendMessage should fail when group is not operational")
	}
}

// TestReceiveMessage_NilMessage verifica que ReceiveMessage falla con mensaje nil
func TestReceiveMessage_NilMessage(t *testing.T) {
	_, bobGroup, _, _ := setupTwoMemberGroup(t)

	// Intentar recibir mensaje nil
	_, err := bobGroup.ReceiveMessage(nil, 0)
	if err == nil {
		t.Error("ReceiveMessage should fail with nil message")
	}
}

// TestSendMessage_NoSecretTree verifica que SendMessage falla sin SecretTree
func TestSendMessage_NoSecretTree(t *testing.T) {
	aliceGroup, _, alicePriv, _ := setupTwoMemberGroup(t)

	// Corromper el grupo removiendo el SecretTree (solo para test)
	originalTree := aliceGroup.SecretTree
	aliceGroup.SecretTree = nil

	aliceSigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)
	_, err := aliceGroup.SendMessage([]byte("hola"), aliceSigPriv)
	if err == nil {
		t.Error("SendMessage should fail without SecretTree")
	}

	// Restaurar
	aliceGroup.SecretTree = originalTree
}

// TestReceiveMessage_NoSecretTree verifica que ReceiveMessage falla sin SecretTree
func TestReceiveMessage_NoSecretTree(t *testing.T) {
	_, bobGroup, _, _ := setupTwoMemberGroup(t)

	// Corromper el grupo removiendo el SecretTree (solo para test)
	originalTree := bobGroup.SecretTree
	bobGroup.SecretTree = nil

	pm := &framing.PrivateMessage{}
	_, err := bobGroup.ReceiveMessage(pm, 0)
	if err == nil {
		t.Error("ReceiveMessage should fail without SecretTree")
	}

	// Restaurar
	bobGroup.SecretTree = originalTree
}
