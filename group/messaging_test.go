package group

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/keypackages"
)

func tamperApplicationMessageSignature(t *testing.T, senderGroup *Group, pm *framing.PrivateMessage) *framing.PrivateMessage {
	t.Helper()

	ac, err := framing.Decrypt(pm, framing.DecryptParams{
		CipherSuite:      senderGroup.CipherSuite,
		SenderDataSecret: senderGroup.EpochSecrets.SenderDataSecret,
		SecretTree:       senderGroup.SecretTree,
		GroupContext:     senderGroup.GroupContext.Marshal(),
	})
	if err != nil {
		t.Fatalf("Decrypt(sender): %v", err)
	}

	sig := ac.Auth.Signature.AsSlice()
	if len(sig) == 0 {
		t.Fatal("signature is empty")
	}
	sig[0] ^= 0xFF

	tampered, err := framing.Encrypt(framing.EncryptParams{
		AuthContent:      ac,
		SenderLeafIndex:  uint32(senderGroup.OwnLeafIndex),
		CipherSuite:      senderGroup.CipherSuite,
		PaddingSize:      senderGroup.PaddingSize,
		SenderDataSecret: senderGroup.EpochSecrets.SenderDataSecret,
		SecretTree:       senderGroup.SecretTree,
	})
	if err != nil {
		t.Fatalf("Encrypt(tampered): %v", err)
	}

	return tampered
}

// TestSendMessage_EmptyPayload verifies that SendMessage funciona con payload vacío
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
	// completa de secrets entre Alice y Bob, lo cual se prueba en integration_test.go
}

// TestSendMessage_NilSignKey verifies that SendMessage fails con sigKey nil
func TestSendMessage_NilSignKey(t *testing.T) {
	aliceGroup, _, _, _ := setupTwoMemberGroup(t)

	// Intentar enviar con signature key nil
	_, err := aliceGroup.SendMessage([]byte("hola"), nil)
	if err == nil {
		t.Error("SendMessage should fail with nil signature key")
	}
}

// TestReceiveMessage_WrongSender verifies that ReceiveMessage fails con sender inválido
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

// TestSendMessage_WrongState verifies that SendMessage fails si el grupo no está operational
func TestSendMessage_WrongState(t *testing.T) {
	// Create grupo pero forzar estado no operational (solo para test)
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

	// Force estado no operational (hack para test)
	group.state = StateInactive

	// Intentar enviar mensaje
	sigPriv := ciphersuite.NewSignaturePrivateKey(priv.SignatureKey)
	_, err = group.SendMessage([]byte("hola"), sigPriv)
	if err == nil {
		t.Error("SendMessage should fail when group is not operational")
	}
}

// TestReceiveMessage_NilMessage verifies that ReceiveMessage fails con mensaje nil
func TestReceiveMessage_NilMessage(t *testing.T) {
	_, bobGroup, _, _ := setupTwoMemberGroup(t)

	// Intentar recibir mensaje nil
	_, err := bobGroup.ReceiveMessage(nil, 0)
	if err == nil {
		t.Error("ReceiveMessage should fail with nil message")
	}
}

// TestSendMessage_NoSecretTree verifies that SendMessage fails sin SecretTree
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

// TestReceiveMessage_NoSecretTree verifies that ReceiveMessage fails sin SecretTree
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

func TestReceiveApplicationMessage_VerifiesSignature(t *testing.T) {
	aliceGroup, bobGroup, alice, _ := makeTwoMemberGroups(t)

	msg := []byte("hello bob")
	aad := []byte("aad")
	pm, err := aliceGroup.SendApplicationMessage(msg, aad, alice.sigPriv)
	if err != nil {
		t.Fatalf("SendApplicationMessage: %v", err)
	}

	got, gotAAD, err := bobGroup.ReceiveApplicationMessage(pm)
	if err != nil {
		t.Fatalf("ReceiveApplicationMessage(valid): %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("plaintext = %q, want %q", got, msg)
	}
	if !bytes.Equal(gotAAD, aad) {
		t.Fatalf("authenticated data = %x, want %x", gotAAD, aad)
	}

	tampered := tamperApplicationMessageSignature(t, aliceGroup, pm)
	if _, _, err := bobGroup.ReceiveApplicationMessage(tampered); err == nil {
		t.Fatal("ReceiveApplicationMessage should fail with tampered signature")
	}
}

func TestReceiveApplicationMessage_OldEpochUsesHistoricalContext(t *testing.T) {
	aliceGroup, bobGroup, alice, _ := makeTwoMemberGroups(t)

	msg := []byte("message from previous epoch")
	aad := []byte("epoch1")
	pm, err := aliceGroup.SendApplicationMessage(msg, aad, alice.sigPriv)
	if err != nil {
		t.Fatalf("SendApplicationMessage: %v", err)
	}

	charlieCred, _, err := credentials.GenerateCredentialWithKey([]byte("Charlie-OldEpoch"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(Charlie): %v", err)
	}
	charlieKP, _, err := keypackages.Generate(charlieCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage(Charlie): %v", err)
	}

	if _, err := aliceGroup.AddMember(charlieKP); err != nil {
		t.Fatalf("AddMember(Charlie): %v", err)
	}
	stagedCommit, err := aliceGroup.Commit(alice.sigPriv, alice.sigPub, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := bobGroup.ProcessCommit(stagedCommit); err != nil {
		t.Fatalf("ProcessCommit(bob): %v", err)
	}
	if err := aliceGroup.MergeCommit(stagedCommit); err != nil {
		t.Fatalf("MergeCommit(alice): %v", err)
	}

	history, ok := bobGroup.EpochHistory[1]
	if !ok {
		t.Fatal("epoch 1 not cached in EpochHistory")
	}
	if history.GroupContext == nil {
		t.Fatal("historical GroupContext is nil")
	}

	got, gotAAD, err := bobGroup.ReceiveApplicationMessage(pm)
	if err != nil {
		t.Fatalf("ReceiveApplicationMessage(old epoch): %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("plaintext = %q, want %q", got, msg)
	}
	if !bytes.Equal(gotAAD, aad) {
		t.Fatalf("authenticated data = %x, want %x", gotAAD, aad)
	}
}

func TestVerifyPublicMessage_NewMemberCommit_VerifiesSignature(t *testing.T) {
	aliceGroup, _, alice, _ := makeTwoMemberGroups(t)
	charlie := newTestUser(t, "charlie-new-member-commit")

	groupInfo, err := aliceGroup.GetGroupInfo(alice.sigPriv)
	if err != nil {
		t.Fatalf("GetGroupInfo: %v", err)
	}

	_, stagedCommit, err := ExternalCommit(
		groupInfo,
		aliceGroup.CipherSuite,
		charlie.sigPriv,
		charlie.sigPub,
		-1,
		charlie.kp.LeafNode.Credential,
	)
	if err != nil {
		t.Fatalf("ExternalCommit: %v", err)
	}

	pm := &framing.PublicMessage{
		Content: stagedCommit.AuthenticatedContent.Content,
		Auth:    stagedCommit.AuthenticatedContent.Auth,
	}
	if err := aliceGroup.VerifyPublicMessage(pm); err != nil {
		t.Fatalf("VerifyPublicMessage(valid): %v", err)
	}

	sig := pm.Auth.Signature.AsSlice()
	if len(sig) == 0 {
		t.Fatal("signature is empty")
	}
	sig[0] ^= 0xFF
	if err := aliceGroup.VerifyPublicMessage(pm); err == nil {
		t.Fatal("VerifyPublicMessage should fail with tampered new member commit signature")
	}
}

func TestSendMessage_UsesConfiguredPadding(t *testing.T) {
	aliceNoPad, _, alicePrivNoPad, _ := setupTwoMemberGroup(t)
	alicePad, _, alicePrivPad, _ := setupTwoMemberGroup(t)
	alicePad.PaddingSize = 32

	msg := []byte("short")
	pmNoPad, err := aliceNoPad.SendMessage(msg, ciphersuite.NewSignaturePrivateKey(alicePrivNoPad.SignatureKey))
	if err != nil {
		t.Fatalf("SendMessage(no padding): %v", err)
	}
	pmPad, err := alicePad.SendMessage(msg, ciphersuite.NewSignaturePrivateKey(alicePrivPad.SignatureKey))
	if err != nil {
		t.Fatalf("SendMessage(with padding): %v", err)
	}

	if len(pmPad.Ciphertext) <= len(pmNoPad.Ciphertext) {
		t.Fatalf("padded ciphertext len = %d, want > %d", len(pmPad.Ciphertext), len(pmNoPad.Ciphertext))
	}
}

func TestSendApplicationMessage_UsesConfiguredPadding(t *testing.T) {
	aliceNoPad, _, alicePrivNoPad, _ := setupTwoMemberGroup(t)
	alicePad, _, alicePrivPad, _ := setupTwoMemberGroup(t)
	alicePad.PaddingSize = 32

	msg := []byte("short")
	aad := []byte("aad")
	pmNoPad, err := aliceNoPad.SendApplicationMessage(msg, aad, ciphersuite.NewSignaturePrivateKey(alicePrivNoPad.SignatureKey))
	if err != nil {
		t.Fatalf("SendApplicationMessage(no padding): %v", err)
	}
	pmPad, err := alicePad.SendApplicationMessage(msg, aad, ciphersuite.NewSignaturePrivateKey(alicePrivPad.SignatureKey))
	if err != nil {
		t.Fatalf("SendApplicationMessage(with padding): %v", err)
	}

	if len(pmPad.Ciphertext) <= len(pmNoPad.Ciphertext) {
		t.Fatalf("padded ciphertext len = %d, want > %d", len(pmPad.Ciphertext), len(pmNoPad.Ciphertext))
	}
}
