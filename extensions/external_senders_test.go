package extensions_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/openmls/go/credentials"
	"github.com/openmls/go/extensions"
)

// Helper: genera un keypair ECDSA para tests
func generateECDSAKey(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	return privKey, &privKey.PublicKey
}

// Helper: genera una credential básica
func generateBasicCredential(t *testing.T, identifier []byte) *credentials.Credential {
	t.Helper()
	cred := credentials.NewBasicCredential(identifier)
	return cred
}

// TestExternalSendersExtension_New prueba creación
func TestExternalSendersExtension_New(t *testing.T) {
	ext := extensions.NewExternalSendersExtension()
	if ext == nil {
		t.Fatal("NewExternalSendersExtension should return non-nil")
	}
	if ext.Len() != 0 {
		t.Errorf("Expected Len() = 0, got %d", ext.Len())
	}
}

// TestExternalSendersExtension_AddSenderValid prueba agregar sender válido
func TestExternalSendersExtension_AddSenderValid(t *testing.T) {
	_, pubKey := generateECDSAKey(t)
	cred := generateBasicCredential(t, []byte("sender"))

	sender := extensions.ExternalSender{
		Credential: cred,
		PublicKey:  pubKey,
	}

	ext := extensions.NewExternalSendersExtension()
	if err := ext.AddSender(sender); err != nil {
		t.Fatalf("AddSender failed: %v", err)
	}

	if ext.Len() != 1 {
		t.Errorf("Expected Len() = 1, got %d", ext.Len())
	}

	if err := ext.Validate(); err != nil {
		t.Errorf("Validate should succeed: %v", err)
	}
}

// TestExternalSendersExtension_ValidateNilCredential prueba validación con credential nil
func TestExternalSendersExtension_ValidateNilCredential(t *testing.T) {
	_, pubKey := generateECDSAKey(t)

	ext := extensions.NewExternalSendersExtension()
	ext.Senders = append(ext.Senders, extensions.ExternalSender{
		Credential: nil,
		PublicKey:  pubKey,
	})

	if err := ext.Validate(); err == nil {
		t.Error("Validate should fail with nil credential")
	}
}

// TestExternalSendersExtension_ValidateNilPubKey prueba validación con pubkey nil
func TestExternalSendersExtension_ValidateNilPubKey(t *testing.T) {
	cred := generateBasicCredential(t, []byte("sender"))

	ext := extensions.NewExternalSendersExtension()
	ext.Senders = append(ext.Senders, extensions.ExternalSender{
		Credential: cred,
		PublicKey:  nil,
	})

	if err := ext.Validate(); err == nil {
		t.Error("Validate should fail with nil public key")
	}
}

// TestExternalSendersExtension_FindSender prueba búsqueda por credential
func TestExternalSendersExtension_FindSender(t *testing.T) {
	cred1 := generateBasicCredential(t, []byte("sender1"))
	_, pubKey1 := generateECDSAKey(t)

	cred2 := generateBasicCredential(t, []byte("sender2"))
	_, pubKey2 := generateECDSAKey(t)

	ext := extensions.NewExternalSendersExtension()
	ext.Senders = append(ext.Senders, extensions.ExternalSender{
		Credential: cred1,
		PublicKey:  pubKey1,
	})
	ext.Senders = append(ext.Senders, extensions.ExternalSender{
		Credential: cred2,
		PublicKey:  pubKey2,
	})

	found, ok := ext.FindSender(cred1)
	if !ok {
		t.Error("FindSender should find existing sender")
	}
	if found == nil {
		t.Fatal("FindSender should return non-nil sender")
	}

	cred3 := generateBasicCredential(t, []byte("sender3"))
	_, ok = ext.FindSender(cred3)
	if ok {
		t.Error("FindSender should not find non-existent sender")
	}
}

// TestExternalSendersExtension_FindSenderByPublicKey prueba búsqueda por pubkey
func TestExternalSendersExtension_FindSenderByPublicKey(t *testing.T) {
	cred1 := generateBasicCredential(t, []byte("sender1"))
	_, pubKey1 := generateECDSAKey(t)

	cred2 := generateBasicCredential(t, []byte("sender2"))
	_, pubKey2 := generateECDSAKey(t)

	ext := extensions.NewExternalSendersExtension()
	ext.Senders = append(ext.Senders, extensions.ExternalSender{
		Credential: cred1,
		PublicKey:  pubKey1,
	})
	ext.Senders = append(ext.Senders, extensions.ExternalSender{
		Credential: cred2,
		PublicKey:  pubKey2,
	})

	found, ok := ext.FindSenderByPublicKey(pubKey1)
	if !ok {
		t.Error("FindSenderByPublicKey should find existing sender")
	}
	if found == nil {
		t.Fatal("FindSenderByPublicKey should return non-nil sender")
	}

	_, pubKey3 := generateECDSAKey(t)
	_, ok = ext.FindSenderByPublicKey(pubKey3)
	if ok {
		t.Error("FindSenderByPublicKey should not find non-existent sender")
	}
}

// TestExternalSendersExtension_ToExtension prueba conversión a Extension
func TestExternalSendersExtension_ToExtension(t *testing.T) {
	_, pubKey := generateECDSAKey(t)
	cred := generateBasicCredential(t, []byte("sender"))

	ext := extensions.NewExternalSendersExtension()
	ext.Senders = append(ext.Senders, extensions.ExternalSender{
		Credential: cred,
		PublicKey:  pubKey,
	})

	genExt, err := ext.ToExtension()
	if err != nil {
		t.Fatalf("ToExtension failed: %v", err)
	}
	if genExt == nil {
		t.Fatal("ToExtension should return non-nil Extension")
	}

	if genExt.Type != 5 {
		t.Errorf("Expected ExtensionType = 5, got %d", genExt.Type)
	}
}

// TestExternalSenderEqual prueba comparación de senders
func TestExternalSenderEqual(t *testing.T) {
	cred1 := generateBasicCredential(t, []byte("sender1"))
	_, pubKey1 := generateECDSAKey(t)

	cred2 := generateBasicCredential(t, []byte("sender2"))
	_, pubKey2 := generateECDSAKey(t)

	sender1 := extensions.ExternalSender{
		Credential: cred1,
		PublicKey:  pubKey1,
	}

	sender2 := extensions.ExternalSender{
		Credential: cred2,
		PublicKey:  pubKey2,
	}

	if sender1.Equal(&sender2) {
		t.Error("Different senders should not be equal")
	}

	sender1Copy := extensions.ExternalSender{
		Credential: cred1,
		PublicKey:  pubKey1,
	}

	if !sender1.Equal(&sender1Copy) {
		t.Error("Same senders should be equal")
	}
}

// TestExternalSendersExtension_Marshal prueba marshaling básico
func TestExternalSendersExtension_Marshal(t *testing.T) {
	_, pubKey := generateECDSAKey(t)
	cred := generateBasicCredential(t, []byte("sender"))

	ext := extensions.NewExternalSendersExtension()
	ext.Senders = append(ext.Senders, extensions.ExternalSender{
		Credential: cred,
		PublicKey:  pubKey,
	})

	data := ext.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal returned empty data")
	}

	// Marshal dos veces debería ser determinístico
	data2 := ext.Marshal()
	if !bytes.Equal(data, data2) {
		t.Error("Marshal should be deterministic")
	}
}

// TestExternalSendersExtension_Empty prueba extensión vacía
func TestExternalSendersExtension_Empty(t *testing.T) {
	ext := extensions.NewExternalSendersExtension()

	data := ext.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal returned empty data")
	}
}

// TestExternalSendersExtension_MultipleSenders prueba con múltiples senders
func TestExternalSendersExtension_MultipleSenders(t *testing.T) {
	ext := extensions.NewExternalSendersExtension()

	for i := 0; i < 5; i++ {
		cred := generateBasicCredential(t, []byte("sender"))
		_, pubKey := generateECDSAKey(t)
		ext.Senders = append(ext.Senders, extensions.ExternalSender{
			Credential: cred,
			PublicKey:  pubKey,
		})
	}

	if ext.Len() != 5 {
		t.Errorf("Expected Len() = 5, got %d", ext.Len())
	}

	if err := ext.Validate(); err != nil {
		t.Errorf("Validate should succeed: %v", err)
	}
}

// TestExternalSendersExtension_AddSenderInvalid prueba agregar sender inválido
func TestExternalSendersExtension_AddSenderInvalid(t *testing.T) {
	ext := extensions.NewExternalSendersExtension()

	// Sender con credential nil
	sender := extensions.ExternalSender{
		Credential: nil,
		PublicKey:  nil,
	}

	if err := ext.AddSender(sender); err == nil {
		t.Error("AddSender should fail with invalid sender")
	}
}
