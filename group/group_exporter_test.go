package group

import (
	"bytes"
	"testing"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/credentials"
	keypackages "github.com/openmls/go/keypackages"
)

// TestExport_Basic verifica que Export deriva keys consistentes (RFC 9420 §8.5).
func TestExport_Basic(t *testing.T) {
	// Crear grupo con Alice
	cred1, _, err := credentials.GenerateCredentialWithKey([]byte("alice"))
	if err != nil {
		t.Fatalf("generating alice credential: %v", err)
	}
	kp1, priv1, err := keypackages.Generate(cred1, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating alice key package: %v", err)
	}

	groupID, _ := NewGroupIDRandom()
	aliceGroup, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kp1, priv1)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}

	// Export con mismo label y context debe dar mismo resultado
	label := "test-label"
	context := []byte("test-context")
	length := 32

	key1, err := aliceGroup.Export(label, context, length)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	if len(key1) != length {
		t.Errorf("Export length = %d, want %d", len(key1), length)
	}

	// Segunda export con mismos parámetros debe dar igual resultado
	key2, err := aliceGroup.Export(label, context, length)
	if err != nil {
		t.Fatalf("Export second call failed: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Error("Export should be deterministic")
	}

	// Export con diferente label debe dar diferente resultado
	key3, _ := aliceGroup.Export("different-label", context, length)
	if bytes.Equal(key1, key3) {
		t.Error("Different label should produce different key")
	}
}

// TestExport_WhenNotOperational verifica que Export falla si el grupo no está operacional.
func TestExport_WhenNotOperational(t *testing.T) {
	cred, _, err := credentials.GenerateCredentialWithKey([]byte("alice"))
	if err != nil {
		t.Fatalf("generating credential: %v", err)
	}
	kp, priv, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating key package: %v", err)
	}

	groupID, _ := NewGroupIDRandom()
	group, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kp, priv)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}

	// Crear un commit pendiente cambia el estado
	cred2, _, _ := credentials.GenerateCredentialWithKey([]byte("bob"))
	kp2, _, _ := keypackages.Generate(cred2, keypackages.MLS128DHKEMP256)
	group.AddMember(kp2)
	sigPriv := ciphersuite.NewSignaturePrivateKey(priv.SignatureKey)
	sigPub := sigPriv.PublicKey()
	group.Commit(sigPriv, sigPub, nil) // Estado cambia a PendingCommit

	// Export debería fallar porque el grupo está en PendingCommit
	_, err = group.Export("label", nil, 32)
	if err == nil {
		t.Error("Export should fail when group is not operational")
	}
}

// TestExport_AfterCommit verifica que Export funciona después de un commit.
func TestExport_AfterCommit(t *testing.T) {
	// Crear grupo con Alice
	cred1, _, err := credentials.GenerateCredentialWithKey([]byte("alice"))
	if err != nil {
		t.Fatalf("generating alice credential: %v", err)
	}
	kp1, priv1, err := keypackages.Generate(cred1, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating alice key package: %v", err)
	}

	groupID, _ := NewGroupIDRandom()
	aliceGroup, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kp1, priv1)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}

	// Crear KeyPackage para Bob
	cred2, _, err := credentials.GenerateCredentialWithKey([]byte("bob"))
	if err != nil {
		t.Fatalf("generating bob credential: %v", err)
	}
	kp2, _, err := keypackages.Generate(cred2, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating bob key package: %v", err)
	}

	// Agregar a Bob y hacer commit
	_, _ = aliceGroup.AddMember(kp2)
	sigPriv := ciphersuite.NewSignaturePrivateKey(priv1.SignatureKey)
	sigPub := sigPriv.PublicKey()
	sc, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		t.Fatalf("creating commit: %v", err)
	}
	if err := aliceGroup.MergeCommit(sc); err != nil {
		t.Fatalf("merging commit: %v", err)
	}

	// Export debería funcionar después del commit
	key, err := aliceGroup.Export("media-key", []byte("context"), 32)
	if err != nil {
		t.Fatalf("Export after commit failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("Export length = %d, want 32", len(key))
	}
}
