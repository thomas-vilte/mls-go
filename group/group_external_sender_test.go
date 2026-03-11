package group

import (
	"bytes"
	"testing"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/credentials"
	itls "github.com/openmls/go/internal/tls"
	keypackages "github.com/openmls/go/keypackages"
)

// buildExternalSendersExtData construye el payload de la extensión ExternalSenders
// con un único sender dado sigKey y credBytes.
func buildExternalSendersExtData(t *testing.T, sigKey []byte, credBytes []byte) []byte {
	t.Helper()
	w := itls.NewWriter()
	w.WriteVLBytes(sigKey)
	w.WriteVLBytes(credBytes)
	return w.Bytes()
}

func TestGetExternalSenderSigningKey_Found(t *testing.T) {
	cred, _, err := credentials.GenerateCredentialWithKey([]byte("alice"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey: %v", err)
	}
	kp, priv, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	gid, _ := NewGroupIDRandom()
	g, err := NewGroup(gid, ciphersuite.MLS128DHKEMP256, kp, priv)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}

	extPriv, extPubErr := ciphersuite.GenerateSignaturePrivateKey()
	if extPubErr != nil {
		t.Fatalf("GenerateSignaturePrivateKey: %v", extPubErr)
	}
	extSigKey := extPriv.PublicKey().AsSlice()
	extCredBytes := credentials.NewBasicCredentialFromString("external-sender").Marshal()

	extData := buildExternalSendersExtData(t, extSigKey, extCredBytes)
	g.GroupContext.Extensions = append(g.GroupContext.Extensions, Extension{
		Type: 0x0005,
		Data: extData,
	})

	got, err := g.getExternalSenderSigningKey(0)
	if err != nil {
		t.Fatalf("getExternalSenderSigningKey: %v", err)
	}
	if !bytes.Equal(got, extSigKey) {
		t.Errorf("sigKey = %x, want %x", got, extSigKey)
	}
}

func TestGetExternalSenderSigningKey_NoExtension(t *testing.T) {
	cred, _, err := credentials.GenerateCredentialWithKey([]byte("alice"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey: %v", err)
	}
	kp, priv, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	gid, _ := NewGroupIDRandom()
	g, err := NewGroup(gid, ciphersuite.MLS128DHKEMP256, kp, priv)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}

	_, err = g.getExternalSenderSigningKey(0)
	if err == nil {
		t.Error("expected error when ExternalSenders extension is absent")
	}
}

func TestGetExternalSenderSigningKey_OutOfRange(t *testing.T) {
	cred, _, err := credentials.GenerateCredentialWithKey([]byte("alice"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey: %v", err)
	}
	kp, priv, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	gid, _ := NewGroupIDRandom()
	g, err := NewGroup(gid, ciphersuite.MLS128DHKEMP256, kp, priv)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}

	extPriv, genErr := ciphersuite.GenerateSignaturePrivateKey()
	if genErr != nil {
		t.Fatalf("GenerateSignaturePrivateKey: %v", genErr)
	}
	extSigKey := extPriv.PublicKey().AsSlice()
	extCredBytes := credentials.NewBasicCredentialFromString("ext").Marshal()

	g.GroupContext.Extensions = append(g.GroupContext.Extensions, Extension{
		Type: 0x0005,
		Data: buildExternalSendersExtData(t, extSigKey, extCredBytes),
	})

	// Index 1 fuera de rango (solo hay 1 sender en la extensión).
	_, err = g.getExternalSenderSigningKey(1)
	if err == nil {
		t.Error("expected error for out-of-range sender index")
	}
}

func TestGetExternalSenderSigningKey_MultipleSenders(t *testing.T) {
	cred, _, err := credentials.GenerateCredentialWithKey([]byte("alice"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey: %v", err)
	}
	kp, priv, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	gid, _ := NewGroupIDRandom()
	g, err := NewGroup(gid, ciphersuite.MLS128DHKEMP256, kp, priv)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}

	extPriv0, _ := ciphersuite.GenerateSignaturePrivateKey()
	extPriv1, _ := ciphersuite.GenerateSignaturePrivateKey()
	key0 := extPriv0.PublicKey().AsSlice()
	key1 := extPriv1.PublicKey().AsSlice()
	credBytes := credentials.NewBasicCredentialFromString("ext").Marshal()

	w := itls.NewWriter()
	w.WriteVLBytes(key0)
	w.WriteVLBytes(credBytes)
	w.WriteVLBytes(key1)
	w.WriteVLBytes(credBytes)

	g.GroupContext.Extensions = append(g.GroupContext.Extensions, Extension{
		Type: 0x0005,
		Data: w.Bytes(),
	})

	got0, err := g.getExternalSenderSigningKey(0)
	if err != nil {
		t.Fatalf("getExternalSenderSigningKey(0): %v", err)
	}
	got1, err := g.getExternalSenderSigningKey(1)
	if err != nil {
		t.Fatalf("getExternalSenderSigningKey(1): %v", err)
	}

	if !bytes.Equal(got0, key0) {
		t.Error("sender 0 key mismatch")
	}
	if !bytes.Equal(got1, key1) {
		t.Error("sender 1 key mismatch")
	}
}
