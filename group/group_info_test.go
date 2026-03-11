package group

import (
	"bytes"
	"testing"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/credentials"
	keypackages "github.com/openmls/go/keypackages"
)

func TestUnmarshalGroupInfo_RoundTrip(t *testing.T) {
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

	sigPriv := ciphersuite.NewSignaturePrivateKey(priv.SignatureKey)
	gi, err := g.GetGroupInfo(sigPriv)
	if err != nil {
		t.Fatalf("GetGroupInfo: %v", err)
	}

	data := gi.Marshal()
	if len(data) == 0 {
		t.Fatal("GroupInfo.Marshal() returned empty data")
	}

	got, err := UnmarshalGroupInfo(data)
	if err != nil {
		t.Fatalf("UnmarshalGroupInfo: %v", err)
	}

	if !bytes.Equal(got.GroupContext.GroupID.AsSlice(), g.GroupContext.GroupID.AsSlice()) {
		t.Error("GroupID mismatch after unmarshal")
	}
	if got.GroupContext.Epoch.AsUint64() != g.GroupContext.Epoch.AsUint64() {
		t.Errorf("Epoch = %d, want %d", got.GroupContext.Epoch.AsUint64(), g.GroupContext.Epoch.AsUint64())
	}
	if got.GroupContext.CipherSuite != g.GroupContext.CipherSuite {
		t.Errorf("CipherSuite = %d, want %d", got.GroupContext.CipherSuite, g.GroupContext.CipherSuite)
	}
	if !bytes.Equal(got.GroupContext.TreeHash, g.GroupContext.TreeHash) {
		t.Error("TreeHash mismatch after unmarshal")
	}
}

func TestUnmarshalGroupInfo_Truncated(t *testing.T) {
	_, err := UnmarshalGroupInfo([]byte{0x00, 0x01})
	if err == nil {
		t.Error("expected error for truncated GroupInfo")
	}
}

func TestUnmarshalGroupInfo_Empty(t *testing.T) {
	_, err := UnmarshalGroupInfo([]byte{})
	if err == nil {
		t.Error("expected error for empty GroupInfo")
	}
}

func TestGetGroupInfo_NotOperational(t *testing.T) {
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

	// Forzar estado no-operacional creando un pending commit.
	cred2, _, _ := credentials.GenerateCredentialWithKey([]byte("bob"))
	kp2, _, _ := keypackages.Generate(cred2, keypackages.MLS128DHKEMP256)
	g.AddMember(kp2)
	sigPriv := ciphersuite.NewSignaturePrivateKey(priv.SignatureKey)
	sigPub := sigPriv.PublicKey()
	g.Commit(sigPriv, sigPub, nil)

	_, err = g.GetGroupInfo(sigPriv)
	if err == nil {
		t.Error("GetGroupInfo should fail when group is not in operational state")
	}
}
