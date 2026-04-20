package group

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	mlsext "github.com/thomas-vilte/mls-go/extensions"
	"github.com/thomas-vilte/mls-go/keypackages"
)

func hasGroupInfoExtension(extensions []Extension, extType mlsext.ExtensionType) bool {
	for _, ext := range extensions {
		if ext.Type == extType {
			return true
		}
	}
	return false
}

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

	if !bytes.Equal(got.GroupContext.GroupID.AsSlice(), g.groupContext.GroupID.AsSlice()) {
		t.Error("GroupID match after unmarshal")
	}
	if got.GroupContext.Epoch.AsUint64() != g.groupContext.Epoch.AsUint64() {
		t.Errorf("Epoch = %d, want %d", got.GroupContext.Epoch.AsUint64(), g.groupContext.Epoch.AsUint64())
	}
	if got.GroupContext.CipherSuite != g.groupContext.CipherSuite {
		t.Errorf("CipherSuite = %d, want %d", got.GroupContext.CipherSuite, g.groupContext.CipherSuite)
	}
	if !bytes.Equal(got.GroupContext.TreeHash, g.groupContext.TreeHash) {
		t.Error("TreeHash match after unmarshal")
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

	// Force non-operational state by creating a pending commit.
	cred2, _, _ := credentials.GenerateCredentialWithKey([]byte("bob"))
	kp2, _, _ := keypackages.Generate(cred2, keypackages.MLS128DHKEMP256)
	if _, err := g.AddMember(kp2); err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}
	sigPriv := ciphersuite.NewSignaturePrivateKey(priv.SignatureKey)
	sigPub := sigPriv.PublicKey()
	if _, err := g.Commit(sigPriv, sigPub, nil); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	_, err = g.GetGroupInfo(sigPriv)
	if err == nil {
		t.Error("GetGroupInfo should fail when group is not in operational state")
	}
}

func TestGetGroupInfoWithOptions_OmitsOptionalExtensions(t *testing.T) {
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

	defaultInfo, err := g.GetGroupInfo(sigPriv)
	if err != nil {
		t.Fatalf("GetGroupInfo: %v", err)
	}
	if !hasGroupInfoExtension(defaultInfo.Extensions, mlsext.ExtensionTypeRatchetTree) {
		t.Fatal("default GroupInfo should include ratchet_tree extension")
	}
	if !hasGroupInfoExtension(defaultInfo.Extensions, mlsext.ExtensionTypeExternalPub) {
		t.Fatal("default GroupInfo should include external_pub extension")
	}

	customInfo, err := g.GetGroupInfoWithOptions(sigPriv, WithRatchetTree(false), WithExternalPub(false))
	if err != nil {
		t.Fatalf("GetGroupInfoWithOptions: %v", err)
	}
	if hasGroupInfoExtension(customInfo.Extensions, mlsext.ExtensionTypeRatchetTree) {
		t.Fatal("ratchet_tree extension should be omitted")
	}
	if hasGroupInfoExtension(customInfo.Extensions, mlsext.ExtensionTypeExternalPub) {
		t.Fatal("external_pub extension should be omitted")
	}
}
