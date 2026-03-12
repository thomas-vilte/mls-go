package keypackages_test

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/credentials"
	kp "github.com/thomas-vilte/mls-go/keypackages"
)

func newCredWithKey(t *testing.T, identity string) *credentials.CredentialWithKey {
	t.Helper()
	c, _, err := credentials.GenerateCredentialWithKey([]byte(identity))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(%s): %v", identity, err)
	}
	return c
}

func TestKeyPackageGenerate(t *testing.T) {
	keyPackage, privKeys, err := kp.Generate(newCredWithKey(t, "TestUser"), kp.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if keyPackage.ProtocolVersion != kp.MLS10 {
		t.Errorf("ProtocolVersion = %d, want MLS10", keyPackage.ProtocolVersion)
	}
	if keyPackage.CipherSuite != kp.MLS128DHKEMP256 {
		t.Errorf("CipherSuite = %d, want MLS128DHKEMP256", keyPackage.CipherSuite)
	}
	if len(keyPackage.InitKey) == 0 {
		t.Error("InitKey is empty")
	}
	if keyPackage.LeafNode == nil {
		t.Fatal("LeafNode is nil")
	}
	if len(keyPackage.Signature) == 0 {
		t.Error("Signature is empty")
	}
	if privKeys.InitKey == nil {
		t.Error("privKeys.InitKey is nil")
	}
	if privKeys.SignatureKey == nil {
		t.Error("privKeys.SignatureKey is nil")
	}
}

func TestKeyPackageGenerate_NilCredential(t *testing.T) {
	_, _, err := kp.Generate(nil, kp.MLS128DHKEMP256)
	if err == nil {
		t.Fatal("Generate with nil credential should fail")
	}
}

func TestKeyPackage_IsRandom(t *testing.T) {
	// Two Generate calls must produce different bytes (HPKE keys are random).
	kp1, _, _ := kp.Generate(newCredWithKey(t, "User"), kp.MLS128DHKEMP256)
	kp2, _, _ := kp.Generate(newCredWithKey(t, "User"), kp.MLS128DHKEMP256)
	if bytes.Equal(kp1.Marshal(), kp2.Marshal()) {
		t.Error("two Generate calls produced identical bytes — missing randomness")
	}
}

func TestKeyPackageHash_DeterministicAndUnique(t *testing.T) {
	kp1, _, _ := kp.Generate(newCredWithKey(t, "Alice"), kp.MLS128DHKEMP256)
	h1a := kp1.Hash()
	h1b := kp1.Hash()
	if !bytes.Equal(h1a, h1b) {
		t.Error("Hash() is not deterministic")
	}
	if len(h1a) != 32 {
		t.Errorf("Hash length = %d, want 32", len(h1a))
	}

	kp2, _, _ := kp.Generate(newCredWithKey(t, "Bob"), kp.MLS128DHKEMP256)
	if bytes.Equal(h1a, kp2.Hash()) {
		t.Error("Different KeyPackages produced the same hash")
	}
}

func TestKeyPackageCapabilities(t *testing.T) {
	keyPackage, _, _ := kp.Generate(newCredWithKey(t, "CapsTest"), kp.MLS128DHKEMP256)
	caps := keyPackage.LeafNode.Capabilities
	if caps == nil {
		t.Fatal("Capabilities is nil")
	}
	if len(caps.ProtocolVersions) == 0 {
		t.Error("ProtocolVersions is empty")
	}
	if len(caps.CipherSuites) == 0 {
		t.Error("CipherSuites is empty")
	}
	foundMLS10 := false
	for _, v := range caps.ProtocolVersions {
		if v == kp.MLS10 {
			foundMLS10 = true
		}
	}
	if !foundMLS10 {
		t.Error("MLS 1.0 not in ProtocolVersions")
	}
}

func TestKeyPackageLifetime(t *testing.T) {
	keyPackage, _, _ := kp.Generate(newCredWithKey(t, "LifetimeTest"), kp.MLS128DHKEMP256)
	lt := keyPackage.LeafNode.Lifetime
	if lt == nil {
		t.Fatal("Lifetime is nil")
	}
	if lt.NotBefore == 0 {
		t.Error("NotBefore should be set")
	}
	if lt.NotAfter <= lt.NotBefore {
		t.Error("NotAfter should be after NotBefore")
	}
	if lt.NotAfter-lt.NotBefore < 24*60*60 {
		t.Error("Lifetime too short (< 24h)")
	}
}
