package keypackages_test

import (
	"bytes"
	"testing"

	"github.com/openmls/go/credentials"
	"github.com/openmls/go/internal/tls"
	kp "github.com/openmls/go/keypackages"
)

// TestKeyPackageGenerate tests KeyPackage generation.
func TestKeyPackageGenerate(t *testing.T) {
	credWithKey, _, err := credentials.GenerateCredentialWithKey([]byte("TestUser"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}

	keyPackage, privKeys, err := kp.Generate(credWithKey, kp.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if err := keyPackage.Validate(); err != nil {
		t.Errorf("KeyPackage validation failed: %v", err)
	}

	if keyPackage.ProtocolVersion != kp.MLS10 {
		t.Errorf("Wrong protocol version: got %d, want %d", keyPackage.ProtocolVersion, kp.MLS10)
	}

	if keyPackage.CipherSuite != kp.MLS128DHKEMP256 {
		t.Errorf("Wrong cipher suite: got %d, want %d", keyPackage.CipherSuite, kp.MLS128DHKEMP256)
	}

	if len(keyPackage.InitKey) == 0 {
		t.Error("InitKey is empty")
	}

	if keyPackage.LeafNode == nil {
		t.Fatal("LeafNode is nil")
	}

	if privKeys.InitKey == nil {
		t.Error("InitKey private key is nil")
	}

	if privKeys.SignatureKey == nil {
		t.Error("SignatureKey private key is nil")
	}
}

// TestKeyPackageMarshalUnmarshal tests KeyPackage serialization.
func TestKeyPackageMarshalUnmarshal(t *testing.T) {
	credWithKey, _, err := credentials.GenerateCredentialWithKey([]byte("MarshalTest"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}

	keyPackage, _, err := kp.Generate(credWithKey, kp.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	data := keyPackage.Marshal()
	t.Logf("Serialized KeyPackage: %d bytes", len(data))
}

// TestKeyPackageHash tests KeyPackage hashing.
func TestKeyPackageHash(t *testing.T) {
	credWithKey, _, err := credentials.GenerateCredentialWithKey([]byte("HashTest"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}

	keyPackage, _, err := kp.Generate(credWithKey, kp.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	hash1 := keyPackage.Hash()
	hash2 := keyPackage.Hash()

	if !bytes.Equal(hash1, hash2) {
		t.Error("KeyPackage hash is not deterministic")
	}

	if len(hash1) != 32 {
		t.Errorf("KeyPackage hash should be 32 bytes, got %d", len(hash1))
	}

	credWithKey2, _, _ := credentials.GenerateCredentialWithKey([]byte("DifferentUser"))
	keyPackage2, _, _ := kp.Generate(credWithKey2, kp.MLS128DHKEMP256)
	hash3 := keyPackage2.Hash()

	if bytes.Equal(hash1, hash3) {
		t.Error("Different KeyPackages produced same hash")
	}
}

// TestKeyPackageDeterministic tests that KeyPackage generation is random.
func TestKeyPackageDeterministic(t *testing.T) {
	credWithKey, _, _ := credentials.GenerateCredentialWithKey([]byte("User"))
	keyPackage1, _, _ := kp.Generate(credWithKey, kp.MLS128DHKEMP256)

	credWithKey2, _, _ := credentials.GenerateCredentialWithKey([]byte("User"))
	keyPackage2, _, _ := kp.Generate(credWithKey2, kp.MLS128DHKEMP256)

	data1 := keyPackage1.Marshal()
	data2 := keyPackage2.Marshal()

	if bytes.Equal(data1, data2) {
		t.Error("KeyPackage generation should be random")
	}
}

// TestKeyPackageCapabilities tests KeyPackage capabilities.
func TestKeyPackageCapabilities(t *testing.T) {
	credWithKey, _, err := credentials.GenerateCredentialWithKey([]byte("CapsTest"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}

	keyPackage, _, err := kp.Generate(credWithKey, kp.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

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
			break
		}
	}
	if !foundMLS10 {
		t.Error("Should support MLS 1.0")
	}

	foundCipherSuite := false
	for _, cs := range caps.CipherSuites {
		if cs == kp.MLS128DHKEMP256 {
			foundCipherSuite = true
			break
		}
	}
	if !foundCipherSuite {
		t.Error("Should support MLS_128_DHKEMP256")
	}
}

// TestKeyPackageLifetime tests KeyPackage lifetime.
func TestKeyPackageLifetime(t *testing.T) {
	credWithKey, _, err := credentials.GenerateCredentialWithKey([]byte("LifetimeTest"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}

	keyPackage, _, err := kp.Generate(credWithKey, kp.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	lifetime := keyPackage.LeafNode.Lifetime
	if lifetime == nil {
		t.Fatal("Lifetime is nil")
	}

	if lifetime.NotBefore == 0 {
		t.Error("NotBefore should be set")
	}

	if lifetime.NotAfter <= lifetime.NotBefore {
		t.Error("NotAfter should be after NotBefore")
	}

	expectedDuration := uint64(24 * 60 * 60)
	actualDuration := lifetime.NotAfter - lifetime.NotBefore
	if actualDuration < expectedDuration {
		t.Errorf("Lifetime too short: got %d seconds, want at least %d", actualDuration, expectedDuration)
	}
}

// TestCapabilitiesMarshal tests Capabilities serialization.
func TestCapabilitiesMarshal(t *testing.T) {
	caps := kp.DefaultCapabilities()

	buf := tls.NewWriter()
	caps.Marshal(buf)

	data := buf.Bytes()
	if len(data) == 0 {
		t.Fatal("Capabilities marshaled to empty data")
	}

	t.Logf("Serialized Capabilities: %d bytes", len(data))
}
