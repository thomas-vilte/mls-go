package credentials_test

import (
	"bytes"
	"testing"

	"github.com/openmls/go/credentials"
)

// TestBasicCredentialMarshalUnmarshal tests BasicCredential serialization.
//
// Based on openmls Rust test: openmls/src/credentials/basic.rs
func TestBasicCredentialMarshalUnmarshal(t *testing.T) {
	// Test with uint64 identity
	cred1 := credentials.NewBasicCredentialFromUint64(12345)
	data1 := cred1.Marshal()

	parsed1, err := credentials.UnmarshalCredential(data1)
	if err != nil {
		t.Fatalf("UnmarshalCredential failed: %v", err)
	}

	if parsed1.CredentialType != credentials.BasicCredential {
		t.Errorf("Wrong credential type: got %d, want %d", parsed1.CredentialType, credentials.BasicCredential)
	}

	if !bytes.Equal(parsed1.Identity, cred1.Identity) {
		t.Error("Identity mismatch")
	}

	// Test with string identity
	cred2 := credentials.NewBasicCredentialFromString("Alice")
	data2 := cred2.Marshal()

	parsed2, err := credentials.UnmarshalCredential(data2)
	if err != nil {
		t.Fatalf("UnmarshalCredential failed: %v", err)
	}

	if parsed2.IdentityString() != "Alice" {
		t.Errorf("IdentityString mismatch: got %s, want Alice", parsed2.IdentityString())
	}
}

// TestCredentialIdentityString tests identity encoding/decoding.
func TestCredentialIdentityString(t *testing.T) {
	// uint64 identity
	cred1 := credentials.NewBasicCredentialFromUint64(42)
	if cred1.IdentityString() != "42" {
		t.Errorf("uint64 identity failed: got %s, want 42", cred1.IdentityString())
	}

	// String identity
	cred2 := credentials.NewBasicCredentialFromString("Bob")
	if cred2.IdentityString() != "Bob" {
		t.Errorf("string identity failed: got %s, want Bob", cred2.IdentityString())
	}

	// Raw bytes identity
	cred3 := credentials.NewBasicCredential([]byte{0x01, 0x02, 0x03})
	if cred3.IdentityString() != "\x01\x02\x03" {
		t.Error("raw bytes identity failed")
	}
}

// TestGenerateCredentialWithKey tests credential and key generation.
func TestGenerateCredentialWithKey(t *testing.T) {
	credWithKey, privKey, err := credentials.GenerateCredentialWithKey([]byte("TestUser"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}

	if credWithKey.Credential == nil {
		t.Fatal("Credential is nil")
	}

	if credWithKey.SignatureKey == nil {
		t.Fatal("SignatureKey is nil")
	}

	if privKey == nil {
		t.Fatal("Private key is nil")
	}

	// Verify the public key matches
	if !credWithKey.SignatureKey.Equal(&privKey.PublicKey) {
		t.Error("Public key doesn't match private key")
	}
}

// TestSignVerify tests signature generation and verification.
func TestSignVerify(t *testing.T) {
	_, privKey, err := credentials.GenerateCredentialWithKey([]byte("Signer"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}

	data := []byte("Hello, MLS!")

	// Sign
	signature, err := credentials.Sign(privKey, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("Signature is empty")
	}

	// Verify
	pubKey := &privKey.PublicKey
	if !credentials.Verify(pubKey, data, signature) {
		t.Error("Verify failed with valid signature")
	}

	// Verify with wrong data should fail
	wrongData := []byte("Wrong data")
	if credentials.Verify(pubKey, wrongData, signature) {
		t.Error("Verify succeeded with wrong data")
	}

	// Verify with tampered signature should fail
	tamperedSig := make([]byte, len(signature))
	copy(tamperedSig, signature)
	tamperedSig[0] ^= 0xFF

	if credentials.Verify(pubKey, data, tamperedSig) {
		t.Error("Verify succeeded with tampered signature")
	}
}

// TestCredentialHash tests credential hashing.
func TestCredentialHash(t *testing.T) {
	cred := credentials.NewBasicCredentialFromString("TestUser")

	hash1 := cred.Hash()
	hash2 := cred.Hash()

	if !bytes.Equal(hash1, hash2) {
		t.Error("Credential hash is not deterministic")
	}

	if len(hash1) != 32 {
		t.Errorf("Credential hash should be 32 bytes (SHA-256), got %d", len(hash1))
	}

	// Different credentials should have different hashes
	cred2 := credentials.NewBasicCredentialFromString("DifferentUser")
	hash3 := cred2.Hash()

	if bytes.Equal(hash1, hash3) {
		t.Error("Different credentials produced same hash")
	}
}

// TestCredentialValidate tests credential validation.
func TestCredentialValidate(t *testing.T) {
	// Valid credential
	cred1 := credentials.NewBasicCredentialFromString("ValidUser")
	if err := cred1.Validate(); err != nil {
		t.Errorf("Valid credential failed validation: %v", err)
	}

	// Empty identity should fail
	cred2 := credentials.NewBasicCredential([]byte{})
	if err := cred2.Validate(); err == nil {
		t.Error("Empty identity should fail validation")
	}

	// Unsupported credential type
	cred3 := &credentials.Credential{
		CredentialType: 0x9999, // Invalid type
		Identity:       []byte("test"),
	}
	if err := cred3.Validate(); err == nil {
		t.Error("Unsupported credential type should fail validation")
	}
}

// TestCredentialDeterministicKeys tests that key generation is random.
func TestCredentialDeterministicKeys(t *testing.T) {
	credWithKey1, _, _ := credentials.GenerateCredentialWithKey([]byte("User"))
	credWithKey2, _, _ := credentials.GenerateCredentialWithKey([]byte("User"))

	// Keys should be different (random generation)
	if credWithKey1.SignatureKey.X.Cmp(credWithKey2.SignatureKey.X) == 0 &&
		credWithKey1.SignatureKey.Y.Cmp(credWithKey2.SignatureKey.Y) == 0 {
		t.Error("Key generation is not random")
	}
}
