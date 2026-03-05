package credentials_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

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

	if parsed1.Type() != credentials.BasicCredential {
		t.Errorf("Wrong credential type: got %d, want %d", parsed1.Type(), credentials.BasicCredential)
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

// TestX509CredentialMarshalUnmarshal tests X509Credential serialization.
func TestX509CredentialMarshalUnmarshal(t *testing.T) {
	// Create test certificates (self-signed for testing)
	certDER := generateTestCertificate(t)

	cred := credentials.NewX509Credential([][]byte{certDER})
	data := cred.Marshal()

	parsed, err := credentials.UnmarshalCredential(data)
	if err != nil {
		t.Fatalf("UnmarshalCredential failed: %v", err)
	}

	if parsed.Type() != credentials.X509Credential {
		t.Errorf("Wrong credential type: got %d, want %d", parsed.Type(), credentials.X509Credential)
	}

	if len(parsed.Certificates) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(parsed.Certificates))
	}

	if !bytes.Equal(parsed.Certificates[0], certDER) {
		t.Error("Certificate mismatch")
	}
}

// TestX509CredentialValidate tests X509Credential validation.
func TestX509CredentialValidate(t *testing.T) {
	certDER := generateTestCertificate(t)

	// Valid X509Credential
	cred := credentials.NewX509Credential([][]byte{certDER})
	err := cred.Validate()
	if err != nil {
		t.Errorf("Valid X509Credential failed validation: %v", err)
	}

	// Empty certificate chain
	credEmpty := credentials.NewX509Credential([][]byte{})
	err = credEmpty.Validate()
	if err == nil {
		t.Error("Empty X509Credential should fail validation")
	}

	// Invalid DER
	credInvalid := credentials.NewX509Credential([][]byte{[]byte("invalid der")})
	err = credInvalid.Validate()
	if err == nil {
		t.Error("Invalid DER should fail validation")
	}
}

// TestBasicCredentialValidate tests BasicCredential validation.
func TestBasicCredentialValidate(t *testing.T) {
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
}

// TestGREASECredential tests GREASE credential handling.
func TestGREASECredential(t *testing.T) {
	// GREASE credential type
	greaseCred := &credentials.Credential{
		CredentialType: 0x0A0A, // GREASE value
	}

	// Should be recognized as GREASE
	if !greaseCred.IsGREASE() {
		t.Error("GREASE credential not recognized")
	}

	// GREASE credentials should always validate
	err := greaseCred.Validate()
	if err != nil {
		t.Errorf("GREASE credential should validate: %v", err)
	}

	// String representation
	if greaseCred.Type().String() != "GREASE" {
		t.Errorf("GREASE string mismatch: got %s", greaseCred.Type().String())
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

	if len(signature) != 64 {
		t.Errorf("Signature should be 64 bytes (R||S), got %d", len(signature))
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

// TestCredentialTypeString tests credential type string representation.
func TestCredentialTypeString(t *testing.T) {
	tests := []struct {
		ct   credentials.CredentialType
		want string
	}{
		{credentials.BasicCredential, "Basic"},
		{credentials.X509Credential, "X509"},
		{0x0A0A, "GREASE"},
		{0x9999, "Unknown(0x9999)"},
	}

	for _, tt := range tests {
		if tt.ct.String() != tt.want {
			t.Errorf("CredentialType(%d).String() = %s, want %s", tt.ct, tt.ct.String(), tt.want)
		}
	}
}

// generateTestCertificate creates a self-signed certificate for testing.
func generateTestCertificate(t *testing.T) []byte {
	t.Helper()

	// Generate private key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	return certDER
}

// TestASN1SignatureEncoding tests that signatures are properly encoded.
func TestASN1SignatureEncoding(t *testing.T) {
	_, privKey, _ := credentials.GenerateCredentialWithKey([]byte("Signer"))
	data := []byte("Test data")

	signature, err := credentials.Sign(privKey, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Signature should be exactly 64 bytes (32 bytes R + 32 bytes S)
	if len(signature) != 64 {
		t.Errorf("Signature length should be 64 bytes, got %d", len(signature))
	}

	// R and S should be properly encoded (no leading zeros unless necessary)
	r := signature[:32]
	s := signature[32:]

	// Verify the signature works
	pubKey := &privKey.PublicKey
	if !credentials.Verify(pubKey, data, signature) {
		t.Error("Signature verification failed")
	}

	// R and S should not both be zero
	if bytes.Equal(r, make([]byte, 32)) && bytes.Equal(s, make([]byte, 32)) {
		t.Error("R and S cannot both be zero")
	}
}

// BenchmarkCredentialMarshal benchmarks credential marshaling.
func BenchmarkCredentialMarshal(b *testing.B) {
	cred := credentials.NewBasicCredentialFromString("TestUser")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cred.Marshal()
	}
}

// BenchmarkCredentialUnmarshal benchmarks credential unmarshaling.
func BenchmarkCredentialUnmarshal(b *testing.B) {
	cred := credentials.NewBasicCredentialFromString("TestUser")
	data := cred.Marshal()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		credentials.UnmarshalCredential(data)
	}
}

// BenchmarkCredentialHash benchmarks credential hashing.
func BenchmarkCredentialHash(b *testing.B) {
	cred := credentials.NewBasicCredentialFromString("TestUser")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cred.Hash()
	}
}

// BenchmarkSign benchmarks signature generation.
func BenchmarkSign(b *testing.B) {
	_, privKey, _ := credentials.GenerateCredentialWithKey([]byte("Signer"))
	data := []byte("Test data")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		credentials.Sign(privKey, data)
	}
}

// BenchmarkVerify benchmarks signature verification.
func BenchmarkVerify(b *testing.B) {
	_, privKey, _ := credentials.GenerateCredentialWithKey([]byte("Signer"))
	data := []byte("Test data")
	signature, _ := credentials.Sign(privKey, data)
	pubKey := &privKey.PublicKey
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		credentials.Verify(pubKey, data, signature)
	}
}
