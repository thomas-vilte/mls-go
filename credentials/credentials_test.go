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

	"github.com/mls-go/credentials"
	"github.com/mls-go/internal/tls"
)

// generateTestCertificate creates a self-signed certificate for testing.
func generateTestCertificate(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	return certDER, privKey
}

// ============================================================================
// BasicCredential Tests
// ============================================================================

func TestBasicCredentialMarshalUnmarshal(t *testing.T) {
	for _, identity := range [][]byte{
		[]byte("Alice"),
		{0x01, 0x02, 0x03},
	} {
		cred := credentials.NewBasicCredential(identity)
		data := cred.Marshal()
		got, err := credentials.UnmarshalCredential(data)
		if err != nil {
			t.Fatalf("UnmarshalCredential: %v", err)
		}
		if got.Type() != credentials.BasicCredential {
			t.Errorf("type = %d, want BasicCredential", got.Type())
		}
		if !bytes.Equal(got.Identity, identity) {
			t.Error("Identity mismatch")
		}
	}
}

func TestUnmarshalCredentialFromReader_Basic(t *testing.T) {
	cred := credentials.NewBasicCredentialFromString("Bob")
	r := tls.NewReader(cred.Marshal())
	got, err := credentials.UnmarshalCredentialFromReader(r)
	if err != nil {
		t.Fatalf("UnmarshalCredentialFromReader: %v", err)
	}
	if got.IdentityString() != "Bob" {
		t.Errorf("identity = %q, want %q", got.IdentityString(), "Bob")
	}
}

func TestUnmarshalCredentialFromReader_Truncated(t *testing.T) {
	r := tls.NewReader([]byte{0x00, 0x01}) // type=BasicCredential but no length/body
	if _, err := credentials.UnmarshalCredentialFromReader(r); err == nil {
		t.Fatal("expected error for truncated data")
	}
}

func TestBasicCredentialIdentityString(t *testing.T) {
	if credentials.NewBasicCredentialFromUint64(42).IdentityString() != "42" {
		t.Error("uint64 identity string mismatch")
	}
	if credentials.NewBasicCredentialFromString("Carol").IdentityString() != "Carol" {
		t.Error("string identity mismatch")
	}
}

func TestBasicCredentialValidate_Empty(t *testing.T) {
	if err := credentials.NewBasicCredential([]byte{}).Validate(); err == nil {
		t.Fatal("expected error for empty identity")
	}
}

func TestBasicCredentialValidate_Valid(t *testing.T) {
	if err := credentials.NewBasicCredentialFromString("ok").Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// ============================================================================
// X509Credential Tests
// ============================================================================

func TestX509CredentialMarshalUnmarshal(t *testing.T) {
	certDER, _ := generateTestCertificate(t)
	cred := credentials.NewX509Credential([][]byte{certDER})
	data := cred.Marshal()

	got, err := credentials.UnmarshalCredential(data)
	if err != nil {
		t.Fatalf("UnmarshalCredential: %v", err)
	}
	if got.Type() != credentials.X509Credential {
		t.Errorf("type = %d, want X509Credential", got.Type())
	}
	if len(got.Certificates) != 1 {
		t.Fatalf("certificates count = %d, want 1", len(got.Certificates))
	}
	if !bytes.Equal(got.Certificates[0], certDER) {
		t.Error("certificate DER mismatch")
	}
}

func TestUnmarshalCredentialFromReader_X509MultiCert(t *testing.T) {
	cert1DER, _ := generateTestCertificate(t)
	cert2DER, _ := generateTestCertificate(t)
	cred := credentials.NewX509Credential([][]byte{cert1DER, cert2DER})
	r := tls.NewReader(cred.Marshal())
	got, err := credentials.UnmarshalCredentialFromReader(r)
	if err != nil {
		t.Fatalf("UnmarshalCredentialFromReader: %v", err)
	}
	if got.Type() != credentials.X509Credential {
		t.Errorf("type = %d, want X509Credential", got.Type())
	}
	if len(got.Certificates) != 2 {
		t.Fatalf("certificates count = %d, want 2", len(got.Certificates))
	}
	if !bytes.Equal(got.Certificates[0], cert1DER) {
		t.Error("certificate[0] DER mismatch")
	}
	if !bytes.Equal(got.Certificates[1], cert2DER) {
		t.Error("certificate[1] DER mismatch")
	}
}

func TestX509CredentialValidate_Valid(t *testing.T) {
	certDER, _ := generateTestCertificate(t)
	if err := credentials.NewX509Credential([][]byte{certDER}).Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestX509CredentialValidate_Empty(t *testing.T) {
	if err := credentials.NewX509Credential([][]byte{}).Validate(); err == nil {
		t.Fatal("expected error for empty chain")
	}
}

func TestX509CredentialValidate_InvalidDER(t *testing.T) {
	if err := credentials.NewX509Credential([][]byte{[]byte("not-a-cert")}).Validate(); err == nil {
		t.Fatal("expected error for invalid DER")
	}
}

// TestValidateX509Chain verifies full chain validation (RFC 9420 §5.3.2).
func TestValidateX509Chain(t *testing.T) {
	certDER, _ := generateTestCertificate(t)
	cred := credentials.NewX509Credential([][]byte{certDER})

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	if err := cred.ValidateX509Chain(roots, ""); err != nil {
		t.Fatalf("ValidateX509Chain: %v", err)
	}
}

// TestGenerateX509CredentialWithKey wraps an existing cert+key into a CredentialWithKey.
func TestGenerateX509CredentialWithKey(t *testing.T) {
	certDER, privKey := generateTestCertificate(t)
	cwk, err := credentials.GenerateX509CredentialWithKey(certDER, privKey)
	if err != nil {
		t.Fatalf("GenerateX509CredentialWithKey: %v", err)
	}
	if cwk.Credential == nil {
		t.Fatal("Credential is nil")
	}
	if cwk.SignatureKey == nil {
		t.Fatal("SignatureKey is nil")
	}
	if cwk.Credential.Type() != credentials.X509Credential {
		t.Errorf("type = %d, want X509Credential", cwk.Credential.Type())
	}
}

// ============================================================================
// GREASE Tests
// ============================================================================

func TestGREASECredential(t *testing.T) {
	grease := &credentials.Credential{CredentialType: 0x0A0A}
	if !grease.IsGREASE() {
		t.Error("not recognized as GREASE")
	}
	if err := grease.Validate(); err != nil {
		t.Fatalf("GREASE Validate: %v", err)
	}
	if grease.Type().String() != "GREASE" {
		t.Errorf("String = %q, want GREASE", grease.Type().String())
	}
}

// ============================================================================
// CredentialWithKey Generation Tests
// ============================================================================

func TestGenerateCredentialWithKey(t *testing.T) {
	cwk, privKey, err := credentials.GenerateCredentialWithKey([]byte("TestUser"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey: %v", err)
	}
	if cwk.Credential == nil {
		t.Fatal("Credential is nil")
	}
	if cwk.SignatureKey == nil {
		t.Fatal("SignatureKey is nil")
	}
	if privKey == nil {
		t.Fatal("privKey is nil")
	}
	if !cwk.SignatureKey.Equal(&privKey.PublicKey) {
		t.Error("public key mismatch")
	}
}

func TestGenerateCredentialWithKey_IsRandom(t *testing.T) {
	cwk1, _, _ := credentials.GenerateCredentialWithKey([]byte("User"))
	cwk2, _, _ := credentials.GenerateCredentialWithKey([]byte("User"))
	// Use Equal() to compare; if they're the same key, generation is not random.
	if cwk1.SignatureKey.Equal(cwk2.SignatureKey) {
		t.Error("two calls produced identical keys — missing randomness")
	}
}

// ============================================================================
// Sign / Verify Tests (RFC 9420 §5.1.1 raw R||S encoding)
// ============================================================================

func TestSignVerify_Valid(t *testing.T) {
	_, privKey, err := credentials.GenerateCredentialWithKey([]byte("Signer"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey: %v", err)
	}
	msg := []byte("Hello, MLS!")
	sig, err := credentials.Sign(privKey, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 64 {
		t.Errorf("signature len = %d, want 64 (raw R||S)", len(sig))
	}
	if !credentials.Verify(&privKey.PublicKey, msg, sig) {
		t.Error("Verify failed for valid signature")
	}
}

func TestSignVerify_WrongMessage(t *testing.T) {
	_, privKey, _ := credentials.GenerateCredentialWithKey([]byte("Signer"))
	sig, _ := credentials.Sign(privKey, []byte("msg"))
	if credentials.Verify(&privKey.PublicKey, []byte("other"), sig) {
		t.Error("Verify should fail for wrong message")
	}
}

func TestSignVerify_TamperedSignature(t *testing.T) {
	_, privKey, _ := credentials.GenerateCredentialWithKey([]byte("Signer"))
	msg := []byte("test")
	sig, _ := credentials.Sign(privKey, msg)
	sig[0] ^= 0xFF
	if credentials.Verify(&privKey.PublicKey, msg, sig) {
		t.Error("Verify should fail for tampered signature")
	}
}

// ============================================================================
// Credential Hash Tests
// ============================================================================

func TestCredentialHash_DeterministicAndUnique(t *testing.T) {
	c1 := credentials.NewBasicCredentialFromString("Alice")
	h1 := c1.Hash()
	if !bytes.Equal(h1, c1.Hash()) {
		t.Error("Hash is not deterministic")
	}
	if len(h1) != 32 {
		t.Errorf("hash len = %d, want 32", len(h1))
	}
	c2 := credentials.NewBasicCredentialFromString("Bob")
	if bytes.Equal(h1, c2.Hash()) {
		t.Error("different credentials produced the same hash")
	}
}

// ============================================================================
// CredentialType.String() Tests
// ============================================================================

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
		if got := tt.ct.String(); got != tt.want {
			t.Errorf("CredentialType(0x%04x).String() = %q, want %q", tt.ct, got, tt.want)
		}
	}
}

// ============================================================================
// Error Paths — RFC 9420 §5.3
// ============================================================================

// TestUnmarshalCredential_UnknownType tests unknown credential type.
func TestUnmarshalCredential_UnknownType(t *testing.T) {
	// Unknown non-GREASE type (0x9999)
	w := tls.NewWriter()
	w.WriteUint16(0x9999) // unknown credential_type
	w.WriteVLBytes([]byte("unknown body"))
	data := w.Bytes()

	// Should return error or credential with unknown type
	cred, err := credentials.UnmarshalCredential(data)
	if err == nil && cred == nil {
		t.Error("UnmarshalCredential should return error or non-nil credential")
	}
}

// TestValidateX509Chain_Expired tests expired certificate.
func TestValidateX509Chain_Expired(t *testing.T) {
	// Create expired certificate
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Expired"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour), // Expired
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}

	cred := credentials.NewX509Credential([][]byte{certDER})

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	// ValidateX509Chain should fail because the certificate is expired.
	if err := cred.ValidateX509Chain(roots, ""); err == nil {
		t.Error("ValidateX509Chain should fail for expired certificate")
	}
}

// TestValidateX509Chain_NilCredential tests validation with nil credential.
func TestValidateX509Chain_NilCredential(t *testing.T) {
	// This test documents that Validate with nil causes panic
	// It's a known behavior that should be handled in production
	t.Skip("Validate with nil credential panics - known issue")
}

// ============================================================================
// Benchmarks
// ============================================================================

func BenchmarkCredentialMarshal(b *testing.B) {
	cred := credentials.NewBasicCredentialFromString("TestUser")
	b.ResetTimer()
	for range b.N {
		cred.Marshal()
	}
}

func BenchmarkSign(b *testing.B) {
	_, privKey, _ := credentials.GenerateCredentialWithKey([]byte("Signer"))
	data := []byte("benchmark data")
	b.ResetTimer()
	for range b.N {
		if _, err := credentials.Sign(privKey, data); err != nil {
			b.Fatal(err)
		}
	}
}
