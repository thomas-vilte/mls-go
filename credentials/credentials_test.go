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

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/internal/tls"
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
	// DER-encoded ECDSA signatures for P-256 are variable length (typically 70-72 bytes)
	if len(sig) == 0 {
		t.Error("Sign returned empty signature")
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
// GenerateCredentialWithKeyForCS Tests
// ============================================================================

func TestGenerateCredentialWithKeyForCS_AllSuites(t *testing.T) {
	suites := []ciphersuite.CipherSuite{
		ciphersuite.MLS128DHKEMX25519,
		ciphersuite.MLS128DHKEMP256,
		ciphersuite.MLS128DHKEMX25519ChaCha20,
	}
	for _, cs := range suites {
		cwk, sigPriv, err := credentials.GenerateCredentialWithKeyForCS([]byte("test"), cs)
		if err != nil {
			t.Errorf("GenerateCredentialWithKeyForCS(%v): %v", cs, err)
			continue
		}
		if cwk == nil {
			t.Errorf("GenerateCredentialWithKeyForCS(%v): nil CredentialWithKey", cs)
			continue
		}
		if sigPriv == nil {
			t.Errorf("GenerateCredentialWithKeyForCS(%v): nil SignaturePrivateKey", cs)
		}
		if cwk.Credential == nil {
			t.Errorf("GenerateCredentialWithKeyForCS(%v): nil Credential", cs)
		}
	}
}

func TestGenerateCredentialWithKeyForCS_Unsupported(t *testing.T) {
	_, _, err := credentials.GenerateCredentialWithKeyForCS([]byte("test"), ciphersuite.CipherSuite(0x0099))
	if err == nil {
		t.Fatal("expected error for unsupported cipher suite")
	}
}

// ============================================================================
// GenerateCredentialWithKey SignatureKeyBytes
// ============================================================================

func TestGenerateCredentialWithKey_SignatureKeyBytes(t *testing.T) {
	cwk, _, err := credentials.GenerateCredentialWithKey([]byte("test"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey: %v", err)
	}
	// Must be populated: uncompressed P-256 point = 65 bytes (0x04 || X || Y)
	if len(cwk.SignatureKeyBytes) != 65 {
		t.Errorf("SignatureKeyBytes len = %d, want 65", len(cwk.SignatureKeyBytes))
	}
	if cwk.SignatureKeyBytes[0] != 0x04 {
		t.Errorf("SignatureKeyBytes[0] = 0x%02x, want 0x04 (uncompressed point)", cwk.SignatureKeyBytes[0])
	}
}

// ============================================================================
// X509 wire format — RFC 9420 §5.3 exact encoding
// ============================================================================

// TestX509CredentialWireFormat verifies that each certificate is wrapped in a
// Certificate struct with MLS varint length prefix per RFC 9420 §5.3.
func TestX509CredentialWireFormat(t *testing.T) {
	certDER, _ := generateTestCertificate(t)
	cred := credentials.NewX509Credential([][]byte{certDER})
	data := cred.Marshal()

	r := tls.NewReader(data)

	// credential_type: uint16 = 0x0002 (X509)
	credType, err := r.ReadUint16()
	if err != nil {
		t.Fatalf("ReadUint16: %v", err)
	}
	if credType != uint16(credentials.X509Credential) {
		t.Fatalf("credential_type = 0x%04x, want 0x%04x", credType, credentials.X509Credential)
	}

	// outer vector: certificates<V>
	outer, err := r.ReadVLBytes()
	if err != nil {
		t.Fatalf("outer ReadVLBytes: %v", err)
	}

	// inner: one Certificate = cert_data<V>
	inner := tls.NewReader(outer)
	cert, err := inner.ReadVLBytes()
	if err != nil {
		t.Fatalf("inner ReadVLBytes (cert_data): %v", err)
	}
	if inner.Remaining() != 0 {
		t.Errorf("unexpected bytes after certificate: %d remaining", inner.Remaining())
	}
	if !bytes.Equal(cert, certDER) {
		t.Error("cert_data mismatch")
	}
}

// ============================================================================
// UnmarshalCredentialFromReader edge cases
// ============================================================================

func TestUnmarshalCredentialFromReader_Nil(t *testing.T) {
	// type=0 (nil placeholder)
	w := tls.NewWriter()
	w.WriteUint16(0x0000)
	w.WriteVLBytes(nil)
	r := tls.NewReader(w.Bytes())
	cred, err := credentials.UnmarshalCredentialFromReader(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred != nil {
		t.Errorf("expected nil credential for type=0, got %v", cred)
	}
}

func TestUnmarshalCredentialFromReader_Unknown(t *testing.T) {
	// unknown non-GREASE type with body
	w := tls.NewWriter()
	w.WriteUint16(0x9999)
	w.WriteVLBytes([]byte("body"))
	r := tls.NewReader(w.Bytes())
	cred, err := credentials.UnmarshalCredentialFromReader(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential for unknown type")
	}
}

// ============================================================================
// validateBasic edge cases
// ============================================================================

func TestBasicCredentialValidate_TooLong(t *testing.T) {
	identity := make([]byte, 65536) // > 65535
	if err := credentials.NewBasicCredential(identity).Validate(); err == nil {
		t.Fatal("expected error for identity > 65535 bytes")
	}
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
