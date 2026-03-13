package keypackages

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/internal/tls"
)

func makeCredWithKey(t *testing.T) *credentials.CredentialWithKey {
	t.Helper()
	c, _, err := credentials.GenerateCredentialWithKey([]byte("Test"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey: %v", err)
	}
	return c
}

func generateKP(t *testing.T) *KeyPackage {
	t.Helper()
	kp, _, err := Generate(makeCredWithKey(t), MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return kp
}

// ============================================================================
// Marshal / Unmarshal
// ============================================================================

func TestKeyPackage_MarshalUnmarshal_Roundtrip(t *testing.T) {
	orig := generateKP(t)
	data := orig.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal() returned empty")
	}
	got, err := UnmarshalKeyPackage(data)
	if err != nil {
		t.Fatalf("UnmarshalKeyPackage() failed: %v", err)
	}
	if got.ProtocolVersion != orig.ProtocolVersion {
		t.Error("ProtocolVersion mismatch")
	}
	if got.CipherSuite != orig.CipherSuite {
		t.Error("CipherSuite mismatch")
	}
	if !bytes.Equal(got.InitKey, orig.InitKey) {
		t.Error("InitKey mismatch")
	}
}

func TestUnmarshalKeyPackage_EmptyData(t *testing.T) {
	if _, err := UnmarshalKeyPackage([]byte{}); err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestUnmarshalKeyPackage_Truncated(t *testing.T) {
	if _, err := UnmarshalKeyPackage([]byte{0x00, 0x01, 0x02}); err == nil {
		t.Fatal("expected error for truncated data")
	}
}

func TestUnmarshalKeyPackageFromReader(t *testing.T) {
	orig := generateKP(t)
	r := tls.NewReader(orig.Marshal())
	got, err := UnmarshalKeyPackageFromReader(r)
	if err != nil {
		t.Fatalf("UnmarshalKeyPackageFromReader() failed: %v", err)
	}
	if got.CipherSuite != orig.CipherSuite {
		t.Error("CipherSuite mismatch")
	}
}

// ============================================================================
// LeafNode Marshal / Unmarshal
// ============================================================================

func TestLeafNode_MarshalUnmarshal(t *testing.T) {
	orig := generateKP(t).LeafNode
	data := orig.Marshal()
	if len(data) == 0 {
		t.Fatal("LeafNode.Marshal() returned empty")
	}
	got, err := UnmarshalLeafNode(data)
	if err != nil {
		t.Fatalf("UnmarshalLeafNode() failed: %v", err)
	}
	if !bytes.Equal(got.EncryptionKey, orig.EncryptionKey) {
		t.Error("EncryptionKey mismatch")
	}
}

func TestUnmarshalLeafNode_EmptyData(t *testing.T) {
	if _, err := UnmarshalLeafNode([]byte{}); err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestUnmarshalLeafNodeFromReader(t *testing.T) {
	orig := generateKP(t).LeafNode
	r := tls.NewReader(orig.Marshal())
	got, err := UnmarshalLeafNodeFromReader(r)
	if err != nil {
		t.Fatalf("UnmarshalLeafNodeFromReader() failed: %v", err)
	}
	if got.EncryptionKey == nil {
		t.Error("EncryptionKey is nil")
	}
}

// ============================================================================
// Capabilities
// ============================================================================

func TestCapabilities_MarshalUnmarshal(t *testing.T) {
	caps := DefaultCapabilities()
	w := tls.NewWriter()
	caps.Marshal(w)
	r := tls.NewReader(w.Bytes())
	got, err := UnmarshalCapabilities(r)
	if err != nil {
		t.Fatalf("UnmarshalCapabilities() failed: %v", err)
	}
	if len(got.ProtocolVersions) == 0 {
		t.Error("ProtocolVersions empty after roundtrip")
	}
	if len(got.CipherSuites) == 0 {
		t.Error("CipherSuites empty after roundtrip")
	}
}

func TestUnmarshalCapabilities_EmptyData(t *testing.T) {
	r := tls.NewReader([]byte{})
	if _, err := UnmarshalCapabilities(r); err == nil {
		t.Fatal("expected error for empty data")
	}
}

// ============================================================================
// KeyPackage.Verify — RFC 9420 §10.1
// ============================================================================

func TestKeyPackage_Verify_Valid(t *testing.T) {
	kp := generateKP(t)
	if err := kp.Verify(ciphersuite.MLS128DHKEMP256); err != nil {
		t.Fatalf("Verify() failed on freshly generated KeyPackage: %v", err)
	}
}

func TestKeyPackage_Verify_CorruptedSignature(t *testing.T) {
	kp := generateKP(t)
	// Flip the first byte of the signature to corrupt it
	kp.Signature[0] ^= 0xFF
	if err := kp.Verify(ciphersuite.MLS128DHKEMP256); err == nil {
		t.Fatal("Verify() should fail for corrupted signature")
	}
}

func TestKeyPackage_Verify_NilLeafNode(t *testing.T) {
	kp := &KeyPackage{
		ProtocolVersion: MLS10,
		CipherSuite:     MLS128DHKEMP256,
		InitKey:         []byte{0x01},
		LeafNode:        nil,
	}
	if err := kp.Verify(ciphersuite.MLS128DHKEMP256); err == nil {
		t.Fatal("Verify() should fail when LeafNode is nil")
	}
}

// ============================================================================
// KeyPackage.MarshalTBS — determinismo
// ============================================================================

func TestKeyPackage_MarshalTBS_Deterministic(t *testing.T) {
	kp := generateKP(t)
	if !bytes.Equal(kp.MarshalTBS(), kp.MarshalTBS()) {
		t.Error("MarshalTBS() is not deterministic")
	}
}

func TestKeyPackage_MarshalTBS_DiffersFromMarshal(t *testing.T) {
	// MarshalTBS must not include the signature — so it must differ from Marshal
	kp := generateKP(t)
	if bytes.Equal(kp.MarshalTBS(), kp.Marshal()) {
		t.Error("MarshalTBS() and Marshal() must not be identical")
	}
}

// ============================================================================
// KeyPackage.Validate — error cases (RFC 9420 §12.2)
// ============================================================================

func TestKeyPackage_Validate_Valid(t *testing.T) {
	if err := generateKP(t).Validate(); err != nil {
		t.Fatalf("Validate() failed on valid KP: %v", err)
	}
}

func TestKeyPackage_Validate_WrongProtocolVersion(t *testing.T) {
	kp := generateKP(t)
	kp.ProtocolVersion = 99
	if err := kp.Validate(); err == nil {
		t.Fatal("expected error for unsupported protocol version")
	}
}

func TestKeyPackage_Validate_WrongCipherSuite(t *testing.T) {
	kp := generateKP(t)
	kp.CipherSuite = 99
	if err := kp.Validate(); err == nil {
		t.Fatal("expected error for unsupported cipher suite")
	}
}

func TestKeyPackage_Validate_EmptyInitKey(t *testing.T) {
	kp := generateKP(t)
	kp.InitKey = nil
	if err := kp.Validate(); err == nil {
		t.Fatal("expected error for empty init_key")
	}
}

func TestKeyPackage_Validate_NilLeafNode(t *testing.T) {
	kp := generateKP(t)
	kp.LeafNode = nil
	if err := kp.Validate(); err == nil {
		t.Fatal("expected error for nil LeafNode")
	}
}

// ============================================================================
// LeafNode.Validate — error cases
// ============================================================================

func TestLeafNode_Validate_Valid(t *testing.T) {
	if err := generateKP(t).LeafNode.Validate(); err != nil {
		t.Fatalf("LeafNode.Validate() failed: %v", err)
	}
}

func TestLeafNode_Validate_EmptyEncryptionKey(t *testing.T) {
	ln := generateKP(t).LeafNode
	ln.EncryptionKey = nil
	if err := ln.Validate(); err == nil {
		t.Fatal("expected error for empty encryption_key")
	}
}

func TestLeafNode_Validate_NilSignatureKey(t *testing.T) {
	ln := generateKP(t).LeafNode
	ln.SignatureKey = nil
	ln.SignatureKeyBytes = nil
	if err := ln.Validate(); err == nil {
		t.Fatal("expected error for nil signature_key")
	}
}

func TestLeafNode_Validate_NilCredential(t *testing.T) {
	ln := generateKP(t).LeafNode
	ln.Credential = nil
	if err := ln.Validate(); err == nil {
		t.Fatal("expected error for nil credential")
	}
}
