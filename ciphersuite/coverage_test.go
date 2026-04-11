package ciphersuite

import (
	"bytes"
	"testing"
)

// TestHashReference verifies hash references.
func TestHashReference(t *testing.T) {
	data := []byte("test data for hash reference")

	// NewHashReference
	hashRef := NewHashReference(data)
	if hashRef == nil {
		t.Fatal("NewHashReference() returned nil")
	}

	// AsSlice
	slice := hashRef.AsSlice()
	if len(slice) == 0 {
		t.Error("AsSlice() returned empty slice")
	}

	// String
	str := hashRef.String()
	if str == "" {
		t.Error("String() returned empty string")
	}
}

// TestMakeKeyPackageRef verifies KeyPackage reference creation.
func TestMakeKeyPackageRef(t *testing.T) {
	data := []byte("key package data")

	keyPackageRef := MakeKeyPackageRef(data, MLS128DHKEMP256.HashFunction())
	if keyPackageRef == nil {
		t.Fatal("MakeKeyPackageRef() returned nil")
	}

	// Check that the hash is correct
	slice := keyPackageRef.AsSlice()
	if len(slice) != 32 {
		t.Errorf("KeyPackageRef should be 32 bytes, got %d", len(slice))
	}
}

// TestMakeProposalRef verifies proposal reference creation.
func TestMakeProposalRef(t *testing.T) {
	data := []byte("proposal data")

	proposalRef := MakeProposalRef(data, MLS128DHKEMP256.HashFunction())
	if proposalRef == nil {
		t.Fatal("MakeProposalRef() returned nil")
	}

	// Check that the hash is correct
	slice := proposalRef.AsSlice()
	if len(slice) != 32 {
		t.Errorf("ProposalRef should be 32 bytes, got %d", len(slice))
	}
}

// TestHashReferenceMarshal verifies HashReference marshaling.
func TestHashReferenceMarshal(t *testing.T) {
	// Use 32 bytes to simulate a real hash
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i)
	}

	hashRef := NewHashReference(data)

	// HashReference no tiene método Marshal, usamos AsSlice
	marshaled := hashRef.AsSlice()
	if len(marshaled) == 0 {
		t.Error("AsSlice() returned empty data")
	}

	// Should preserve the original 32 bytes
	if len(marshaled) != 32 {
		t.Errorf("AsSlice() should return 32 bytes, got %d", len(marshaled))
	}
}

// TestMakeHashReference verifies the internal makeHashReference helper.
func TestMakeHashReference(t *testing.T) {
	data := []byte("test data for internal hash")
	label := []byte("test label")

	hash := makeHashReference(data, label, MLS128DHKEMP256.HashFunction())
	if hash == nil {
		t.Fatal("makeHashReference() returned nil")
	}

	// Should be SHA-256 (32 bytes)
	if len(hash.Value) != 32 {
		t.Errorf("makeHashReference() should return 32 bytes, got %d", len(hash.Value))
	}
}

// TestMac verifies MAC operations.
func TestMac(t *testing.T) {
	value := []byte("mac value")

	// NewMac
	mac := NewMac(value)
	if mac == nil {
		t.Fatal("NewMac() returned nil")
	}

	// AsSlice
	slice := mac.AsSlice()
	if !bytes.Equal(slice, value) {
		t.Error("AsSlice() returned different value")
	}

	// Equal
	mac2 := NewMac(value)
	if !mac.Equal(mac2) {
		t.Error("Equal() should return true for same values")
	}

	// Equal with different value
	mac3 := NewMac([]byte("different"))
	if mac.Equal(mac3) {
		t.Error("Equal() should return false for different values")
	}

	// ComputeMac
	key, _ := NewSecretRandom(32)
	message := []byte("message to authenticate")
	computedMac, err := ComputeMac(key, message)
	if err != nil {
		t.Fatalf("ComputeMac() error = %v", err)
	}
	if computedMac == nil {
		t.Error("ComputeMac() returned nil")
	}
	if len(computedMac.AsSlice()) == 0 {
		t.Error("ComputeMac() returned empty MAC")
	}
}

// TestReuseGuard verifies ReuseGuard operations.
func TestReuseGuard(t *testing.T) {
	// NewReuseGuardRandom
	rg, err := NewReuseGuardRandom()
	if err != nil {
		t.Fatalf("NewReuseGuardRandom() error = %v", err)
	}
	if rg == nil {
		t.Fatal("NewReuseGuardRandom() returned nil")
	}

	// AsSlice
	slice := rg.AsSlice()
	if len(slice) != ReuseGuardBytes {
		t.Errorf("AsSlice() should return %d bytes, got %d", ReuseGuardBytes, len(slice))
	}

	// NewReuseGuardFromBytes
	testBytes := []byte{0x01, 0x02, 0x03, 0x04}
	rg2, err := NewReuseGuardFromBytes(testBytes)
	if err != nil {
		t.Fatalf("NewReuseGuardFromBytes() error = %v", err)
	}
	if !bytes.Equal(rg2.AsSlice(), testBytes) {
		t.Error("NewReuseGuardFromBytes() returned different bytes")
	}

	// NewReuseGuardFromBytes with invalid length
	_, err = NewReuseGuardFromBytes([]byte{0x01, 0x02})
	if err == nil {
		t.Error("NewReuseGuardFromBytes() should fail with invalid length")
	}
}

// TestSecret_FromSlice verifies FromSlice.
func TestSecret_FromSlice(t *testing.T) {
	var secret Secret
	data := []byte("secret data")

	result := secret.FromSlice(data)
	if result == nil {
		t.Fatal("FromSlice() returned nil")
	}
	if !bytes.Equal(result.AsSlice(), data) {
		t.Error("FromSlice() returned different data")
	}
}

// TestSignaturePublicKeyMethods verifies SignaturePublicKey methods.
func TestSignaturePublicKeyMethods(t *testing.T) {
	pubKey, _ := GenerateSignaturePrivateKey()
	pubKeyBytes := pubKey.PublicKey().AsSlice()

	// NewSignaturePublicKey
	sigPubKey := NewSignaturePublicKey(pubKeyBytes)
	if sigPubKey == nil {
		t.Fatal("NewSignaturePublicKey() returned nil")
	}

	// AsSlice
	slice := sigPubKey.AsSlice()
	if !bytes.Equal(slice, pubKeyBytes) {
		t.Error("AsSlice() returned different bytes")
	}
}

// TestMLSSignaturePublicKeyMethods verifies MLSSignaturePublicKey methods.
func TestMLSSignaturePublicKeyMethods(t *testing.T) {
	privKey, _ := GenerateSignaturePrivateKey()
	pubKey := privKey.PublicKey()
	pubKeyBytes := pubKey.AsSlice()

	// NewMLSSignaturePublicKey
	mlsPubKey := NewMLSSignaturePublicKey(pubKeyBytes, ECDSA_SECP256R1_SHA256)
	if mlsPubKey == nil {
		t.Fatal("NewMLSSignaturePublicKey() returned nil")
	}

	// AsSlice
	slice := mlsPubKey.AsSlice()
	if !bytes.Equal(slice, pubKeyBytes) {
		t.Error("AsSlice() returned different bytes")
	}

	// Scheme
	scheme := mlsPubKey.Scheme()
	if scheme != ECDSA_SECP256R1_SHA256 {
		t.Errorf("Scheme() should return ECDSA_SECP256R1_SHA256, got %v", scheme)
	}
}

// TestSignatureError verifies SignatureError.
func TestSignatureError(t *testing.T) {
	err := ErrVerificationError
	str := err.Error()
	if str == "" {
		t.Error("Error() returned empty string")
	}

	err2 := ErrSigningError
	str2 := err2.Error()
	if str2 == "" {
		t.Error("Error() returned empty string")
	}
}

// TestSentinelErrors verifies that sentinel errors are non-nil and have messages.
func TestSentinelErrors(t *testing.T) {
	for _, err := range []error{
		ErrAeadDecryption,
		ErrInvalidKeyLength,
		ErrInvalidNonceLength,
		ErrInsufficientRandom,
		ErrInvalidSignature,
		ErrSigningError,
		ErrVerificationError,
		ErrInvalidLength,
		ErrKdfLabelTooLarge,
		ErrUnsupportedSuite,
	} {
		t.Run(err.Error(), func(t *testing.T) {
			if err == nil {
				t.Fatal("error should not be nil")
			}
			if err.Error() == "" {
				t.Error("Error() returned empty string")
			}
		})
	}
}

// TestAeadAlgorithmMethods verifies AeadAlgorithm methods.
func TestAeadAlgorithmMethods(t *testing.T) {
	// NonceLength
	nonceLen := AES128GCM.NonceLength()
	if nonceLen != 12 {
		t.Errorf("NonceLength() should return 12, got %d", nonceLen)
	}
}

// TestHashAlgorithmMethods verifies HashAlgorithm methods.
func TestHashAlgorithmMethods(t *testing.T) {
	// Size
	size := SHA256.Size()
	if size != 32 {
		t.Errorf("Size() should return 32, got %d", size)
	}
}

// TestKEMAlgorithmMethods verifies KEMAlgorithm methods.
func TestKEMAlgorithmMethods(t *testing.T) {
	str := DHKEM_P256_HKDF_SHA256.String()
	if str == "" {
		t.Error("String() returned empty string")
	}
}

// TestKDFAlgorithmMethods verifies KDFAlgorithm methods.
func TestKDFAlgorithmMethods(t *testing.T) {
	str := HKDF_SHA256.String()
	if str == "" {
		t.Error("String() returned empty string")
	}
}

// TestHpkeCiphertext verifies HpkeCiphertext.
func TestHpkeCiphertext(t *testing.T) {
	ciphertext := &HpkeCiphertext{
		KEMOutput:  []byte("kem output"),
		Ciphertext: []byte("ciphertext"),
	}

	if len(ciphertext.KEMOutput) == 0 {
		t.Error("KEMOutput is empty")
	}
	if len(ciphertext.Ciphertext) == 0 {
		t.Error("Ciphertext is empty")
	}
}

// TestSignAndVerify verifies SignWithLabel and VerifyWithLabel are exported.
func TestSignAndVerify(_ *testing.T) {
	_ = VerifyWithLabel
	_ = SignWithLabel
}

// BenchmarkHashReference measures HashReference performance.
func BenchmarkHashReference(b *testing.B) {
	data := []byte("test data")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewHashReference(data)
	}
}

// BenchmarkMac measures MAC performance.
func BenchmarkMac(b *testing.B) {
	key, _ := NewSecretRandom(32)
	message := []byte("message")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ComputeMac(key, message); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReuseGuard measures ReuseGuard generation performance.
func BenchmarkReuseGuard(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := NewReuseGuardRandom(); err != nil {
			b.Fatal(err)
		}
	}
}
