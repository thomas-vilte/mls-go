package ciphersuite

import (
	"bytes"
	"testing"
)

// TestHashReference prueba las referencias hash.
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

// TestMakeKeyPackageRef prueba la creación de referencias a KeyPackage.
func TestMakeKeyPackageRef(t *testing.T) {
	data := []byte("key package data")

	keyPackageRef := MakeKeyPackageRef(data, MLS128DHKEMP256.HashFunction())
	if keyPackageRef == nil {
		t.Fatal("MakeKeyPackageRef() returned nil")
	}

	// Verificar que el hash es correcto
	slice := keyPackageRef.AsSlice()
	if len(slice) != 32 {
		t.Errorf("KeyPackageRef should be 32 bytes, got %d", len(slice))
	}
}

// TestMakeProposalRef prueba la creación de referencias a Proposals.
func TestMakeProposalRef(t *testing.T) {
	data := []byte("proposal data")

	proposalRef := MakeProposalRef(data, MLS128DHKEMP256.HashFunction())
	if proposalRef == nil {
		t.Fatal("MakeProposalRef() returned nil")
	}

	// Verificar que el hash es correcto
	slice := proposalRef.AsSlice()
	if len(slice) != 32 {
		t.Errorf("ProposalRef should be 32 bytes, got %d", len(slice))
	}
}

// TestHashReferenceMarshal prueba el marshaling de HashReference.
func TestHashReferenceMarshal(t *testing.T) {
	// Usar datos de 32 bytes para simular un hash real
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

	// Debería mantener los 32 bytes original
	if len(marshaled) != 32 {
		t.Errorf("AsSlice() should return 32 bytes, got %d", len(marshaled))
	}
}

// TestMakeHashReference prueba la función interna makeHashReference.
func TestMakeHashReference(t *testing.T) {
	data := []byte("test data for internal hash")
	label := []byte("test label")

	hash := makeHashReference(data, label, MLS128DHKEMP256.HashFunction())
	if hash == nil {
		t.Fatal("makeHashReference() returned nil")
	}

	// Debería ser SHA-256 (32 bytes)
	if len(hash.Value) != 32 {
		t.Errorf("makeHashReference() should return 32 bytes, got %d", len(hash.Value))
	}
}

// TestMac prueba las operaciones MAC.
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

	// Equal con diferente valor
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

// TestReuseGuard prueba las operaciones de ReuseGuard.
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

	// NewReuseGuardFromBytes con longitud inválida
	_, err = NewReuseGuardFromBytes([]byte{0x01, 0x02})
	if err == nil {
		t.Error("NewReuseGuardFromBytes() should fail with invalid length")
	}
}

// TestSecret_FromSlice prueba FromSlice.
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

// TestSignaturePublicKeyMethods prueba métodos de SignaturePublicKey.
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

// TestMLSSignaturePublicKeyMethods prueba métodos de MLSSignaturePublicKey.
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

// TestSignatureError prueba SignatureError.
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

// TestCryptoError prueba CryptoError.
func TestCryptoError(t *testing.T) {
	// Los errores modernos son variables, no tipos
	// Verificamos que los errores estándar existen y funcionan
	err := ErrCryptoLibraryError
	if err == nil {
		t.Error("ErrCryptoLibraryError should not be nil")
	}
	str := err.Error()
	if str == "" {
		t.Error("Error() returned empty string")
	}
}

// TestAeadAlgorithmMethods prueba métodos de AeadAlgorithm.
func TestAeadAlgorithmMethods(t *testing.T) {
	// NonceLength
	nonceLen := AES128GCM.NonceLength()
	if nonceLen != 12 {
		t.Errorf("NonceLength() should return 12, got %d", nonceLen)
	}
}

// TestHashAlgorithmMethods prueba métodos de HashAlgorithm.
func TestHashAlgorithmMethods(t *testing.T) {
	// Size
	size := SHA256.Size()
	if size != 32 {
		t.Errorf("Size() should return 32, got %d", size)
	}
}

// TestKEMAlgorithmMethods prueba métodos de KEMAlgorithm.
func TestKEMAlgorithmMethods(t *testing.T) {
	str := DHKEM_P256_HKDF_SHA256.String()
	if str == "" {
		t.Error("String() returned empty string")
	}
}

// TestKDFAlgorithmMethods prueba métodos de KDFAlgorithm.
func TestKDFAlgorithmMethods(t *testing.T) {
	str := HKDF_SHA256.String()
	if str == "" {
		t.Error("String() returned empty string")
	}
}

// TestHpkeCiphertext prueba HpkeCiphertext.
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

// BenchmarkHashReference mide el performance de HashReference.
func BenchmarkHashReference(b *testing.B) {
	data := []byte("test data")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewHashReference(data)
	}
}

// BenchmarkMac mide el performance de MAC.
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

// BenchmarkReuseGuard mide el performance de ReuseGuard.
func BenchmarkReuseGuard(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := NewReuseGuardRandom(); err != nil {
			b.Fatal(err)
		}
	}
}
