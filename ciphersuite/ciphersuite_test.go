package ciphersuite

import (
	"testing"
)

// TestCipherSuite_IsSupported prueba qué cipher suites están soportadas.
func TestCipherSuite_IsSupported(t *testing.T) {
	// MLS128DHKEMP256 debería estar soportado
	if !MLS128DHKEMP256.IsSupported() {
		t.Error("MLS128DHKEMP256 should be supported")
	}

	// Cipher suites no soportadas
	var unsupported CipherSuite = 0x0001
	if unsupported.IsSupported() {
		t.Error("Unknown cipher suite should not be supported")
	}
}

// TestCipherSuite_HashAlgorithm prueba los algoritmos de hash.
func TestCipherSuite_HashAlgorithm(t *testing.T) {
	hashAlgo := MLS128DHKEMP256.HashAlgorithm()
	if hashAlgo != SHA256 {
		t.Errorf("MLS128DHKEMP256 should use SHA256, got %v", hashAlgo)
	}
}

// TestCipherSuite_AeadAlgorithm prueba los algoritmos AEAD.
func TestCipherSuite_AeadAlgorithm(t *testing.T) {
	aeadAlgo := MLS128DHKEMP256.AeadAlgorithm()
	if aeadAlgo != AES128GCM {
		t.Errorf("MLS128DHKEMP256 should use AES128GCM, got %v", aeadAlgo)
	}
}

// TestCipherSuite_SignatureScheme prueba los esquemas de firma.
func TestCipherSuite_SignatureScheme(t *testing.T) {
	sigScheme := MLS128DHKEMP256.SignatureScheme()
	if sigScheme != ECDSA_SECP256R1_SHA256 {
		t.Errorf("MLS128DHKEMP256 should use ECDSA_SECP256R1_SHA256, got %v", sigScheme)
	}
}

// TestCipherSuite_HashLength prueba las longitudes de hash.
func TestCipherSuite_HashLength(t *testing.T) {
	hashLen := MLS128DHKEMP256.HashLength()
	if hashLen != 32 {
		t.Errorf("MLS128DHKEMP256 hash length should be 32, got %d", hashLen)
	}
}

// TestCipherSuite_AeadKeyLength prueba las longitudes de clave AEAD.
func TestCipherSuite_AeadKeyLength(t *testing.T) {
	keyLen := MLS128DHKEMP256.AeadKeyLength()
	if keyLen != 16 {
		t.Errorf("MLS128DHKEMP256 AEAD key length should be 16, got %d", keyLen)
	}
}

// TestCipherSuite_AeadNonceLength prueba las longitudes de nonce.
func TestCipherSuite_AeadNonceLength(t *testing.T) {
	nonceLen := MLS128DHKEMP256.AeadNonceLength()
	if nonceLen != 12 {
		t.Errorf("MLS128DHKEMP256 AEAD nonce length should be 12, got %d", nonceLen)
	}
}

// TestCipherSuite_HPKEConfig prueba la configuración HPKE.
func TestCipherSuite_HPKEConfig(t *testing.T) {
	config := MLS128DHKEMP256.HPKEConfig()

	if config.KEM != DHKEM_P256_HKDF_SHA256 {
		t.Errorf("KEM should be DHKEM_P256_HKDF_SHA256, got %v", config.KEM)
	}
	if config.KDF != HKDF_SHA256 {
		t.Errorf("KDF should be HKDF_SHA256, got %v", config.KDF)
	}
	if config.AEAD != AES128GCM {
		t.Errorf("AEAD should be AES128GCM, got %v", config.AEAD)
	}
}

// TestCipherSuite_String prueba la representación string.
func TestCipherSuite_String(t *testing.T) {
	str := MLS128DHKEMP256.String()
	expected := "MLS_128_DHKEMP256_AES128GCM_SHA256_P256"
	if str != expected {
		t.Errorf("String() = %s, want %s", str, expected)
	}

	// Cipher suite desconocida
	var unknown CipherSuite = 0xFFFF
	unknownStr := unknown.String()
	if unknownStr != "Unknown(0xFFFF)" {
		t.Errorf("Unknown cipher suite string = %s, want Unknown(0xFFFF)", unknownStr)
	}
}

// TestHashAlgorithm_Size prueba los tamaños de hash.
func TestHashAlgorithm_Size(t *testing.T) {
	size := SHA256.Size()
	if size != 32 {
		t.Errorf("SHA256 size should be 32, got %d", size)
	}
}

// TestHashAlgorithm_String prueba la representación string.
func TestHashAlgorithm_String(t *testing.T) {
	str := SHA256.String()
	if str != "SHA256" {
		t.Errorf("SHA256 string = %s, want SHA256", str)
	}
}

// TestAeadAlgorithm_KeyLength prueba las longitudes de clave AEAD.
func TestAeadAlgorithm_KeyLength(t *testing.T) {
	keyLen128 := AES128GCM.KeyLength()
	if keyLen128 != 16 {
		t.Errorf("AES128GCM key length should be 16, got %d", keyLen128)
	}

	keyLen256 := AES256GCM.KeyLength()
	if keyLen256 != 32 {
		t.Errorf("AES256GCM key length should be 32, got %d", keyLen256)
	}
}

// TestSignatureScheme_String prueba la representación string.
func TestSignatureScheme_String(t *testing.T) {
	str := ECDSA_SECP256R1_SHA256.String()
	if str != "ecdsa_secp256r1_sha256" {
		t.Errorf("Signature scheme string = %s, want ecdsa_secp256r1_sha256", str)
	}
}

// TestKEMAlgorithm_String prueba la representación string de KEM.
func TestKEMAlgorithm_String(t *testing.T) {
	str := DHKEM_P256_HKDF_SHA256.String()
	if str != "DHKEM_P256_HKDF_SHA256" {
		t.Errorf("KEM string = %s, want DHKEM_P256_HKDF_SHA256", str)
	}
}

// TestKDFAlgorithm_String prueba la representación string de KDF.
func TestKDFAlgorithm_String(t *testing.T) {
	str := HKDF_SHA256.String()
	if str != "HKDF-SHA256" {
		t.Errorf("KDF string = %s, want HKDF-SHA256", str)
	}
}

// TestEqualCT prueba la comparación constant-time.
func TestEqualCT(t *testing.T) {
	// Iguales
	a := []byte{1, 2, 3, 4}
	b := []byte{1, 2, 3, 4}
	if !EqualCT(a, b) {
		t.Error("EqualCT should return true for equal slices")
	}

	// Diferentes
	c := []byte{1, 2, 3, 5}
	if EqualCT(a, c) {
		t.Error("EqualCT should return false for different slices")
	}

	// Diferente longitud
	d := []byte{1, 2, 3}
	if EqualCT(a, d) {
		t.Error("EqualCT should return false for different lengths")
	}

	// Vacíos
	e := []byte{}
	f := []byte{}
	if !EqualCT(e, f) {
		t.Error("EqualCT should return true for empty slices")
	}
}

// TestSecret_Random prueba la generación de secretos aleatorios.
func TestSecret_Random(t *testing.T) {
	secret1, err := NewSecretRandom(32)
	if err != nil {
		t.Fatalf("NewSecretRandom() error = %v", err)
	}

	secret2, err := NewSecretRandom(32)
	if err != nil {
		t.Fatalf("NewSecretRandom() error = %v", err)
	}

	// Deberían ser diferentes
	if secret1.Equal(secret2) {
		t.Error("Random secrets should be different")
	}

	// Longitud correcta
	if secret1.Len() != 32 {
		t.Errorf("Secret length should be 32, got %d", secret1.Len())
	}
}

// TestSecret_Clone prueba el clonado de secretos.
func TestSecret_Clone(t *testing.T) {
	original := NewSecret([]byte("secret value"))
	clone := original.Clone()

	// Deberían ser iguales
	if !original.Equal(clone) {
		t.Error("Clone should be equal to original")
	}

	// Modificar el original no debería afectar el clone
	original.Value[0] = 0xFF
	if original.Equal(clone) {
		t.Error("Modifying original should not affect clone")
	}
}

// TestSecret_SecureZero prueba que SecureZero limpia la memoria.
func TestSecret_SecureZero(t *testing.T) {
	secret := NewSecret([]byte("secret value"))

	// Verificar que tiene valor
	if secret.Len() == 0 {
		t.Fatal("Secret should have value")
	}

	// Zero out
	secret.SecureZero()

	// Verificar que está en cero
	for i, b := range secret.Value {
		if b != 0 {
			t.Errorf("Byte %d should be 0 after SecureZero, got %d", i, b)
		}
	}
}

// TestSecret_HKDFExtract prueba HKDF-Extract con Secrets.
func TestSecret_HKDFExtract(t *testing.T) {
	salt, _ := NewSecretRandom(32)
	ikm, _ := NewSecretRandom(32)

	prk, err := salt.HKDFExtract(ikm)
	if err != nil {
		t.Fatalf("HKDFExtract() error = %v", err)
	}

	// PRK debería tener la longitud correcta
	if prk.Len() != 32 {
		t.Errorf("PRK length should be 32, got %d", prk.Len())
	}

	// Salt e IKM deberían estar en cero después de usar
	for i, b := range salt.Value {
		if b != 0 {
			t.Errorf("Salt byte %d should be 0 after HKDFExtract, got %d", i, b)
		}
	}
}

// TestSecret_HKDFExpand prueba HKDF-Expand con Secrets.
func TestSecret_HKDFExpand(t *testing.T) {
	prk, _ := NewSecretRandom(32)
	info := []byte("info")
	length := 64

	okm, err := prk.HKDFExpand(info, length)
	if err != nil {
		t.Fatalf("HKDFExpand() error = %v", err)
	}

	// OKM debería tener la longitud correcta
	if okm.Len() != length {
		t.Errorf("OKM length should be %d, got %d", length, okm.Len())
	}
}

// TestSecret_DeriveSecret prueba la derivación de secretos.
func TestSecret_DeriveSecret(t *testing.T) {
	secret, _ := NewSecretRandom(32)
	cs := MLS128DHKEMP256
	label := "test label"

	derived, err := secret.DeriveSecret(cs, label)
	if err != nil {
		t.Fatalf("DeriveSecret() error = %v", err)
	}

	// El secreto derivado debería tener la longitud del hash
	if derived.Len() != cs.HashLength() {
		t.Errorf("Derived secret length should be %d, got %d", cs.HashLength(), derived.Len())
	}
}

// TestSecret_Hmac prueba HMAC con Secrets.
func TestSecret_Hmac(t *testing.T) {
	key, _ := NewSecretRandom(32)
	message := []byte("message to authenticate")

	mac, err := key.Hmac(message)
	if err != nil {
		t.Fatalf("Hmac() error = %v", err)
	}

	// MAC debería tener la longitud correcta (SHA-256)
	if len(mac) != 32 {
		t.Errorf("MAC length should be 32, got %d", len(mac))
	}
}

// TestSecret_NilSafety prueba que los métodos manejan nil correctamente.
func TestSecret_NilSafety(t *testing.T) {
	var nilSecret *Secret

	// AsSlice con nil debería retornar nil
	if nilSecret.AsSlice() != nil {
		t.Error("AsSlice() on nil should return nil")
	}

	// Len con nil debería retornar 0
	if nilSecret.Len() != 0 {
		t.Error("Len() on nil should return 0")
	}

	// Clone con nil debería retornar secret vacío
	clone := nilSecret.Clone()
	if clone == nil || clone.Value != nil {
		t.Error("Clone() on nil should return empty secret")
	}

	// Equal con nil
	if nilSecret.Equal(nilSecret) != true {
		t.Error("Equal() with both nil should return true")
	}
}

// TestSecretRandomCS prueba NewSecretRandomCS.
func TestSecretRandomCS(t *testing.T) {
	cs := MLS128DHKEMP256
	secret, err := NewSecretRandomCS(cs)
	if err != nil {
		t.Fatalf("NewSecretRandomCS() error = %v", err)
	}

	// Debería tener la longitud del hash del ciphersuite
	if secret.Len() != cs.HashLength() {
		t.Errorf("Secret length should be %d, got %d", cs.HashLength(), secret.Len())
	}
}

// TestZeroSecret prueba ZeroSecret.
func TestZeroSecret(t *testing.T) {
	length := 32
	secret := ZeroSecret(length)

	// Verificar longitud
	if secret.Len() != length {
		t.Errorf("ZeroSecret length should be %d, got %d", length, secret.Len())
	}

	// Verificar que todos los bytes son cero
	for i, b := range secret.Value {
		if b != 0 {
			t.Errorf("Byte %d should be 0, got %d", i, b)
		}
	}
}

// TestZeroSecretCS prueba ZeroSecretCS.
func TestZeroSecretCS(t *testing.T) {
	cs := MLS128DHKEMP256
	secret := ZeroSecretCS(cs)

	// Debería tener la longitud del hash
	if secret.Len() != cs.HashLength() {
		t.Errorf("ZeroSecretCS length should be %d, got %d", cs.HashLength(), secret.Len())
	}
}

// BenchmarkSecret_Random mide el performance de generación aleatoria.
func BenchmarkSecret_Random(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewSecretRandom(32)
	}
}

// BenchmarkSecret_HKDFExtract mide el performance de HKDF-Extract.
func BenchmarkSecret_HKDFExtract(b *testing.B) {
	salt, _ := NewSecretRandom(32)
	ikm, _ := NewSecretRandom(32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		salt.HKDFExtract(ikm)
	}
}

// BenchmarkSecret_HKDFExpand mide el performance de HKDF-Expand.
func BenchmarkSecret_HKDFExpand(b *testing.B) {
	prk, _ := NewSecretRandom(32)
	info := []byte("info")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prk.HKDFExpand(info, 64)
	}
}
