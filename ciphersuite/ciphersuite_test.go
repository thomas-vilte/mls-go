package ciphersuite

import (
	"testing"
)

// TestCipherSuite_IsSupported tests which cipher suites are supported.
func TestCipherSuite_IsSupported(t *testing.T) {
	// MLS128DHKEMX25519 (cs=1) should be supported
	if !MLS128DHKEMX25519.IsSupported() {
		t.Error("MLS128DHKEMX25519 (cs=1) should be supported")
	}

	// MLS128DHKEMP256 (cs=2) should be supported
	if !MLS128DHKEMP256.IsSupported() {
		t.Error("MLS128DHKEMP256 (cs=2) should be supported")
	}

	// MLS256DHKEMX25519ChaCha20 (cs=3) should be supported
	if !MLS256DHKEMX25519ChaCha20.IsSupported() {
		t.Error("MLS256DHKEMX25519ChaCha20 (cs=3) should be supported")
	}

	// Unsupported cipher suites (cs=4,5,6,7 are placeholders)
	var unsupported CipherSuite = 0x0004
	if unsupported.IsSupported() {
		t.Error("Unknown cipher suite 0x0004 should not be supported")
	}

	unsupported = 0xFFFF
	if unsupported.IsSupported() {
		t.Error("Unknown cipher suite 0xFFFF should not be supported")
	}
}

// TestCipherSuite_HashAlgorithm tests hash algorithms.
func TestCipherSuite_HashAlgorithm(t *testing.T) {
	hashAlgo := MLS128DHKEMP256.HashAlgorithm()
	if hashAlgo != SHA256 {
		t.Errorf("MLS128DHKEMP256 should use SHA256, got %v", hashAlgo)
	}
}

// TestCipherSuite_AeadAlgorithm tests AEAD algorithms.
func TestCipherSuite_AeadAlgorithm(t *testing.T) {
	aeadAlgo := MLS128DHKEMP256.AeadAlgorithm()
	if aeadAlgo != AES128GCM {
		t.Errorf("MLS128DHKEMP256 should use AES128GCM, got %v", aeadAlgo)
	}
}

// TestCipherSuite_SignatureScheme tests signature schemes.
func TestCipherSuite_SignatureScheme(t *testing.T) {
	sigScheme := MLS128DHKEMP256.SignatureScheme()
	if sigScheme != ECDSA_SECP256R1_SHA256 {
		t.Errorf("MLS128DHKEMP256 should use ECDSA_SECP256R1_SHA256, got %v", sigScheme)
	}
}

// TestCipherSuite_HashLength tests hash lengths.
func TestCipherSuite_HashLength(t *testing.T) {
	hashLen := MLS128DHKEMP256.HashLength()
	if hashLen != 32 {
		t.Errorf("MLS128DHKEMP256 hash length should be 32, got %d", hashLen)
	}
}

// TestCipherSuite_AeadKeyLength tests AEAD key lengths.
func TestCipherSuite_AeadKeyLength(t *testing.T) {
	keyLen := MLS128DHKEMP256.AeadKeyLength()
	if keyLen != 16 {
		t.Errorf("MLS128DHKEMP256 AEAD key length should be 16, got %d", keyLen)
	}
}

// TestCipherSuite_AeadNonceLength tests nonce lengths.
func TestCipherSuite_AeadNonceLength(t *testing.T) {
	nonceLen := MLS128DHKEMP256.AeadNonceLength()
	if nonceLen != 12 {
		t.Errorf("MLS128DHKEMP256 AEAD nonce length should be 12, got %d", nonceLen)
	}
}

// TestCipherSuite_HPKEConfig tests HPKE configuration.
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

// TestCipherSuite_String tests string representation.
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

// TestHashAlgorithm_Size tests hash sizes.
func TestHashAlgorithm_Size(t *testing.T) {
	size := SHA256.Size()
	if size != 32 {
		t.Errorf("SHA256 size should be 32, got %d", size)
	}
}

// TestHashAlgorithm_String tests string representation.
func TestHashAlgorithm_String(t *testing.T) {
	str := SHA256.String()
	if str != "SHA256" {
		t.Errorf("SHA256 string = %s, want SHA256", str)
	}
}

// TestAeadAlgorithm_KeyLength tests AEAD key lengths.
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

// TestSignatureScheme_String tests string representation.
func TestSignatureScheme_String(t *testing.T) {
	str := ECDSA_SECP256R1_SHA256.String()
	if str != "ecdsa_secp256r1_sha256" {
		t.Errorf("Signature scheme string = %s, want ecdsa_secp256r1_sha256", str)
	}
}

// TestKEMAlgorithm_String tests KEM string representation.
func TestKEMAlgorithm_String(t *testing.T) {
	str := DHKEM_P256_HKDF_SHA256.String()
	if str != "DHKEM_P256_HKDF_SHA256" {
		t.Errorf("KEM string = %s, want DHKEM_P256_HKDF_SHA256", str)
	}
}

// TestKDFAlgorithm_String tests KDF string representation.
func TestKDFAlgorithm_String(t *testing.T) {
	str := HKDF_SHA256.String()
	if str != "HKDF-SHA256" {
		t.Errorf("KDF string = %s, want HKDF-SHA256", str)
	}
}

// TestEqualCT tests constant-time comparison.
func TestEqualCT(t *testing.T) {
	// Equal
	a := []byte{1, 2, 3, 4}
	b := []byte{1, 2, 3, 4}
	if !EqualCT(a, b) {
		t.Error("EqualCT should return true for equal slices")
	}

	// Different
	c := []byte{1, 2, 3, 5}
	if EqualCT(a, c) {
		t.Error("EqualCT should return false for different slices")
	}

	// Different length
	d := []byte{1, 2, 3}
	if EqualCT(a, d) {
		t.Error("EqualCT should return false for different lengths")
	}

	// Empty
	e := []byte{}
	f := []byte{}
	if !EqualCT(e, f) {
		t.Error("EqualCT should return true for empty slices")
	}
}

// TestSecret_Random tests random secret generation.
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

// TestSecret_Clone tests secret cloning.
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

// TestSecret_SecureZero tests that SecureZero clears memory.
func TestSecret_SecureZero(t *testing.T) {
	secret := NewSecret([]byte("secret value"))

	// Verify it has value
	if secret.Len() == 0 {
		t.Fatal("Secret should have value")
	}

	// Zero out
	secret.SecureZero()

	// Verify it's zeroed
	for i, b := range secret.Value {
		if b != 0 {
			t.Errorf("Byte %d should be 0 after SecureZero, got %d", i, b)
		}
	}
}

// TestSecret_HKDFExtract tests HKDF-Extract with Secrets.
func TestSecret_HKDFExtract(t *testing.T) {
	salt, _ := NewSecretRandom(32)
	ikm, _ := NewSecretRandom(32)

	prk, err := salt.HKDFExtract(ikm)
	if err != nil {
		t.Fatalf("HKDFExtract() error = %v", err)
	}

	// PRK should have correct length
	if prk.Len() != 32 {
		t.Errorf("PRK length should be 32, got %d", prk.Len())
	}

	// Salt and IKM should be zeroed after use
	for i, b := range salt.Value {
		if b != 0 {
			t.Errorf("Salt byte %d should be 0 after HKDFExtract, got %d", i, b)
		}
	}
}

// TestSecret_HKDFExpand tests HKDF-Expand with Secrets.
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

// TestSecret_DeriveSecret tests secret derivation.
func TestSecret_DeriveSecret(t *testing.T) {
	secret, _ := NewSecretRandom(32)
	cs := MLS128DHKEMP256
	label := "test label"

	derived, err := secret.DeriveSecret(cs, label)
	if err != nil {
		t.Fatalf("DeriveSecret() error = %v", err)
	}

	// Derived secret should have hash length
	if derived.Len() != cs.HashLength() {
		t.Errorf("Derived secret length should be %d, got %d", cs.HashLength(), derived.Len())
	}
}

// TestSecret_Hmac tests HMAC with Secrets.
func TestSecret_Hmac(t *testing.T) {
	key, _ := NewSecretRandom(32)
	message := []byte("message to authenticate")

	mac, err := key.Hmac(message)
	if err != nil {
		t.Fatalf("Hmac() error = %v", err)
	}

	// MAC should have correct length (SHA-256)
	if len(mac) != 32 {
		t.Errorf("MAC length should be 32, got %d", len(mac))
	}
}

// TestSecret_NilSafety tests that methods handle nil correctly.
func TestSecret_NilSafety(t *testing.T) {
	var nilSecret *Secret

	// AsSlice with nil should return nil
	if nilSecret.AsSlice() != nil {
		t.Error("AsSlice() on nil should return nil")
	}

	// Len with nil should return 0
	if nilSecret.Len() != 0 {
		t.Error("Len() on nil should return 0")
	}

	// Clone with nil should return empty secret
	clone := nilSecret.Clone()
	if clone == nil || clone.Value != nil {
		t.Error("Clone() on nil should return empty secret")
	}

	// Equal with nil
	if nilSecret.Equal(nilSecret) != true {
		t.Error("Equal() with both nil should return true")
	}
}

// TestSecretRandomCS tests NewSecretRandomCS.
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

// TestZeroSecret tests ZeroSecret.
func TestZeroSecret(t *testing.T) {
	length := 32
	secret := ZeroSecret(length)

	// Verify length
	if secret.Len() != length {
		t.Errorf("ZeroSecret length should be %d, got %d", length, secret.Len())
	}

	// Verify all bytes are zero
	for i, b := range secret.Value {
		if b != 0 {
			t.Errorf("Byte %d should be 0, got %d", i, b)
		}
	}
}

// TestZeroSecretCS tests ZeroSecretCS.
func TestZeroSecretCS(t *testing.T) {
	cs := MLS128DHKEMP256
	secret := ZeroSecretCS(cs)

	// Debería tener la longitud del hash
	if secret.Len() != cs.HashLength() {
		t.Errorf("ZeroSecretCS length should be %d, got %d", cs.HashLength(), secret.Len())
	}
}

// BenchmarkSecret_Random measures random generation performance.
func BenchmarkSecret_Random(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewSecretRandom(32)
	}
}

// BenchmarkSecret_HKDFExtract measures HKDF-Extract performance.
func BenchmarkSecret_HKDFExtract(b *testing.B) {
	salt, _ := NewSecretRandom(32)
	ikm, _ := NewSecretRandom(32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		salt.HKDFExtract(ikm)
	}
}

// BenchmarkSecret_HKDFExpand measures HKDF-Expand performance.
func BenchmarkSecret_HKDFExpand(b *testing.B) {
	prk, _ := NewSecretRandom(32)
	info := []byte("info")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prk.HKDFExpand(info, 64)
	}
}

// ============================================================================
// Tests for Cipher Suite 1 (Ed25519/X25519) - RFC 9420 §5.1
// ============================================================================

// TestEd25519_GenerateKeyPair tests Ed25519 keypair generation
func TestEd25519_GenerateKeyPair(t *testing.T) {
	privKey, pubKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair failed: %v", err)
	}

	if privKey == nil {
		t.Fatal("GenerateEd25519KeyPair should return non-nil private key")
	}

	if pubKey == nil {
		t.Fatal("GenerateEd25519KeyPair should return non-nil public key")
	}
}

// TestEd25519_SignVerifyWithLabel tests Ed25519 signing and verification
func TestEd25519_SignVerifyWithLabel(t *testing.T) {
	privKey, pubKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair failed: %v", err)
	}

	data := []byte("test message")
	sig, err := privKey.SignWithLabel("test_label", data)
	if err != nil {
		t.Fatalf("SignWithLabel failed: %v", err)
	}

	if len(sig.AsSlice()) != 64 {
		t.Errorf("Ed25519 signature should be 64 bytes, got %d", len(sig.AsSlice()))
	}

	// Verificar con label correcto
	if err := pubKey.VerifyWithLabel("test_label", data, sig); err != nil {
		t.Errorf("VerifyWithLabel should succeed: %v", err)
	}

	// Verificar con label incorrecto debería fallar
	if err := pubKey.VerifyWithLabel("wrong_label", data, sig); err == nil {
		t.Error("VerifyWithLabel should fail with wrong label")
	}

	// Verificar con data modificada debería fallar
	badData := []byte("tampered message")
	if err := pubKey.VerifyWithLabel("test_label", badData, sig); err == nil {
		t.Error("VerifyWithLabel should fail with tampered data")
	}
}

// TestEd25519_Bytes tests Ed25519 key serialization
func TestEd25519_Bytes(t *testing.T) {
	privKey, pubKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair failed: %v", err)
	}

	privBytes := privKey.Bytes()
	if len(privBytes) != 64 {
		t.Errorf("Ed25519 private key should be 64 bytes, got %d", len(privBytes))
	}

	pubBytes := pubKey.Bytes()
	if len(pubBytes) != 32 {
		t.Errorf("Ed25519 public key should be 32 bytes, got %d", len(pubBytes))
	}
}

// TestEd25519_NewPrivateKeyFromBytes tests private key creation from bytes
func TestEd25519_NewPrivateKeyFromBytes(t *testing.T) {
	// Generate original key
	privKey1, _, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair failed: %v", err)
	}

	// Get bytes
	privBytes := privKey1.Bytes()

	// Create key from bytes
	privKey2, err := NewEd25519PrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewEd25519PrivateKey failed: %v", err)
	}

	// Both keys should sign the same
	data := []byte("test")
	sig1, _ := privKey1.SignWithLabel("label", data)
	sig2, _ := privKey2.SignWithLabel("label", data)

	// Signatures should be equal (Ed25519 is deterministic)
	if string(sig1.AsSlice()) != string(sig2.AsSlice()) {
		t.Error("Same private key should produce same signature")
	}
}

// TestEd25519_InvalidKeyLength tests invalid lengths
func TestEd25519_InvalidKeyLength(t *testing.T) {
	// Private key too short
	_, err := NewEd25519PrivateKey([]byte{0x01, 0x02})
	if err == nil {
		t.Error("NewEd25519PrivateKey should fail with short key")
	}

	// Public key too short
	_, err = NewEd25519PublicKey([]byte{0x01, 0x02})
	if err == nil {
		t.Error("NewEd25519PublicKey should fail with short key")
	}
}

// ============================================================================
// Tests for X25519 (DHKEM) - RFC 9420 §4.1
// ============================================================================

// TestX25519_GenerateKeyPair tests X25519 keypair generation
func TestX25519_GenerateKeyPair(t *testing.T) {
	privKey, pubKey, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair failed: %v", err)
	}

	if privKey == nil {
		t.Fatal("GenerateX25519KeyPair should return non-nil private key")
	}

	if pubKey == nil {
		t.Fatal("GenerateX25519KeyPair should return non-nil public key")
	}
}

// TestX25519_EncapDecap tests X25519 encapsulation/decapsulation
func TestX25519_EncapDecap(t *testing.T) {
	// Generate receiver keypair
	pubKey, privKey, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair failed: %v", err)
	}

	// Encapsulate
	ciphertext, sharedSecret1, err := EncapToBytes(pubKey, MLS128DHKEMX25519)
	if err != nil {
		t.Fatalf("EncapToBytes failed: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Fatal("EncapToBytes should return non-empty ciphertext")
	}

	if len(sharedSecret1) == 0 {
		t.Fatal("EncapToBytes should return non-nil shared secret")
	}

	// Decapsulate
	sharedSecret2, err := DecapToBytes(ciphertext, privKey, MLS128DHKEMX25519)
	if err != nil {
		t.Fatalf("DecapToBytes failed: %v", err)
	}

	// Shared secrets should be equal
	if string(sharedSecret1) != string(sharedSecret2) {
		t.Error("Encap/Decap should produce same shared secret")
	}
}

// TestDeriveKeyPairX25519 tests deterministic keypair derivation
func TestDeriveKeyPairX25519(t *testing.T) {
	ikm := []byte("test ikm for derivation")

	// Derive twice with same IKM
	pub1, priv1, err := DeriveKeyPairX25519(ikm)
	if err != nil {
		t.Fatalf("DeriveKeyPairX25519 failed: %v", err)
	}

	pub2, priv2, err := DeriveKeyPairX25519(ikm)
	if err != nil {
		t.Fatalf("DeriveKeyPairX25519 failed: %v", err)
	}

	// Should be equal (deterministic derivation)
	if string(pub1) != string(pub2) || string(priv1) != string(priv2) {
		t.Error("Same IKM should produce same keypair")
	}
}

// ============================================================================
// Tests for hash and derivation functions - RFC 9420 §5.2
// ============================================================================

// TestCiphersuite_Hash tests hash function
func TestCiphersuite_Hash(t *testing.T) {
	data := []byte("test data")

	// Hash with cs=2 (P256/AES-GCM)
	hashFunc := MLS128DHKEMP256.HashFunction()
	hash1 := hashFunc()
	hash1.Write(data)
	sum1 := hash1.Sum(nil)

	if len(sum1) != 32 {
		t.Errorf("SHA-256 hash should be 32 bytes, got %d", len(sum1))
	}

	// Hash with cs=1 (X25519)
	hashFunc2 := MLS128DHKEMX25519.HashFunction()
	hash2 := hashFunc2()
	hash2.Write(data)
	sum2 := hash2.Sum(nil)

	if len(sum2) != 32 {
		t.Errorf("SHA-256 hash should be 32 bytes, got %d", len(sum2))
	}

	// Same input should produce same hash
	hash3 := hashFunc()
	hash3.Write(data)
	sum3 := hash3.Sum(nil)

	if string(sum1) != string(sum3) {
		t.Error("Hash should be deterministic")
	}
}

// TestDeriveKeyPairP256 tests P256 keypair derivation
func TestDeriveKeyPairP256(t *testing.T) {
	ikm := []byte("test ikm for P256 derivation")

	// Derive twice with same IKM
	pub1, priv1, err := DeriveKeyPairP256(ikm)
	if err != nil {
		t.Fatalf("DeriveKeyPairP256 failed: %v", err)
	}

	pub2, priv2, err := DeriveKeyPairP256(ikm)
	if err != nil {
		t.Fatalf("DeriveKeyPairP256 failed: %v", err)
	}

	// Should be equal (deterministic derivation)
	if string(pub1) != string(pub2) || string(priv1) != string(priv2) {
		t.Error("Same IKM should produce same P256 keypair")
	}
}

// TestSignable_Sign_Verify tests generic signing and verification
func TestSignable_Sign_Verify(t *testing.T) {
	// Generate ECDSA keypair
	privKey, err := GenerateSignaturePrivateKey()
	if err != nil {
		t.Fatalf("GenerateSignaturePrivateKey failed: %v", err)
	}

	data := []byte("test data to sign")

	// Sign
	sig, err := SignWithLabel(privKey, "test_label", data)
	if err != nil {
		t.Fatalf("SignWithLabel failed: %v", err)
	}

	// Verify
	pubKey := privKey.PublicKey()
	openMlsPubKey := NewOpenMlsSignaturePublicKey(pubKey.AsSlice(), ECDSA_SECP256R1_SHA256)
	if err := VerifyWithLabel(openMlsPubKey, "test_label", data, sig); err != nil {
		t.Errorf("VerifyWithLabel should succeed: %v", err)
	}

	// Verify with wrong label should fail
	if err := VerifyWithLabel(openMlsPubKey, "wrong_label", data, sig); err == nil {
		t.Error("VerifyWithLabel should fail with wrong label")
	}
}
