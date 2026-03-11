package ciphersuite

import (
	"testing"
)

// TestCipherSuite_IsSupported prueba qué cipher suites están soportadas.
func TestCipherSuite_IsSupported(t *testing.T) {
	// MLS128DHKEMX25519 (cs=1) debería estar soportado
	if !MLS128DHKEMX25519.IsSupported() {
		t.Error("MLS128DHKEMX25519 (cs=1) should be supported")
	}

	// MLS128DHKEMP256 (cs=2) debería estar soportado
	if !MLS128DHKEMP256.IsSupported() {
		t.Error("MLS128DHKEMP256 (cs=2) should be supported")
	}

	// MLS256DHKEMX25519ChaCha20 (cs=3) debería estar soportado
	if !MLS256DHKEMX25519ChaCha20.IsSupported() {
		t.Error("MLS256DHKEMX25519ChaCha20 (cs=3) should be supported")
	}

	// Cipher suites no soportadas (cs=4,5,6,7 son placeholders)
	var unsupported CipherSuite = 0x0004
	if unsupported.IsSupported() {
		t.Error("Unknown cipher suite 0x0004 should not be supported")
	}

	unsupported = 0xFFFF
	if unsupported.IsSupported() {
		t.Error("Unknown cipher suite 0xFFFF should not be supported")
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

// ============================================================================
// Tests para Cipher Suite 1 (Ed25519/X25519) - RFC 9420 §5.1
// ============================================================================

// TestEd25519_GenerateKeyPair prueba generación de keypair Ed25519
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

// TestEd25519_SignVerifyWithLabel prueba firma y verificación Ed25519
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

// TestEd25519_Bytes prueba serialización de keys Ed25519
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

// TestEd25519_NewPrivateKeyFromBytes prueba creación de private key desde bytes
func TestEd25519_NewPrivateKeyFromBytes(t *testing.T) {
	// Generar key original
	privKey1, _, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair failed: %v", err)
	}

	// Obtener bytes
	privBytes := privKey1.Bytes()

	// Crear key desde bytes
	privKey2, err := NewEd25519PrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewEd25519PrivateKey failed: %v", err)
	}

	// Ambas keys deberían firmar igual
	data := []byte("test")
	sig1, _ := privKey1.SignWithLabel("label", data)
	sig2, _ := privKey2.SignWithLabel("label", data)

	// Las firmas deberían ser iguales (Ed25519 es determinístico)
	if string(sig1.AsSlice()) != string(sig2.AsSlice()) {
		t.Error("Same private key should produce same signature")
	}
}

// TestEd25519_InvalidKeyLength prueba longitudes inválidas
func TestEd25519_InvalidKeyLength(t *testing.T) {
	// Private key muy corto
	_, err := NewEd25519PrivateKey([]byte{0x01, 0x02})
	if err == nil {
		t.Error("NewEd25519PrivateKey should fail with short key")
	}

	// Public key muy corto
	_, err = NewEd25519PublicKey([]byte{0x01, 0x02})
	if err == nil {
		t.Error("NewEd25519PublicKey should fail with short key")
	}
}

// ============================================================================
// Tests para X25519 (DHKEM) - RFC 9420 §4.1
// ============================================================================

// TestX25519_GenerateKeyPair prueba generación de keypair X25519
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

// TestX25519_EncapDecap prueba encapsulación/decapsulación X25519
func TestX25519_EncapDecap(t *testing.T) {
	// Generar keypair receptor
	pubKey, privKey, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair failed: %v", err)
	}

	// Encapsular
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

	// Decapsular
	sharedSecret2, err := DecapToBytes(ciphertext, privKey, MLS128DHKEMX25519)
	if err != nil {
		t.Fatalf("DecapToBytes failed: %v", err)
	}

	// Los shared secrets deberían ser iguales
	if string(sharedSecret1) != string(sharedSecret2) {
		t.Error("Encap/Decap should produce same shared secret")
	}
}

// TestDeriveKeyPairX25519 prueba derivación determinística de keypair
func TestDeriveKeyPairX25519(t *testing.T) {
	ikm := []byte("test ikm for derivation")

	// Derivar dos veces con mismo IKM
	pub1, priv1, err := DeriveKeyPairX25519(ikm)
	if err != nil {
		t.Fatalf("DeriveKeyPairX25519 failed: %v", err)
	}

	pub2, priv2, err := DeriveKeyPairX25519(ikm)
	if err != nil {
		t.Fatalf("DeriveKeyPairX25519 failed: %v", err)
	}

	// Deberían ser iguales (derivación determinística)
	if string(pub1) != string(pub2) || string(priv1) != string(priv2) {
		t.Error("Same IKM should produce same keypair")
	}
}

// ============================================================================
// Tests para Cipher Suite 3 (ChaCha20-Poly1305) - RFC 9420 §5.1
// ============================================================================

// TestChaCha20Poly1305_EncryptDecrypt prueba cifrado/descifrado ChaCha20-Poly1305
func TestChaCha20Poly1305_EncryptDecrypt(t *testing.T) {
	// Generar key y nonce
	key, err := GenerateChaCha20Key()
	if err != nil {
		t.Fatalf("GenerateChaCha20Key failed: %v", err)
	}
	nonce, err := GenerateChaCha20Nonce()
	if err != nil {
		t.Fatalf("GenerateChaCha20Nonce failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("ChaCha20 key should be 32 bytes, got %d", len(key))
	}

	if len(nonce) != 12 {
		t.Errorf("ChaCha20 nonce should be 12 bytes, got %d", len(nonce))
	}

	plaintext := []byte("Hello, ChaCha20!")
	aad := []byte("additional data")

	// Cifrar
	ciphertext, err := ChaCha20Poly1305Encrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("ChaCha20Poly1305Encrypt failed: %v", err)
	}

	if len(ciphertext) <= len(plaintext) {
		t.Error("Ciphertext should be longer than plaintext (includes auth tag)")
	}

	// Descifrar
	decrypted, err := ChaCha20Poly1305Decrypt(key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("ChaCha20Poly1305Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text mismatch: got %q, want %q", string(decrypted), string(plaintext))
	}
}

// TestChaCha20Poly1305_WrongKey prueba que key incorrecta falla
func TestChaCha20Poly1305_WrongKey(t *testing.T) {
	key1, _ := GenerateChaCha20Key()
	key2, _ := GenerateChaCha20Key()
	nonce, _ := GenerateChaCha20Nonce()

	plaintext := []byte("test message")
	aad := []byte("aad")

	ciphertext, _ := ChaCha20Poly1305Encrypt(key1, nonce, plaintext, aad)

	// Descifrar con key incorrecta debería fallar
	_, err := ChaCha20Poly1305Decrypt(key2, nonce, ciphertext, aad)
	if err == nil {
		t.Error("ChaCha20Poly1305Decrypt should fail with wrong key")
	}
}

// TestChaCha20Poly1305_TamperedData prueba que datos modificados fallan
func TestChaCha20Poly1305_TamperedData(t *testing.T) {
	key, _ := GenerateChaCha20Key()
	nonce, _ := GenerateChaCha20Nonce()

	plaintext := []byte("test message")
	aad := []byte("aad")

	ciphertext, _ := ChaCha20Poly1305Encrypt(key, nonce, plaintext, aad)

	// Corromper un byte del ciphertext
	ciphertext[0] ^= 0xFF

	// Descifrar debería fallar
	_, err := ChaCha20Poly1305Decrypt(key, nonce, ciphertext, aad)
	if err == nil {
		t.Error("ChaCha20Poly1305Decrypt should fail with tampered ciphertext")
	}
}

// TestChaCha20Poly1305_WrongAAD prueba que AAD incorrecto falla
func TestChaCha20Poly1305_WrongAAD(t *testing.T) {
	key, _ := GenerateChaCha20Key()
	nonce, _ := GenerateChaCha20Nonce()

	plaintext := []byte("test message")
	aad1 := []byte("aad1")
	aad2 := []byte("aad2")

	ciphertext, _ := ChaCha20Poly1305Encrypt(key, nonce, plaintext, aad1)

	// Descifrar con AAD incorrecto debería fallar
	_, err := ChaCha20Poly1305Decrypt(key, nonce, ciphertext, aad2)
	if err == nil {
		t.Error("ChaCha20Poly1305Decrypt should fail with wrong AAD")
	}
}

// TestChaCha20_KeyNonceGeneration prueba generación de key y nonce
func TestChaCha20_KeyNonceGeneration(t *testing.T) {
	key1, _ := GenerateChaCha20Key()
	key2, _ := GenerateChaCha20Key()

	if string(key1) == string(key2) {
		t.Error("GenerateChaCha20Key should produce different keys")
	}

	nonce1, _ := GenerateChaCha20Nonce()
	nonce2, _ := GenerateChaCha20Nonce()

	if string(nonce1) == string(nonce2) {
		t.Error("GenerateChaCha20Nonce should produce different nonces")
	}
}

// ============================================================================
// Tests para funciones hash y derivación - RFC 9420 §5.2
// ============================================================================

// TestCiphersuite_Hash prueba función hash
func TestCiphersuite_Hash(t *testing.T) {
	data := []byte("test data")

	// Hash con cs=2 (P256/AES-GCM)
	hashFunc := MLS128DHKEMP256.HashFunction()
	hash1 := hashFunc()
	hash1.Write(data)
	sum1 := hash1.Sum(nil)
	
	if len(sum1) != 32 {
		t.Errorf("SHA-256 hash should be 32 bytes, got %d", len(sum1))
	}

	// Hash con cs=1 (X25519)
	hashFunc2 := MLS128DHKEMX25519.HashFunction()
	hash2 := hashFunc2()
	hash2.Write(data)
	sum2 := hash2.Sum(nil)
	
	if len(sum2) != 32 {
		t.Errorf("SHA-256 hash should be 32 bytes, got %d", len(sum2))
	}

	// Mismo input debería producir mismo hash
	hash3 := hashFunc()
	hash3.Write(data)
	sum3 := hash3.Sum(nil)
	
	if string(sum1) != string(sum3) {
		t.Error("Hash should be deterministic")
	}
}

// TestDeriveKeyPairP256 prueba derivación de keypair P256
func TestDeriveKeyPairP256(t *testing.T) {
	ikm := []byte("test ikm for P256 derivation")

	// Derivar dos veces con mismo IKM
	pub1, priv1, err := DeriveKeyPairP256(ikm)
	if err != nil {
		t.Fatalf("DeriveKeyPairP256 failed: %v", err)
	}

	pub2, priv2, err := DeriveKeyPairP256(ikm)
	if err != nil {
		t.Fatalf("DeriveKeyPairP256 failed: %v", err)
	}

	// Deberían ser iguales (derivación determinística)
	if string(pub1) != string(pub2) || string(priv1) != string(priv2) {
		t.Error("Same IKM should produce same P256 keypair")
	}
}

// TestSignable_Sign_Verify prueba firma y verificación genérica
func TestSignable_Sign_Verify(t *testing.T) {
	// Generar keypair ECDSA
	privKey, err := GenerateSignaturePrivateKey()
	if err != nil {
		t.Fatalf("GenerateSignaturePrivateKey failed: %v", err)
	}

	data := []byte("test data to sign")

	// Firmar
	sig, err := SignWithLabel(privKey, "test_label", data)
	if err != nil {
		t.Fatalf("SignWithLabel failed: %v", err)
	}

	// Verificar
	pubKey := privKey.PublicKey()
	openMlsPubKey := NewOpenMlsSignaturePublicKey(pubKey.AsSlice(), ECDSA_SECP256R1_SHA256)
	if err := VerifyWithLabel(openMlsPubKey, "test_label", data, sig); err != nil {
		t.Errorf("VerifyWithLabel should succeed: %v", err)
	}

	// Verificar con label incorrecto debería fallar
	if err := VerifyWithLabel(openMlsPubKey, "wrong_label", data, sig); err == nil {
		t.Error("VerifyWithLabel should fail with wrong label")
	}
}
