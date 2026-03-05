package ciphersuite

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

// TestHPKE_EncryptDecrypt prueba el cifrado/descifrado HPKE completo.
func TestHPKE_EncryptDecrypt(t *testing.T) {
	// Generar key pair
	privKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	publicKey := privKey.PublicKey().Bytes()

	plaintext := []byte("Hello, MLS!")
	label := "test encryption"
	context := []byte("context data")
	cs := MLS128DHKEMP256

	// Encrypt
	ciphertext, err := EncryptWithLabel(publicKey, label, context, plaintext, cs)
	if err != nil {
		t.Fatalf("EncryptWithLabel() error = %v", err)
	}

	// Verificar que el ciphertext tiene KEMOutput y Ciphertext
	if len(ciphertext.KEMOutput) == 0 {
		t.Error("KEMOutput should not be empty")
	}
	if len(ciphertext.Ciphertext) == 0 {
		t.Error("Ciphertext should not be empty")
	}

	// Decrypt
	privKeyBytes := privKey.Bytes()
	decrypted, err := DecryptWithLabel(privKeyBytes, label, context, ciphertext, cs)
	if err != nil {
		t.Fatalf("DecryptWithLabel() error = %v", err)
	}

	// Verificar
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption mismatch:\ngot  %s\nwant %s", decrypted, plaintext)
	}
}

// TestHPKE_WrongKey prueba que falla con clave privada incorrecta.
func TestHPKE_WrongKey(t *testing.T) {
	// Generar dos key pairs
	privKey1, _ := ecdh.P256().GenerateKey(rand.Reader)
	privKey2, _ := ecdh.P256().GenerateKey(rand.Reader)

	publicKey1 := privKey1.PublicKey().Bytes()
	plaintext := []byte("Secret message")
	label := "test"
	context := []byte{}
	cs := MLS128DHKEMP256

	// Encrypt con key 1
	ciphertext, err := EncryptWithLabel(publicKey1, label, context, plaintext, cs)
	if err != nil {
		t.Fatalf("EncryptWithLabel() error = %v", err)
	}

	// Intentar decrypt con key 2 (incorrecta)
	privKey2Bytes := privKey2.Bytes()
	_, err = DecryptWithLabel(privKey2Bytes, label, context, ciphertext, cs)
	if err == nil {
		t.Error("DecryptWithLabel() should fail with wrong private key")
	}
}

// TestHPKE_TamperedCiphertext prueba que detecta ciphertext modificado.
func TestHPKE_TamperedCiphertext(t *testing.T) {
	privKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey().Bytes()

	plaintext := []byte("Secret message")
	label := "test"
	context := []byte{}
	cs := MLS128DHKEMP256

	// Encrypt
	ciphertext, err := EncryptWithLabel(publicKey, label, context, plaintext, cs)
	if err != nil {
		t.Fatalf("EncryptWithLabel() error = %v", err)
	}

	// Tamper con el ciphertext
	tampered := &HpkeCiphertext{
		KEMOutput:  make([]byte, len(ciphertext.KEMOutput)),
		Ciphertext: make([]byte, len(ciphertext.Ciphertext)),
	}
	copy(tampered.KEMOutput, ciphertext.KEMOutput)
	copy(tampered.Ciphertext, ciphertext.Ciphertext)
	tampered.Ciphertext[0] ^= 0xFF // Modificar primer byte

	// Decrypt con datos modificados debe fallar
	privKeyBytes := privKey.Bytes()
	_, err = DecryptWithLabel(privKeyBytes, label, context, tampered, cs)
	if err == nil {
		t.Error("DecryptWithLabel() should fail with tampered ciphertext")
	}
}

// TestHPKE_EmptyPlaintext prueba cifrado de plaintext vacío.
func TestHPKE_EmptyPlaintext(t *testing.T) {
	privKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey().Bytes()

	plaintext := []byte{}
	label := "test"
	context := []byte{}
	cs := MLS128DHKEMP256

	// Encrypt empty plaintext
	ciphertext, err := EncryptWithLabel(publicKey, label, context, plaintext, cs)
	if err != nil {
		t.Fatalf("EncryptWithLabel() error = %v", err)
	}

	// Decrypt
	privKeyBytes := privKey.Bytes()
	decrypted, err := DecryptWithLabel(privKeyBytes, label, context, ciphertext, cs)
	if err != nil {
		t.Fatalf("DecryptWithLabel() error = %v", err)
	}

	// Verificar
	if len(decrypted) != 0 {
		t.Errorf("Expected empty decrypted data, got %d bytes", len(decrypted))
	}
}

// TestHPKE_LargePlaintext prueba cifrado de plaintext grande.
func TestHPKE_LargePlaintext(t *testing.T) {
	privKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey().Bytes()

	// 1KB plaintext
	plaintext := make([]byte, 1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	label := "test"
	context := []byte{}
	cs := MLS128DHKEMP256

	// Encrypt
	ciphertext, err := EncryptWithLabel(publicKey, label, context, plaintext, cs)
	if err != nil {
		t.Fatalf("EncryptWithLabel() error = %v", err)
	}

	// Decrypt
	privKeyBytes := privKey.Bytes()
	decrypted, err := DecryptWithLabel(privKeyBytes, label, context, ciphertext, cs)
	if err != nil {
		t.Fatalf("DecryptWithLabel() error = %v", err)
	}

	// Verificar
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption mismatch for large plaintext")
	}
}

// TestHPKE_DifferentLabels prueba que diferentes labels producen diferentes ciphertexts.
func TestHPKE_DifferentLabels(t *testing.T) {
	privKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey().Bytes()

	plaintext := []byte("Same plaintext")
	context := []byte{}
	cs := MLS128DHKEMP256

	// Encrypt con diferentes labels
	ciphertext1, err := EncryptWithLabel(publicKey, "label1", context, plaintext, cs)
	if err != nil {
		t.Fatalf("EncryptWithLabel() error = %v", err)
	}

	ciphertext2, err := EncryptWithLabel(publicKey, "label2", context, plaintext, cs)
	if err != nil {
		t.Fatalf("EncryptWithLabel() error = %v", err)
	}

	// Los ciphertexts deberían ser diferentes (diferente KEMOutput por ephemeral key)
	if bytes.Equal(ciphertext1.KEMOutput, ciphertext2.KEMOutput) {
		t.Error("Different labels should produce different KEMOutputs")
	}
}

// TestHPKE_InvalidPublicKey prueba que falla con public key inválida.
func TestHPKE_InvalidPublicKey(t *testing.T) {
	invalidPublicKey := []byte("invalid key")
	plaintext := []byte("test")
	label := "test"
	context := []byte{}
	cs := MLS128DHKEMP256

	_, err := EncryptWithLabel(invalidPublicKey, label, context, plaintext, cs)
	if err == nil {
		t.Error("EncryptWithLabel() should fail with invalid public key")
	}
}

// TestHPKE_InvalidPrivateKey prueba que falla con private key inválida.
func TestHPKE_InvalidPrivateKey(t *testing.T) {
	privKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey().Bytes()

	plaintext := []byte("test")
	label := "test"
	context := []byte{}
	cs := MLS128DHKEMP256

	// Encrypt
	ciphertext, err := EncryptWithLabel(publicKey, label, context, plaintext, cs)
	if err != nil {
		t.Fatalf("EncryptWithLabel() error = %v", err)
	}

	// Decrypt con private key inválida
	invalidPrivKey := []byte("invalid key")
	_, err = DecryptWithLabel(invalidPrivKey, label, context, ciphertext, cs)
	if err == nil {
		t.Error("DecryptWithLabel() should fail with invalid private key")
	}
}

// TestEncryptContext prueba la creación y serialización de EncryptContext.
func TestEncryptContext(t *testing.T) {
	label := "test label"
	context := []byte("test context")

	encContext := NewEncryptContext(label, context)

	// Verificar que el label tiene el prefijo MLS
	expectedLabel := LabelPrefix + label
	if !bytes.Equal(encContext.Label, []byte(expectedLabel)) {
		t.Errorf("Label mismatch:\ngot  %s\nwant %s", encContext.Label, expectedLabel)
	}

	// Verificar contexto
	if !bytes.Equal(encContext.Context, context) {
		t.Errorf("Context mismatch:\ngot  %v\nwant %v", encContext.Context, context)
	}

	// Verificar marshaling
	marshaled := encContext.Marshal()
	if len(marshaled) == 0 {
		t.Error("Marshaled context should not be empty")
	}
}

// BenchmarkHPKE_Encrypt mide el performance de encrypt.
func BenchmarkHPKE_Encrypt(b *testing.B) {
	privKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey().Bytes()
	plaintext := []byte("Hello, MLS!")
	label := "benchmark"
	context := []byte{}
	cs := MLS128DHKEMP256

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncryptWithLabel(publicKey, label, context, plaintext, cs)
	}
}

// BenchmarkHPKE_Decrypt mide el performance de decrypt.
func BenchmarkHPKE_Decrypt(b *testing.B) {
	privKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey().Bytes()
	plaintext := []byte("Hello, MLS!")
	label := "benchmark"
	context := []byte{}
	cs := MLS128DHKEMP256

	// Pre-encrypt
	ciphertext, _ := EncryptWithLabel(publicKey, label, context, plaintext, cs)
	privKeyBytes := privKey.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecryptWithLabel(privKeyBytes, label, context, ciphertext, cs)
	}
}
