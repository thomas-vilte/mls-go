package ciphersuite

import (
	"bytes"
	"testing"
)

// TestSignature_GenerateVerify prueba la generación y verificación de firmas.
func TestSignature_GenerateVerify(t *testing.T) {
	// Generar key pair
	privKey, err := GenerateSignaturePrivateKey()
	if err != nil {
		t.Fatalf("GenerateSignaturePrivateKey() error = %v", err)
	}

	data := []byte("Message to sign")

	// Sign
	signature, err := privKey.Sign(data)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verificar que la signature no está vacía
	if len(signature.AsSlice()) == 0 {
		t.Error("Signature should not be empty")
	}

	// Obtener public key
	pubKey := privKey.PublicKey()
	if pubKey == nil {
		t.Fatal("PublicKey() returned nil")
	}

	// Crear MLSSignaturePublicKey
	mlsPubKey := NewMLSSignaturePublicKey(pubKey.AsSlice(), ECDSA_SECP256R1_SHA256)

	// Verify
	err = mlsPubKey.Verify(data, signature)
	if err != nil {
		t.Errorf("Verify() error = %v", err)
	}
}

// TestSignature_WrongData prueba que falla con datos modificados.
func TestSignature_WrongData(t *testing.T) {
	privKey, _ := GenerateSignaturePrivateKey()

	data := []byte("Original message")
	signature, _ := privKey.Sign(data)
	pubKey := privKey.PublicKey()
	mlsPubKey := NewMLSSignaturePublicKey(pubKey.AsSlice(), ECDSA_SECP256R1_SHA256)

	// Modificar datos
	wrongData := []byte("Modified message")

	// Verify con datos modificados debe fallar
	err := mlsPubKey.Verify(wrongData, signature)
	if err == nil {
		t.Error("Verify() should fail with modified data")
	}
}

// TestSignature_TamperedSignature prueba que falla con signature modificada.
func TestSignature_TamperedSignature(t *testing.T) {
	privKey, _ := GenerateSignaturePrivateKey()

	data := []byte("Message")
	signature, _ := privKey.Sign(data)
	pubKey := privKey.PublicKey()
	mlsPubKey := NewMLSSignaturePublicKey(pubKey.AsSlice(), ECDSA_SECP256R1_SHA256)

	// Tamper con la signature
	tamperedSig := make([]byte, len(signature.AsSlice()))
	copy(tamperedSig, signature.AsSlice())
	tamperedSig[5] ^= 0xFF // Modificar byte

	tamperedSignature := NewSignature(tamperedSig)

	// Verify con signature modificada debe fallar
	err := mlsPubKey.Verify(data, tamperedSignature)
	if err == nil {
		t.Error("Verify() should fail with tampered signature")
	}
}

// TestSignature_EmptyData prueba firma de datos vacíos.
func TestSignature_EmptyData(t *testing.T) {
	privKey, _ := GenerateSignaturePrivateKey()

	data := []byte{}

	// Sign empty data
	signature, err := privKey.Sign(data)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify
	pubKey := privKey.PublicKey()
	mlsPubKey := NewMLSSignaturePublicKey(pubKey.AsSlice(), ECDSA_SECP256R1_SHA256)

	err = mlsPubKey.Verify(data, signature)
	if err != nil {
		t.Errorf("Verify() error = %v", err)
	}
}

// TestSignature_LargeData prueba firma de datos grandes.
func TestSignature_LargeData(t *testing.T) {
	privKey, _ := GenerateSignaturePrivateKey()

	// 10KB data
	data := make([]byte, 10240)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Sign
	signature, err := privKey.Sign(data)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify
	pubKey := privKey.PublicKey()
	mlsPubKey := NewMLSSignaturePublicKey(pubKey.AsSlice(), ECDSA_SECP256R1_SHA256)

	err = mlsPubKey.Verify(data, signature)
	if err != nil {
		t.Errorf("Verify() error = %v", err)
	}
}

// TestSignature_PublicKeyFormat prueba el formato de la public key.
func TestSignature_PublicKeyFormat(t *testing.T) {
	privKey, _ := GenerateSignaturePrivateKey()
	pubKey := privKey.PublicKey()

	// Verificar formato uncompressed (0x04 || X || Y = 65 bytes)
	pubKeyBytes := pubKey.AsSlice()
	if len(pubKeyBytes) != 65 {
		t.Errorf("Public key should be 65 bytes, got %d", len(pubKeyBytes))
	}
	if pubKeyBytes[0] != 0x04 {
		t.Errorf("Public key should start with 0x04, got 0x%02x", pubKeyBytes[0])
	}

	// Convertir a ECDSA y verificar
	ecdsaPubKey, err := NewSignaturePublicKey(pubKeyBytes).ToECDSA()
	if err != nil {
		t.Fatalf("ToECDSA() error = %v", err)
	}
	if ecdsaPubKey == nil {
		t.Error("ToECDSA() returned nil")
	}
}

// TestSignature_InvalidPublicKeyFormat prueba que falla con formato inválido.
func TestSignature_InvalidPublicKeyFormat(t *testing.T) {
	// Formato inválido (muy corto)
	invalidKey := []byte("too short")
	_, err := NewSignaturePublicKey(invalidKey).ToECDSA()
	if err == nil {
		t.Error("ToECDSA() should fail with short key")
	}

	// Formato inválido (no empieza con 0x04)
	invalidKey2 := make([]byte, 65)
	invalidKey2[0] = 0x02 // compressed format, no soportado
	_, err = NewSignaturePublicKey(invalidKey2).ToECDSA()
	if err == nil {
		t.Error("ToECDSA() should fail with invalid format")
	}
}

// TestSignContent prueba la creación y serialización de SignContent.
func TestSignContent(t *testing.T) {
	label := "test label"
	content := []byte("content to sign")

	signContent := NewSignContent(label, content)

	// Verificar que el label tiene el prefijo MLS
	expectedLabel := LabelPrefix + label
	if !bytes.Equal(signContent.Label, []byte(expectedLabel)) {
		t.Errorf("Label mismatch:\ngot  %s\nwant %s", signContent.Label, expectedLabel)
	}

	// Verificar contenido
	if !bytes.Equal(signContent.Content, content) {
		t.Errorf("Content mismatch:\ngot  %v\nwant %v", signContent.Content, content)
	}

	// Verificar marshaling
	marshaled := signContent.Marshal()
	if len(marshaled) == 0 {
		t.Error("Marshaled sign content should not be empty")
	}
}

// TestSignWithLabel prueba el firmado con label específico.
func TestSignWithLabel(t *testing.T) {
	privKey, _ := GenerateSignaturePrivateKey()

	label := "MLS 1.0 test label"
	payload := []byte("payload data")

	// Sign with label
	signature, err := SignWithLabel(privKey, label, payload)
	if err != nil {
		t.Fatalf("SignWithLabel() error = %v", err)
	}

	// Verify with label
	pubKey := privKey.PublicKey()
	mlsPubKey := NewMLSSignaturePublicKey(pubKey.AsSlice(), ECDSA_SECP256R1_SHA256)

	err = VerifyWithLabel(mlsPubKey, label, payload, signature)
	if err != nil {
		t.Errorf("VerifyWithLabel() error = %v", err)
	}
}

// TestSignature_Deterministic prueba que firmas del mismo dato son diferentes (por diseño ECDSA).
func TestSignature_NonDeterministic(t *testing.T) {
	privKey, _ := GenerateSignaturePrivateKey()
	data := []byte("Same data")

	// Firmar dos veces el mismo dato
	sig1, _ := privKey.Sign(data)
	sig2, _ := privKey.Sign(data)

	// Las firmas deberían ser diferentes (ECDSA usa randomness)
	if bytes.Equal(sig1.AsSlice(), sig2.AsSlice()) {
		t.Error("ECDSA signatures should be non-deterministic")
	}

	// Pero ambas deberían verificar
	pubKey := privKey.PublicKey()
	mlsPubKey := NewMLSSignaturePublicKey(pubKey.AsSlice(), ECDSA_SECP256R1_SHA256)

	if err := mlsPubKey.Verify(data, sig1); err != nil {
		t.Errorf("First signature verification failed: %v", err)
	}
	if err := mlsPubKey.Verify(data, sig2); err != nil {
		t.Errorf("Second signature verification failed: %v", err)
	}
}

// TestSignature_KeyConsistency prueba que la public key es consistente.
func TestSignature_KeyConsistency(t *testing.T) {
	privKey, _ := GenerateSignaturePrivateKey()

	// Obtener public key dos veces
	pubKey1 := privKey.PublicKey()
	pubKey2 := privKey.PublicKey()

	// Deberían ser iguales
	if !bytes.Equal(pubKey1.AsSlice(), pubKey2.AsSlice()) {
		t.Error("PublicKey() should return consistent results")
	}
}

// BenchmarkSignature_Sign mide el performance de signing.
func BenchmarkSignature_Sign(b *testing.B) {
	privKey, _ := GenerateSignaturePrivateKey()
	data := []byte("Message to sign")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := privKey.Sign(data); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSignature_Verify mide el performance de verification.
func BenchmarkSignature_Verify(b *testing.B) {
	privKey, _ := GenerateSignaturePrivateKey()
	data := []byte("Message to sign")
	signature, err := privKey.Sign(data)
	if err != nil {
		b.Fatal(err)
	}
	pubKey := privKey.PublicKey()
	mlsPubKey := NewMLSSignaturePublicKey(pubKey.AsSlice(), ECDSA_SECP256R1_SHA256)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := mlsPubKey.Verify(data, signature); err != nil {
			b.Fatal(err)
		}
	}
}
