package ciphersuite

import (
	"bytes"
	"testing"
)

// TestSignature_GenerateVerify verifies signature generation and verification.
func TestSignature_GenerateVerify(t *testing.T) {
	// Generate key pair
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

	// Verify signature is not empty
	if len(signature.AsSlice()) == 0 {
		t.Error("Signature should not be empty")
	}

	// Obtener public key
	pubKey := privKey.PublicKey()
	if pubKey == nil {
		t.Fatal("PublicKey() returned nil")
	}

	// Create MLSSignaturePublicKey.
	mlsPubKey := NewMLSSignaturePublicKey(pubKey.AsSlice(), ECDSA_SECP256R1_SHA256)

	// Verify
	err = mlsPubKey.Verify(data, signature)
	if err != nil {
		t.Errorf("Verify() error = %v", err)
	}
}

// TestSignature_WrongData verifies that modified data fails verification.
func TestSignature_WrongData(t *testing.T) {
	privKey, _ := GenerateSignaturePrivateKey()

	data := []byte("Original message")
	signature, _ := privKey.Sign(data)
	pubKey := privKey.PublicKey()
	mlsPubKey := NewMLSSignaturePublicKey(pubKey.AsSlice(), ECDSA_SECP256R1_SHA256)

	// Modificar datos
	wrongData := []byte("Modified message")

	// Verification with modified data must fail.
	err := mlsPubKey.Verify(wrongData, signature)
	if err == nil {
		t.Error("Verify() should fail with modified data")
	}
}

// TestSignature_TamperedSignature verifies that a tampered signature fails.
func TestSignature_TamperedSignature(t *testing.T) {
	privKey, _ := GenerateSignaturePrivateKey()

	data := []byte("Message")
	signature, _ := privKey.Sign(data)
	pubKey := privKey.PublicKey()
	mlsPubKey := NewMLSSignaturePublicKey(pubKey.AsSlice(), ECDSA_SECP256R1_SHA256)

	// Tamper the signature
	tamperedSig := make([]byte, len(signature.AsSlice()))
	copy(tamperedSig, signature.AsSlice())
	tamperedSig[5] ^= 0xFF // Modify byte

	tamperedSignature := NewSignature(tamperedSig)

	// Verification with a tampered signature must fail.
	err := mlsPubKey.Verify(data, tamperedSignature)
	if err == nil {
		t.Error("Verify() should fail with tampered signature")
	}
}

// TestSignature_EmptyData verifies signing empty input.
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

// TestSignature_LargeData verifies signing large input.
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

// TestSignature_PublicKeyFormat verifies the public key encoding.
func TestSignature_PublicKeyFormat(t *testing.T) {
	privKey, _ := GenerateSignaturePrivateKey()
	pubKey := privKey.PublicKey()

	// Verify uncompressed format (0x04 || X || Y = 65 bytes)
	pubKeyBytes := pubKey.AsSlice()
	if len(pubKeyBytes) != 65 {
		t.Errorf("Public key should be 65 bytes, got %d", len(pubKeyBytes))
	}
	if pubKeyBytes[0] != 0x04 {
		t.Errorf("Public key should start with 0x04, got 0x%02x", pubKeyBytes[0])
	}

	// Convert to ECDSA and verify
	ecdsaPubKey, err := NewSignaturePublicKey(pubKeyBytes).ToECDSA()
	if err != nil {
		t.Fatalf("ToECDSA() error = %v", err)
	}
	if ecdsaPubKey == nil {
		t.Error("ToECDSA() returned nil")
	}
}

// TestSignature_InvalidPublicKeyFormat verifies that invalid key formats fail.
func TestSignature_InvalidPublicKeyFormat(t *testing.T) {
	// Formato inválido (muy corto)
	invalidKey := []byte("too short")
	_, err := NewSignaturePublicKey(invalidKey).ToECDSA()
	if err == nil {
		t.Error("ToECDSA() should fail with short key")
	}

	// Invalid format (doesn't start with 0x04)
	invalidKey2 := make([]byte, 65)
	invalidKey2[0] = 0x02 // compressed format, not supported
	_, err = NewSignaturePublicKey(invalidKey2).ToECDSA()
	if err == nil {
		t.Error("ToECDSA() should fail with invalid format")
	}
}

// TestSignContent verifies SignContent creation and marshaling.
func TestSignContent(t *testing.T) {
	label := "test label"
	content := []byte("content to sign")

	signContent := NewSignContent(label, content)

	// Verify label has MLS prefix
	expectedLabel := LabelPrefix + label
	if !bytes.Equal(signContent.Label, []byte(expectedLabel)) {
		t.Errorf("Label mismatch:\ngot  %s\nwant %s", signContent.Label, expectedLabel)
	}

	// Verify content
	if !bytes.Equal(signContent.Content, content) {
		t.Errorf("Content mismatch:\ngot  %v\nwant %v", signContent.Content, content)
	}

	// Verify marshaling
	marshaled := signContent.Marshal()
	if len(marshaled) == 0 {
		t.Error("Marshaled sign content should not be empty")
	}
}

// TestSignWithLabel verifies labeled signing.
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

// TestSignature_Deterministic verifies that ECDSA signatures differ for the same input.
func TestSignature_NonDeterministic(t *testing.T) {
	privKey, _ := GenerateSignaturePrivateKey()
	data := []byte("Same data")

	// Firmar dos veces el mismo dato
	sig1, _ := privKey.Sign(data)
	sig2, _ := privKey.Sign(data)

	// Signatures should differ because ECDSA uses randomness.
	if bytes.Equal(sig1.AsSlice(), sig2.AsSlice()) {
		t.Error("ECDSA signatures should be non-deterministic")
	}

	// Both signatures should still verify.
	pubKey := privKey.PublicKey()
	mlsPubKey := NewMLSSignaturePublicKey(pubKey.AsSlice(), ECDSA_SECP256R1_SHA256)

	if err := mlsPubKey.Verify(data, sig1); err != nil {
		t.Errorf("First signature verification failed: %v", err)
	}
	if err := mlsPubKey.Verify(data, sig2); err != nil {
		t.Errorf("Second signature verification failed: %v", err)
	}
}

// TestSignature_KeyConsistency verifies public key consistency.
func TestSignature_KeyConsistency(t *testing.T) {
	privKey, _ := GenerateSignaturePrivateKey()

	// Obtener public key dos veces
	pubKey1 := privKey.PublicKey()
	pubKey2 := privKey.PublicKey()

	// Should be equal
	if !bytes.Equal(pubKey1.AsSlice(), pubKey2.AsSlice()) {
		t.Error("PublicKey() should return consistent results")
	}
}

// BenchmarkSignature_Sign measures signing performance.
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

// BenchmarkSignature_Verify measures verification performance.
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
