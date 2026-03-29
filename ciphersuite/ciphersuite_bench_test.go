package ciphersuite

import (
	"crypto/rand"
	"testing"
)

func BenchmarkHPKE_Encap(b *testing.B) {
	cs := MLS128DHKEMP256
	// HPKE uses ECDH keys, not ECDSA signature keys
	privKey, _ := DeriveKeyPair(cs, []byte("test-ikm-test-ikm-test-ikm-test-"))
	pubBytes := privKey.PublicKey().Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = EncapToBytes(pubBytes, cs)
	}
}

func BenchmarkHPKE_Decap(b *testing.B) {
	cs := MLS128DHKEMP256
	// HPKE for CS2 uses P-256
	privKey, _ := DeriveKeyPair(cs, []byte("test-ikm-test-ikm-test-ikm-test-"))
	pubBytes := privKey.PublicKey().Bytes()

	enc, _, err := EncapToBytes(pubBytes, cs)
	if err != nil {
		b.Fatalf("EncapToBytes failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecapToBytes(enc, privKey.Bytes(), cs)
	}
}

func BenchmarkSign(b *testing.B) {
	priv, _ := GenerateSignaturePrivateKey()
	data := make([]byte, 1024)
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = priv.Sign(data)
	}
}

func BenchmarkVerify(b *testing.B) {
	priv, _ := GenerateSignaturePrivateKey()
	pub := priv.PublicKey()
	data := make([]byte, 1024)
	rand.Read(data)
	sig, _ := priv.Sign(data)

	// Create MLSSignaturePublicKey for verify
	openPub := NewMLSSignaturePublicKey(pub.AsSlice(), ECDSA_SECP256R1_SHA256)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = openPub.Verify(data, sig)
	}
}

func BenchmarkKDFExpandLabel(b *testing.B) {
	secret, _ := NewSecretRandomCS(MLS128DHKEMP256)
	context := make([]byte, 32)
	rand.Read(context)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = secret.KdfExpandLabel("test-label", context, 32)
	}
}
