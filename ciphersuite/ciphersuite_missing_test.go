package ciphersuite

import (
	"bytes"
	"errors"
	"testing"
)

// ============================================================================
// Hash()
// ============================================================================

func TestHash_AllSuites(t *testing.T) {
	data := []byte("hello mls")
	suites := []CipherSuite{MLS128DHKEMX25519, MLS128DHKEMP256, MLS128DHKEMX25519ChaCha20}
	for _, cs := range suites {
		h, err := Hash(cs, data)
		if err != nil {
			t.Errorf("Hash(%v) unexpected error: %v", cs, err)
		}
		if len(h) != 32 {
			t.Errorf("Hash(%v) expected 32 bytes, got %d", cs, len(h))
		}
		// Deterministic
		h2, _ := Hash(cs, data)
		for i, b := range h {
			if b != h2[i] {
				t.Errorf("Hash(%v) is not deterministic", cs)
				break
			}
		}
	}
}

func TestHash_UnsupportedSuite(t *testing.T) {
	_, err := Hash(CipherSuite(0x0099), []byte("data"))
	if err == nil {
		t.Fatal("expected error for unsupported suite")
	}
	if !errors.Is(err, ErrUnsupportedSuite) {
		t.Errorf("expected ErrUnsupportedSuite, got %v", err)
	}
}

// ============================================================================
// AeadAlgorithm.String()
// ============================================================================

func TestAeadAlgorithm_String(t *testing.T) {
	cases := []struct {
		alg  AeadAlgorithm
		want string
	}{
		{AES128GCM, "AES-128-GCM"},
		{AES256GCM, "AES-256-GCM"},
		{ChaCha20Poly1305, "ChaCha20-Poly1305"},
	}
	for _, tc := range cases {
		if got := tc.alg.String(); got != tc.want {
			t.Errorf("AeadAlgorithm(%d).String() = %q, want %q", tc.alg, got, tc.want)
		}
	}
}

// ============================================================================
// EncryptWithCipherSuite / DecryptWithCipherSuite — error paths
// ============================================================================

func TestEncryptWithCipherSuite_InvalidKeyLength(t *testing.T) {
	nonce := make([]byte, 12)
	_, err := EncryptWithCipherSuite([]byte{0x01, 0x02}, nonce, []byte("plain"), nil, MLS128DHKEMP256)
	if !errors.Is(err, ErrInvalidKeyLength) {
		t.Errorf("expected ErrInvalidKeyLength, got %v", err)
	}
}

func TestEncryptWithCipherSuite_InvalidNonceLength(t *testing.T) {
	key := make([]byte, 16)
	_, err := EncryptWithCipherSuite(key, []byte{0x01}, []byte("plain"), nil, MLS128DHKEMP256)
	if !errors.Is(err, ErrInvalidNonceLength) {
		t.Errorf("expected ErrInvalidNonceLength, got %v", err)
	}
}

func TestEncryptWithCipherSuite_UnsupportedSuite(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	_, err := EncryptWithCipherSuite(key, nonce, []byte("plain"), nil, CipherSuite(0x0099))
	if err == nil {
		t.Fatal("expected error for unsupported suite")
	}
}

func TestDecryptWithCipherSuite_InvalidKeyLength(t *testing.T) {
	nonce := make([]byte, 12)
	_, err := DecryptWithCipherSuite([]byte{0x01}, nonce, []byte("ct"), nil, MLS128DHKEMX25519ChaCha20)
	if !errors.Is(err, ErrInvalidKeyLength) {
		t.Errorf("expected ErrInvalidKeyLength, got %v", err)
	}
}

func TestDecryptWithCipherSuite_TamperedCiphertext(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	ct, err := EncryptWithCipherSuite(key, nonce, []byte("secret"), nil, MLS128DHKEMP256)
	if err != nil {
		t.Fatal(err)
	}
	ct[0] ^= 0xFF // tamper
	_, err = DecryptWithCipherSuite(key, nonce, ct, nil, MLS128DHKEMP256)
	if !errors.Is(err, ErrAeadDecryption) {
		t.Errorf("expected ErrAeadDecryption, got %v", err)
	}
}

func TestDecryptWithCipherSuite_ChaCha20_TamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	ct, err := EncryptWithCipherSuite(key, nonce, []byte("secret"), nil, MLS128DHKEMX25519ChaCha20)
	if err != nil {
		t.Fatal(err)
	}
	ct[0] ^= 0xFF
	_, err = DecryptWithCipherSuite(key, nonce, ct, nil, MLS128DHKEMX25519ChaCha20)
	if !errors.Is(err, ErrAeadDecryption) {
		t.Errorf("expected ErrAeadDecryption, got %v", err)
	}
}

// ============================================================================
// CS3 — EncryptWithCipherSuite roundtrip
// ============================================================================

func TestEncryptWithCipherSuite_CS3_Roundtrip(t *testing.T) {
	key := make([]byte, 32) // ChaCha20 needs 32-byte key
	nonce := make([]byte, 12)
	plaintext := []byte("cs3 roundtrip test")
	aad := []byte("additional data")

	ct, err := EncryptWithCipherSuite(key, nonce, plaintext, aad, MLS128DHKEMX25519ChaCha20)
	if err != nil {
		t.Fatalf("EncryptWithCipherSuite CS3: %v", err)
	}
	got, err := DecryptWithCipherSuite(key, nonce, ct, aad, MLS128DHKEMX25519ChaCha20)
	if err != nil {
		t.Fatalf("DecryptWithCipherSuite CS3: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("CS3 roundtrip: got %q, want %q", got, plaintext)
	}
}

// ============================================================================
// DeriveKeyPair (hpke.go)
// ============================================================================

func TestDeriveKeyPair_AllSuites(t *testing.T) {
	ikm := make([]byte, 32)
	suites := []CipherSuite{MLS128DHKEMX25519, MLS128DHKEMP256, MLS128DHKEMX25519ChaCha20}
	for _, cs := range suites {
		priv, err := DeriveKeyPair(cs, ikm)
		if err != nil {
			t.Errorf("DeriveKeyPair(%v): %v", cs, err)
			continue
		}
		if priv == nil {
			t.Errorf("DeriveKeyPair(%v) returned nil key", cs)
			continue
		}
		// Deterministic
		priv2, _ := DeriveKeyPair(cs, ikm)
		if !bytes.Equal(priv.Bytes(), priv2.Bytes()) {
			t.Errorf("DeriveKeyPair(%v) is not deterministic", cs)
		}
	}
}

func TestDeriveKeyPair_UnsupportedSuite(t *testing.T) {
	_, err := DeriveKeyPair(CipherSuite(0x0099), make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for unsupported suite")
	}
}

// ============================================================================
// GenerateSignaturePrivateKeyForCS
// ============================================================================

func TestGenerateSignaturePrivateKeyForCS(t *testing.T) {
	suites := []CipherSuite{MLS128DHKEMX25519, MLS128DHKEMP256, MLS128DHKEMX25519ChaCha20}
	for _, cs := range suites {
		k, err := GenerateSignaturePrivateKeyForCS(cs)
		if err != nil {
			t.Errorf("GenerateSignaturePrivateKeyForCS(%v): %v", cs, err)
			continue
		}
		if k == nil {
			t.Errorf("GenerateSignaturePrivateKeyForCS(%v) returned nil", cs)
		}
	}
}

func TestGenerateSignaturePrivateKeyForCS_Unsupported(t *testing.T) {
	_, err := GenerateSignaturePrivateKeyForCS(CipherSuite(0x0099))
	if err == nil {
		t.Fatal("expected error for unsupported suite")
	}
}

// ============================================================================
// NewEd25519SignaturePrivateKey + Scheme()
// ============================================================================

func TestNewEd25519SignaturePrivateKey(t *testing.T) {
	priv, _, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	wrapped := NewEd25519SignaturePrivateKey(priv.key)
	if wrapped == nil {
		t.Fatal("NewEd25519SignaturePrivateKey returned nil")
	}
	if wrapped.Scheme() != ED25519 {
		t.Errorf("Scheme() = %v, want ED25519", wrapped.Scheme())
	}
}

func TestSignaturePrivateKey_Scheme_ECDSA(t *testing.T) {
	k, err := GenerateSignaturePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if k.Scheme() != ECDSA_SECP256R1_SHA256 {
		t.Errorf("Scheme() = %v, want ECDSA_SECP256R1_SHA256", k.Scheme())
	}
}
