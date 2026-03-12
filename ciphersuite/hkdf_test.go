package ciphersuite

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestHKDF_RFC5869_TestCase1 tests Test Case 1 from RFC 5869.
// https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A.1
func TestHKDF_RFC5869_TestCase1(t *testing.T) {
	// RFC 5869 Test Case 1 - Basic test case with SHA-256
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	length := 42
	expectedOKM, _ := hex.DecodeString("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
	expectedPRK, _ := hex.DecodeString("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")

	hkdf := NewHKDF()

	// Test Extract
	prk := hkdf.Extract(salt, ikm)
	if !bytes.Equal(prk, expectedPRK) {
		t.Errorf("HKDF Extract failed:\ngot  %x\nwant %x", prk, expectedPRK)
	}

	// Test Expand
	okm, err := hkdf.Expand(prk, info, length)
	if err != nil {
		t.Fatalf("HKDF.Expand() error = %v", err)
	}
	if !bytes.Equal(okm, expectedOKM) {
		t.Errorf("HKDF Expand failed:\ngot  %x\nwant %x", okm, expectedOKM)
	}
}

// TestHKDF_RFC5869_TestCase2 tests Test Case 2 from RFC 5869.
// https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A.2
func TestHKDF_RFC5869_TestCase2(t *testing.T) {
	// RFC 5869 Test Case 2 - Test with SHA-256 and longer inputs/outputs
	ikm, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
	salt, _ := hex.DecodeString("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
	info, _ := hex.DecodeString("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	length := 82
	expectedOKM, _ := hex.DecodeString("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")
	expectedPRK, _ := hex.DecodeString("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")

	hkdf := NewHKDF()

	// Test Extract
	prk := hkdf.Extract(salt, ikm)
	if !bytes.Equal(prk, expectedPRK) {
		t.Errorf("HKDF Extract failed:\ngot  %x\nwant %x", prk, expectedPRK)
	}

	// Test Expand
	okm, err := hkdf.Expand(prk, info, length)
	if err != nil {
		t.Fatalf("HKDF.Expand() error = %v", err)
	}
	if !bytes.Equal(okm, expectedOKM) {
		t.Errorf("HKDF Expand failed:\ngot  %x\nwant %x", okm, expectedOKM)
	}
}

// TestHKDF_RFC5869_TestCase3 tests Test Case 3 from RFC 5869.
// https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A.3
func TestHKDF_RFC5869_TestCase3(t *testing.T) {
	// RFC 5869 Test Case 3 - Test with SHA-256 and zero-length salt/IKM
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	// salt := []byte{} // Empty salt - not used, we test with nil
	// info := []byte{} // Empty info - not used, we test with nil
	length := 42
	expectedOKM, _ := hex.DecodeString("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
	expectedPRK, _ := hex.DecodeString("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")

	hkdf := NewHKDF()

	// Test Extract (with nil salt, should use HashLen zeros)
	prk := hkdf.Extract(nil, ikm)
	if !bytes.Equal(prk, expectedPRK) {
		t.Errorf("HKDF Extract failed (nil salt):\ngot  %x\nwant %x", prk, expectedPRK)
	}

	// Test Expand (with nil info)
	okm, err := hkdf.Expand(prk, nil, length)
	if err != nil {
		t.Fatalf("HKDF.Expand() error = %v", err)
	}
	if !bytes.Equal(okm, expectedOKM) {
		t.Errorf("HKDF Expand failed:\ngot  %x\nwant %x", okm, expectedOKM)
	}
}

// TestHKDF_ExtractExpand tests the combined ExtractExpand function.
func TestHKDF_ExtractExpand(t *testing.T) {
	ikm := []byte("input key material")
	salt := []byte("salt")
	info := []byte("context info")
	length := 32

	hkdf := NewHKDF()

	// Test ExtractExpand
	okm, err := hkdf.ExtractExpand(salt, ikm, info, length)
	if err != nil {
		t.Fatalf("HKDF.ExtractExpand() error = %v", err)
	}
	if len(okm) != length {
		t.Errorf("HKDF.ExtractExpand() length mismatch: got %d, want %d", len(okm), length)
	}

	// Verify it's the same as doing Extract then Expand
	prk := hkdf.Extract(salt, ikm)
	okm2, err := hkdf.Expand(prk, info, length)
	if err != nil {
		t.Fatalf("HKDF.Expand() error = %v", err)
	}
	if !bytes.Equal(okm, okm2) {
		t.Errorf("HKDF ExtractExpand != Extract+Expand:\ngot  %x\nwant %x", okm, okm2)
	}
}

// TestHKDF_Expand_TooLarge tests that Expand rejects too large lengths.
func TestHKDF_Expand_TooLarge(t *testing.T) {
	hkdf := NewHKDF()
	prk := []byte("pseudorandom key")

	// Max length is 255 * HashLen = 255 * 32 = 8160
	_, err := hkdf.Expand(prk, []byte("info"), 8161)
	if err == nil {
		t.Error("HKDF.Expand() should reject length > 255*HashLen")
	}
}

// TestHKDF_NilInputs tests that HKDF handles nil inputs correctly.
func TestHKDF_NilInputs(t *testing.T) {
	hkdf := NewHKDF()
	ikm := []byte("input key material")

	// Extract with nil salt should work (uses zeros)
	prk := hkdf.Extract(nil, ikm)
	if len(prk) != sha256.Size {
		t.Errorf("HKDF.Extract(nil, ikm) returned wrong length: got %d, want %d", len(prk), sha256.Size)
	}

	// Expand with nil info should work
	okm, err := hkdf.Expand(prk, nil, 32)
	if err != nil {
		t.Fatalf("HKDF.Expand(prk, nil, 32) error = %v", err)
	}
	if len(okm) != 32 {
		t.Errorf("HKDF.Expand() returned wrong length: got %d, want 32", len(okm))
	}
}

// BenchmarkHKDF_Extract measures Extract performance.
func BenchmarkHKDF_Extract(b *testing.B) {
	hkdf := NewHKDF()
	salt := make([]byte, 32)
	ikm := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hkdf.Extract(salt, ikm)
	}
}

// BenchmarkHKDF_Expand measures Expand performance.
func BenchmarkHKDF_Expand(b *testing.B) {
	hkdf := NewHKDF()
	prk := make([]byte, 32)
	info := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hkdf.Expand(prk, info, 32)
	}
}

// BenchmarkHKDF_ExtractExpand measures ExtractExpand performance.
func BenchmarkHKDF_ExtractExpand(b *testing.B) {
	hkdf := NewHKDF()
	salt := make([]byte, 32)
	ikm := make([]byte, 32)
	info := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hkdf.ExtractExpand(salt, ikm, info, 32)
	}
}
