// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE file.

package extensions_test

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/extensions"
)

// TestExternalPubExtension_MarshalUnmarshal tests serialization and deserialization.
func TestExternalPubExtension_MarshalUnmarshal(t *testing.T) {
	// Create extension with P-256 public key (65 bytes)
	publicKey := make([]byte, 65)
	publicKey[0] = 0x04 // Uncompressed format
	for i := 1; i < 65; i++ {
		publicKey[i] = byte(i % 256)
	}

	ext := extensions.NewExternalPubExtension(publicKey)

	// Marshal
	data := ext.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal returned empty data")
	}

	// Unmarshal
	ext2, err := extensions.UnmarshalExternalPubExtension(data)
	if err != nil {
		t.Fatalf("UnmarshalExternalPubExtension failed: %v", err)
	}

	// Verify equality
	if !ext.Equal(ext2) {
		t.Error("Unmarshaled extension not equal to original")
	}
}

// TestExternalPubExtension_Validate tests validation.
func TestExternalPubExtension_Validate(t *testing.T) {
	tests := []struct {
		name    string
		pubKey  []byte
		wantErr bool
	}{
		{"valid P-256", func() []byte {
			k := make([]byte, 65)
			k[0] = 0x04
			return k
		}(), false},
		{"valid X25519", make([]byte, 32), false},
		{"nil", nil, true},
		{"empty", []byte{}, true},
		{"invalid P-256 format", func() []byte {
			k := make([]byte, 65)
			k[0] = 0x02 // Wrong prefix
			return k
		}(), true}, // Should fail validation
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := extensions.NewExternalPubExtension(tt.pubKey)
			err := ext.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestExternalPubExtension_Equal tests comparison.
func TestExternalPubExtension_Equal(t *testing.T) {
	key1 := []byte{0x04, 0x01, 0x02, 0x03}
	key2 := []byte{0x04, 0x01, 0x02, 0x03}
	key3 := []byte{0x04, 0x04, 0x05, 0x06}

	ext1 := extensions.NewExternalPubExtension(key1)
	ext2 := extensions.NewExternalPubExtension(key2)
	ext3 := extensions.NewExternalPubExtension(key3)

	if !ext1.Equal(ext2) {
		t.Error("Equal extensions not equal")
	}
	if ext1.Equal(ext3) {
		t.Error("Different extensions equal")
	}
	if ext1.Equal(nil) {
		t.Error("Extension equal to nil")
	}
}

// TestExternalPubExtension_ToExtension tests conversion to generic Extension.
func TestExternalPubExtension_ToExtension(t *testing.T) {
	publicKey := []byte{0x04, 0x01, 0x02, 0x03}
	ext := extensions.NewExternalPubExtension(publicKey)

	genericExt, err := ext.ToExtension()
	if err != nil {
		t.Fatalf("ToExtension failed: %v", err)
	}

	if genericExt.Type != extensions.ExtensionTypeExternalPub {
		t.Errorf("Wrong extension type: got %d, want %d", genericExt.Type, extensions.ExtensionTypeExternalPub)
	}

	// Verify data matches
	exts := extensions.NewExtensions()
	if err := exts.Add(*genericExt); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	if exts.Len() != 1 {
		t.Errorf("Len() = %d, want 1", exts.Len())
	}
}

// TestExternalPubExtension_FromExtension tests creation from generic Extension.
func TestExternalPubExtension_FromExtension(t *testing.T) {
	publicKey := []byte{0x04, 0x01, 0x02, 0x03}
	ext := extensions.NewExternalPubExtension(publicKey)
	genericExt, _ := ext.ToExtension()

	// Valid conversion
	result, err := extensions.FromExternalPubExtension(genericExt)
	if err != nil {
		t.Fatalf("FromExternalPubExtension failed: %v", err)
	}

	if !ext.Equal(result) {
		t.Error("Converted extension not equal to original")
	}

	// Invalid type
	wrongExt := &extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")}
	_, err = extensions.FromExternalPubExtension(wrongExt)
	if err == nil {
		t.Error("FromExternalPubExtension should fail for wrong type")
	}
}

// TestExternalPubExtension_String tests string representation.
func TestExternalPubExtension_String(t *testing.T) {
	// Normal key
	ext1 := extensions.NewExternalPubExtension([]byte{0x04, 0x01, 0x02, 0x03})
	if ext1.String() != "ExternalPub(040102...)" {
		t.Errorf("String() = %q, want %q", ext1.String(), "ExternalPub(040102...)")
	}

	// Short key
	ext2 := extensions.NewExternalPubExtension([]byte{0x01, 0x02})
	if ext2.String() != "ExternalPub(0102)" {
		t.Errorf("String() = %q, want %q", ext2.String(), "ExternalPub(0102)")
	}

	// Nil extension
	var ext3 *extensions.ExternalPubExtension
	if ext3.String() != "ExternalPub(nil)" {
		t.Errorf("Nil extension String() = %q, want %q", ext3.String(), "ExternalPub(nil)")
	}
}

// TestExternalPubExtension_Len tests length calculation.
func TestExternalPubExtension_Len(t *testing.T) {
	// P-256 key (65 bytes)
	ext1 := extensions.NewExternalPubExtension(make([]byte, 65))
	if ext1.Len() != 65 {
		t.Errorf("P-256 Len() = %d, want 65", ext1.Len())
	}

	// X25519 key (32 bytes)
	ext2 := extensions.NewExternalPubExtension(make([]byte, 32))
	if ext2.Len() != 32 {
		t.Errorf("X25519 Len() = %d, want 32", ext2.Len())
	}

	// Nil extension
	var nilExt *extensions.ExternalPubExtension
	if nilExt.Len() != 0 {
		t.Errorf("Nil extension Len() = %d, want 0", nilExt.Len())
	}
}

// TestExternalPubExtension_IsP256 tests P-256 detection.
func TestExternalPubExtension_IsP256(t *testing.T) {
	// Valid P-256
	key1 := make([]byte, 65)
	key1[0] = 0x04
	ext1 := extensions.NewExternalPubExtension(key1)
	if !ext1.IsP256() {
		t.Error("Valid P-256 key not detected")
	}

	// Invalid P-256 (wrong prefix)
	key2 := make([]byte, 65)
	key2[0] = 0x02
	ext2 := extensions.NewExternalPubExtension(key2)
	if ext2.IsP256() {
		t.Error("Invalid P-256 key detected as P-256")
	}

	// X25519 key
	ext3 := extensions.NewExternalPubExtension(make([]byte, 32))
	if ext3.IsP256() {
		t.Error("X25519 key detected as P-256")
	}
}

// TestExternalPubExtension_IsX25519 tests X25519 detection.
func TestExternalPubExtension_IsX25519(t *testing.T) {
	// Valid X25519
	ext1 := extensions.NewExternalPubExtension(make([]byte, 32))
	if !ext1.IsX25519() {
		t.Error("Valid X25519 key not detected")
	}

	// P-256 key
	key2 := make([]byte, 65)
	key2[0] = 0x04
	ext2 := extensions.NewExternalPubExtension(key2)
	if ext2.IsX25519() {
		t.Error("P-256 key detected as X25519")
	}
}

// TestExternalPubExtension_DeterministicMarshal tests that marshaling is deterministic.
func TestExternalPubExtension_DeterministicMarshal(t *testing.T) {
	publicKey := []byte{0x04, 0x01, 0x02, 0x03, 0x05}
	ext := extensions.NewExternalPubExtension(publicKey)

	data1 := ext.Marshal()
	data2 := ext.Marshal()
	data3 := ext.Marshal()

	if !bytes.Equal(data1, data2) || !bytes.Equal(data2, data3) {
		t.Error("Marshal is not deterministic")
	}
}

// TestExternalPubExtension_Empty tests empty extension.
func TestExternalPubExtension_Empty(t *testing.T) {
	ext := extensions.NewExternalPubExtension([]byte{})

	// Validate should fail for empty
	if err := ext.Validate(); err == nil {
		t.Error("Empty extension should fail validation")
	}
}
