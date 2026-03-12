// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE file.

package extensions_test

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/extensions"
)

// TestApplicationIDExtension_MarshalUnmarshal tests serialization and deserialization.
func TestApplicationIDExtension_MarshalUnmarshal(t *testing.T) {
	// Create extension
	ext := extensions.NewApplicationIDExtension([]byte("com.example.chat"))

	// Marshal
	data := ext.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal returned empty data")
	}

	// Unmarshal
	ext2, err := extensions.UnmarshalApplicationIDExtension(data)
	if err != nil {
		t.Fatalf("UnmarshalApplicationIDExtension failed: %v", err)
	}

	// Verify equality
	if !ext.Equal(ext2) {
		t.Error("Unmarshaled extension not equal to original")
	}
}

// TestApplicationIDExtension_Validate tests validation.
func TestApplicationIDExtension_Validate(t *testing.T) {
	tests := []struct {
		name    string
		appID   []byte
		wantErr bool
	}{
		{"valid", []byte("test-app"), false},
		{"valid empty", []byte(""), true}, // Empty should fail
		{"nil", nil, true},
		{"large", make([]byte, 65536), true}, // Too large
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := extensions.NewApplicationIDExtension(tt.appID)
			err := ext.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestApplicationIDExtension_Equal tests comparison.
func TestApplicationIDExtension_Equal(t *testing.T) {
	ext1 := extensions.NewApplicationIDExtension([]byte("test"))
	ext2 := extensions.NewApplicationIDExtension([]byte("test"))
	ext3 := extensions.NewApplicationIDExtension([]byte("other"))

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

// TestApplicationIDExtension_ToExtension tests conversion to generic Extension.
func TestApplicationIDExtension_ToExtension(t *testing.T) {
	ext := extensions.NewApplicationIDExtension([]byte("test"))

	genericExt, err := ext.ToExtension()
	if err != nil {
		t.Fatalf("ToExtension failed: %v", err)
	}

	if genericExt.Type != extensions.ExtensionTypeApplicationID {
		t.Errorf("Wrong extension type: got %d, want %d", genericExt.Type, extensions.ExtensionTypeApplicationID)
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

// TestApplicationIDExtension_FromExtension tests creation from generic Extension.
func TestApplicationIDExtension_FromExtension(t *testing.T) {
	ext := extensions.NewApplicationIDExtension([]byte("test"))
	genericExt, _ := ext.ToExtension()

	// Valid conversion
	result, err := extensions.FromApplicationIDExtension(genericExt)
	if err != nil {
		t.Fatalf("FromApplicationIDExtension failed: %v", err)
	}

	if !ext.Equal(result) {
		t.Error("Converted extension not equal to original")
	}

	// Invalid type
	wrongExt := &extensions.Extension{Type: extensions.ExtensionTypeExternalPub, Data: []byte{0x04}}
	_, err = extensions.FromApplicationIDExtension(wrongExt)
	if err == nil {
		t.Error("FromApplicationIDExtension should fail for wrong type")
	}
}

// TestApplicationIDExtension_String tests string representation.
func TestApplicationIDExtension_String(t *testing.T) {
	// UTF-8 string
	ext1 := extensions.NewApplicationIDExtension([]byte("com.example.chat"))
	if ext1.String() != "com.example.chat" {
		t.Errorf("String() = %q, want %q", ext1.String(), "com.example.chat")
	}

	// Binary data (hex representation)
	ext2 := extensions.NewApplicationIDExtension([]byte{0x01, 0x02, 0x03})
	// String() returns hex for non-UTF8 data
	s := ext2.String()
	if s != "010203" && s != "\x01\x02\x03" {
		t.Errorf("String() = %q, want hex representation", s)
	}

	// Nil extension
	var ext3 *extensions.ApplicationIDExtension
	if ext3.String() != "" {
		t.Errorf("Nil extension String() = %q, want empty", ext3.String())
	}
}

// TestApplicationIDExtension_Len tests length calculation.
func TestApplicationIDExtension_Len(t *testing.T) {
	ext := extensions.NewApplicationIDExtension([]byte("test"))
	if ext.Len() != 4 {
		t.Errorf("Len() = %d, want 4", ext.Len())
	}

	// Nil extension
	var nilExt *extensions.ApplicationIDExtension
	if nilExt.Len() != 0 {
		t.Errorf("Nil extension Len() = %d, want 0", nilExt.Len())
	}
}

// TestApplicationIDExtension_DeterministicMarshal tests that marshaling is deterministic.
func TestApplicationIDExtension_DeterministicMarshal(t *testing.T) {
	ext := extensions.NewApplicationIDExtension([]byte("test-app-id"))

	data1 := ext.Marshal()
	data2 := ext.Marshal()
	data3 := ext.Marshal()

	if !bytes.Equal(data1, data2) || !bytes.Equal(data2, data3) {
		t.Error("Marshal is not deterministic")
	}
}

// TestApplicationIDExtension_Empty tests empty extension.
func TestApplicationIDExtension_Empty(t *testing.T) {
	ext := extensions.NewApplicationIDExtension([]byte(""))

	data := ext.Marshal()
	if len(data) == 0 {
		t.Error("Empty extension marshal returned empty data")
	}

	// Unmarshal should work
	ext2, err := extensions.UnmarshalApplicationIDExtension(data)
	if err != nil {
		t.Fatalf("UnmarshalApplicationIDExtension failed: %v", err)
	}

	if !ext.Equal(ext2) {
		t.Error("Unmarshaled empty extension not equal")
	}
}

// TestApplicationIDExtension_Large tests large extension.
func TestApplicationIDExtension_Large(t *testing.T) {
	// Create large but valid extension (65535 bytes)
	largeData := make([]byte, 65535)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	ext := extensions.NewApplicationIDExtension(largeData)
	if err := ext.Validate(); err != nil {
		t.Fatalf("Validate() failed for max-size extension: %v", err)
	}

	// Marshal and unmarshal
	data := ext.Marshal()
	ext2, err := extensions.UnmarshalApplicationIDExtension(data)
	if err != nil {
		t.Fatalf("UnmarshalApplicationIDExtension failed: %v", err)
	}

	if !ext.Equal(ext2) {
		t.Error("Large extension not equal after round-trip")
	}
}
