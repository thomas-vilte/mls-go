// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE file.

package extensions_test

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/extensions"
)

// TestLastResortExtension_New tests creation.
func TestLastResortExtension_New(t *testing.T) {
	ext := extensions.NewLastResortExtension()
	if ext == nil {
		t.Fatal("NewLastResortExtension returned nil")
	}
}

// TestLastResortExtension_MarshalUnmarshal tests serialization and deserialization.
func TestLastResortExtension_MarshalUnmarshal(t *testing.T) {
	ext := extensions.NewLastResortExtension()

	// Marshal
	data := ext.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal returned empty data")
	}

	// Unmarshal
	ext2, err := extensions.UnmarshalLastResortExtension(data)
	if err != nil {
		t.Fatalf("UnmarshalLastResortExtension failed: %v", err)
	}

	// Verify equality
	if !ext.Equal(ext2) {
		t.Error("Unmarshaled extension not equal to original")
	}
}

// TestLastResortExtension_Validate tests validation.
func TestLastResortExtension_Validate(t *testing.T) {
	ext := extensions.NewLastResortExtension()
	err := ext.Validate()
	if err != nil {
		t.Errorf("Validate() error = %v, want nil", err)
	}
}

// TestLastResortExtension_Equal tests comparison.
func TestLastResortExtension_Equal(t *testing.T) {
	ext1 := extensions.NewLastResortExtension()
	ext2 := extensions.NewLastResortExtension()

	if !ext1.Equal(ext2) {
		t.Error("All LastResortExtension instances should be equal")
	}
	// Note: Equal(nil) behavior depends on implementation
}

// TestLastResortExtension_ToExtension tests conversion to generic Extension.
func TestLastResortExtension_ToExtension(t *testing.T) {
	ext := extensions.NewLastResortExtension()

	genericExt, err := ext.ToExtension()
	if err != nil {
		t.Fatalf("ToExtension failed: %v", err)
	}

	if genericExt.Type != extensions.ExtensionTypeLastResort {
		t.Errorf("Wrong extension type: got %d, want %d", genericExt.Type, extensions.ExtensionTypeLastResort)
	}

	// Verify data is empty
	if len(genericExt.Data) == 0 {
		t.Error("Extension data should not be empty")
	}

	// Verify can be added to collection
	exts := extensions.NewExtensions()
	if err := exts.Add(*genericExt); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	if exts.Len() != 1 {
		t.Errorf("Len() = %d, want 1", exts.Len())
	}
}

// TestLastResortExtension_FromExtension tests creation from generic Extension.
func TestLastResortExtension_FromExtension(t *testing.T) {
	ext := extensions.NewLastResortExtension()
	genericExt, _ := ext.ToExtension()

	// Valid conversion
	result, err := extensions.FromLastResortExtension(genericExt)
	if err != nil {
		t.Fatalf("FromLastResortExtension failed: %v", err)
	}

	if !ext.Equal(result) {
		t.Error("Converted extension not equal to original")
	}

	// Invalid type
	wrongExt := &extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")}
	_, err = extensions.FromLastResortExtension(wrongExt)
	if err == nil {
		t.Error("FromLastResortExtension should fail for wrong type")
	}
}

// TestLastResortExtension_String tests string representation.
func TestLastResortExtension_String(t *testing.T) {
	ext := extensions.NewLastResortExtension()
	if ext.String() != "LastResortExtension" {
		t.Errorf("String() = %q, want %q", ext.String(), "LastResortExtension")
	}

	// Nil extension
	var nilExt *extensions.LastResortExtension
	if nilExt.String() != "LastResortExtension" {
		t.Errorf("Nil extension String() = %q, want %q", nilExt.String(), "LastResortExtension")
	}
}

// TestLastResortExtension_Len tests length calculation.
func TestLastResortExtension_Len(t *testing.T) {
	ext := extensions.NewLastResortExtension()
	if ext.Len() != 0 {
		t.Errorf("Len() = %d, want 0", ext.Len())
	}
}

// TestLastResortExtension_DeterministicMarshal tests that marshaling is deterministic.
func TestLastResortExtension_DeterministicMarshal(t *testing.T) {
	ext := extensions.NewLastResortExtension()

	data1 := ext.Marshal()
	data2 := ext.Marshal()
	data3 := ext.Marshal()

	if !bytes.Equal(data1, data2) || !bytes.Equal(data2, data3) {
		t.Error("Marshal is not deterministic")
	}
}

// TestLastResortExtension_UnmarshalNil tests unmarshaling nil data.
func TestLastResortExtension_UnmarshalNil(t *testing.T) {
	ext, err := extensions.UnmarshalLastResortExtension(nil)
	if err != nil {
		t.Fatalf("UnmarshalLastResortExtension(nil) error = %v", err)
	}
	if ext == nil {
		t.Error("UnmarshalLastResortExtension(nil) returned nil")
	}
}

// TestLastResortExtension_UnmarshalEmpty tests unmarshaling empty data.
func TestLastResortExtension_UnmarshalEmpty(t *testing.T) {
	ext, err := extensions.UnmarshalLastResortExtension([]byte{})
	if err != nil {
		t.Fatalf("UnmarshalLastResortExtension([]byte{}) error = %v", err)
	}
	if ext == nil {
		t.Error("UnmarshalLastResortExtension([]byte{}) returned nil")
	}
}

// TestLastResortExtension_ValidateAlwaysValid tests that validation always succeeds.
func TestLastResortExtension_ValidateAlwaysValid(t *testing.T) {
	ext := extensions.NewLastResortExtension()
	for i := 0; i < 10; i++ {
		if err := ext.Validate(); err != nil {
			t.Errorf("Validate() iteration %d error = %v, want nil", i, err)
		}
	}
}

// TestLastResortExtension_AddToExtensions tests adding to Extensions collection.
func TestLastResortExtension_AddToExtensions(t *testing.T) {
	ext := extensions.NewLastResortExtension()
	genericExt, err := ext.ToExtension()
	if err != nil {
		t.Fatalf("ToExtension failed: %v", err)
	}

	exts := extensions.NewExtensions()
	if err := exts.Add(*genericExt); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	if !exts.Has(extensions.ExtensionTypeLastResort) {
		t.Error("Extension not found in collection")
	}

	retrieved, ok := exts.Get(extensions.ExtensionTypeLastResort)
	if !ok {
		t.Fatal("Get() returned false")
	}

	// Verify type
	if retrieved.Type != extensions.ExtensionTypeLastResort {
		t.Errorf("Wrong type: got %d, want %d", retrieved.Type, extensions.ExtensionTypeLastResort)
	}
}
