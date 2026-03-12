package extensions_test

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/extensions"
)

// TestExtensions_Integration tests extension integration.
func TestExtensions_Integration(t *testing.T) {
	// Create collection with multiple extensions
	exts := extensions.NewExtensions()

	// Add ApplicationID
	appID := extensions.NewApplicationIDExtension([]byte("test-app"))
	appIDExt, err := appID.ToExtension()
	if err != nil {
		t.Fatalf("ToExtension() error = %v", err)
	}
	if err := exts.Add(*appIDExt); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	// Add ExternalPub
	pubKey := []byte{0x04, 0x01, 0x02, 0x03}
	extPub := extensions.NewExternalPubExtension(pubKey)
	extPubExt, err := extPub.ToExtension()
	if err != nil {
		t.Fatalf("ToExtension() error = %v", err)
	}
	if err := exts.Add(*extPubExt); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	// Verify both are present
	if exts.Len() != 2 {
		t.Errorf("Len() = %d, want 2", exts.Len())
	}

	if !exts.Has(extensions.ExtensionTypeApplicationID) {
		t.Error("Missing ApplicationID extension")
	}

	if !exts.Has(extensions.ExtensionTypeExternalPub) {
		t.Error("Missing ExternalPub extension")
	}
}

// TestExtensions_Remove tests removal.
func TestExtensions_Remove(t *testing.T) {
	exts := extensions.NewExtensions()

	if err := exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if err := exts.Add(extensions.Extension{Type: extensions.ExtensionTypeExternalPub, Data: []byte{0x04}}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	if exts.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", exts.Len())
	}

	exts.Remove(extensions.ExtensionTypeApplicationID)

	if exts.Len() != 1 {
		t.Errorf("After remove, Len() = %d, want 1", exts.Len())
	}

	if exts.Has(extensions.ExtensionTypeApplicationID) {
		t.Error("Removed extension still exists")
	}
}

// TestExtensions_Get tests retrieval.
func TestExtensions_Get(t *testing.T) {
	exts := extensions.NewExtensions()
	expected := extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")}
	if err := exts.Add(expected); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	ext, ok := exts.Get(extensions.ExtensionTypeApplicationID)
	if !ok {
		t.Fatal("Get returned false")
	}

	if ext.Type != expected.Type {
		t.Errorf("Type mismatch: got %d, want %d", ext.Type, expected.Type)
	}
}

// TestExtensions_All tests getting all extensions.
func TestExtensions_All(t *testing.T) {
	exts := extensions.NewExtensions()
	if err := exts.Add(extensions.Extension{Type: extensions.ExtensionTypeExternalPub, Data: []byte{0x04}}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if err := exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	all := exts.All()
	if len(all) != 2 {
		t.Errorf("All() returned %d extensions, want 2", len(all))
	}

	// Verify ascending order
	if all[0].Type != extensions.ExtensionTypeApplicationID {
		t.Error("Extensions not in ascending order")
	}
}

// TestExtensions_Clone tests cloning.
func TestExtensions_Clone(t *testing.T) {
	exts := extensions.NewExtensions()
	if err := exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	cloned := exts.Clone()

	if cloned.Len() != exts.Len() {
		t.Errorf("Clone Len mismatch: got %d, want %d", cloned.Len(), exts.Len())
	}

	// Modifying original should not affect clone
	exts.Remove(extensions.ExtensionTypeApplicationID)
	if cloned.Len() != 1 {
		t.Error("Clone affected by original modification")
	}
}

// TestExtensions_MultipleAdds tests multiple adds.
func TestExtensions_MultipleAdds(t *testing.T) {
	exts := extensions.NewExtensions()

	// Add same extension multiple times
	if err := exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test1")}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if err := exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test2")}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	// Should replace, not duplicate
	if exts.Len() != 1 {
		t.Errorf("Len() = %d, want 1 (should replace)", exts.Len())
	}

	ext, ok := exts.Get(extensions.ExtensionTypeApplicationID)
	if !ok {
		t.Fatal("Get() returned false")
	}
	if string(ext.Data) != "test2" {
		t.Errorf("Data = %s, want test2 (should be replaced)", ext.Data)
	}
}

// TestExtensions_EmptyMarshal tests marshaling empty collection.
func TestExtensions_EmptyMarshal(t *testing.T) {
	exts := extensions.NewExtensions()
	data := exts.Marshal()

	// Just verify marshal doesn't panic
	if data == nil {
		t.Error("Marshal returned nil")
	}
}

// TestExtensions_UnmarshalInvalid tests invalid unmarshal.
func TestExtensions_UnmarshalInvalid(t *testing.T) {
	// Truncated data
	_, err := extensions.UnmarshalExtensions([]byte{0x05, 0x00})
	if err == nil {
		t.Error("UnmarshalExtensions should fail on truncated data")
	}
}

// TestExtensions_OrderDeterministic tests that order is deterministic.
func TestExtensions_OrderDeterministic(t *testing.T) {
	// Create extensions in random order
	createExts := func() []byte {
		exts := extensions.NewExtensions()
		_ = exts.Add(extensions.Extension{Type: extensions.ExtensionTypeExternalPub, Data: []byte{0x04}})
		_ = exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")})
		_ = exts.Add(extensions.Extension{Type: extensions.ExtensionTypeRatchetTree, Data: []byte{0x01}})
		return exts.Marshal()
	}

	data1 := createExts()
	data2 := createExts()
	data3 := createExts()

	if !bytes.Equal(data1, data2) || !bytes.Equal(data2, data3) {
		t.Error("Marshal order is not deterministic")
	}
}

// TestExtensions_GetNonExistent tests getting non-existent extension.
func TestExtensions_GetNonExistent(t *testing.T) {
	exts := extensions.NewExtensions()
	if err := exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	_, ok := exts.Get(extensions.ExtensionTypeExternalPub)
	if ok {
		t.Error("Get returned true for non-existent extension")
	}
}

// TestExtensions_Has tests existence check.
func TestExtensions_Has(t *testing.T) {
	exts := extensions.NewExtensions()
	if err := exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	if !exts.Has(extensions.ExtensionTypeApplicationID) {
		t.Error("Has returned false for existing extension")
	}

	if exts.Has(extensions.ExtensionTypeExternalPub) {
		t.Error("Has returned true for non-existent extension")
	}
}

// TestExtensions_RemoveNonExistent tests removing non-existent extension.
func TestExtensions_RemoveNonExistent(t *testing.T) {
	exts := extensions.NewExtensions()
	if err := exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	// Removing non-existent extension should be no-op
	exts.Remove(extensions.ExtensionTypeExternalPub)

	if exts.Len() != 1 {
		t.Errorf("Remove non-existent changed Len: got %d, want 1", exts.Len())
	}
}
