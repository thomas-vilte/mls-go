package extensions_test

import (
	"testing"

	"github.com/mls-go/extensions"
)

// TestRatchetTreeExtension_Validate prueba validación.
func TestRatchetTreeExtension_Validate(t *testing.T) {
	// Nil tree es válido
	ext := &extensions.RatchetTreeExtension{Tree: nil}
	err := ext.Validate()
	if err != nil {
		t.Errorf("Validate() with nil tree failed: %v", err)
	}

	// TODO: Agregar tests con árbol real cuando treesync esté completo
}

// TestRatchetTreeExtension_GetTree prueba obtención de árbol.
func TestRatchetTreeExtension_GetTree(t *testing.T) {
	ext := &extensions.RatchetTreeExtension{}
	tree := ext.GetTree()
	if tree != nil {
		t.Error("GetTree() should return nil for empty extension")
	}
}

// TestRatchetTreeExtension_SetTree prueba seteo de árbol.
func TestRatchetTreeExtension_SetTree(t *testing.T) {
	ext := &extensions.RatchetTreeExtension{}
	ext.SetTree(nil)
	if ext.GetTree() != nil {
		t.Error("SetTree(nil) should set tree to nil")
	}
}

// TestRatchetTreeExtension_ToExtension prueba conversión.
func TestRatchetTreeExtension_ToExtension(t *testing.T) {
	ext := &extensions.RatchetTreeExtension{}
	genericExt, err := ext.ToExtension()
	if err != nil {
		t.Fatalf("ToExtension failed: %v", err)
	}

	if genericExt.Type != extensions.ExtensionTypeRatchetTree {
		t.Errorf("Wrong extension type: got %d", genericExt.Type)
	}
}

// TestRatchetTreeExtension_FromExtension prueba conversión desde genérica.
func TestRatchetTreeExtension_FromExtension(t *testing.T) {
	genericExt := &extensions.Extension{
		Type: extensions.ExtensionTypeRatchetTree,
		Data: []byte{},
	}

	ext, err := extensions.FromExtension(genericExt)
	if err != nil {
		t.Fatalf("FromExtension failed: %v", err)
	}

	if ext == nil {
		t.Error("FromExtension returned nil")
	}
}

// TestRatchetTreeExtension_ExtensionType prueba tipo.
func TestRatchetTreeExtension_ExtensionType(t *testing.T) {
	ext := &extensions.RatchetTreeExtension{}
	if ext.ExtensionType() != extensions.ExtensionTypeRatchetTree {
		t.Errorf("Wrong extension type: got %d", ext.ExtensionType())
	}
}

// TestRatchetTreeExtension_Equal prueba comparación.
func TestRatchetTreeExtension_Equal(t *testing.T) {
	ext1 := &extensions.RatchetTreeExtension{Tree: nil}
	ext2 := &extensions.RatchetTreeExtension{Tree: nil}

	if !ext1.Equal(ext2) {
		t.Error("Equal nil trees should be equal")
	}

	if !ext1.Equal(ext1) {
		t.Error("Extension should be equal to itself")
	}
}

// TestRatchetTreeExtension_MarshalEmpty prueba marshal de extensión vacía.
func TestRatchetTreeExtension_MarshalEmpty(t *testing.T) {
	ext := &extensions.RatchetTreeExtension{Tree: nil}
	data := ext.Marshal()
	if len(data) != 0 {
		t.Errorf("Marshal of nil tree should return empty, got %d bytes", len(data))
	}
}

// TestUnmarshalRatchetTreeExtension_Empty prueba unmarshal de datos vacíos.
func TestUnmarshalRatchetTreeExtension_Empty(t *testing.T) {
	ext, err := extensions.UnmarshalRatchetTreeExtension([]byte{})
	if err != nil {
		t.Fatalf("UnmarshalRatchetTreeExtension failed: %v", err)
	}

	if ext == nil {
		t.Error("UnmarshalRatchetTreeExtension returned nil")
	}

	if ext.GetTree() != nil {
		t.Error("Empty data should result in nil tree")
	}
}
