package extensions_test

import (
	"testing"

	"github.com/openmls/go/extensions"
)

// TestExtensions_Integration prueba integración entre extensiones.
func TestExtensions_Integration(t *testing.T) {
	// Crear colección con múltiples extensiones
	exts := extensions.NewExtensions()

	// Agregar ApplicationId
	appId := extensions.NewApplicationIdExtension([]byte("test-app"))
	appIdExt, _ := appId.ToExtension()
	exts.Add(*appIdExt)

	// Agregar ExternalPub
	pubKey := []byte{0x04, 0x01, 0x02, 0x03}
	extPub := extensions.NewExternalPubExtension(pubKey)
	extPubExt, _ := extPub.ToExtension()
	exts.Add(*extPubExt)

	// Verificar que ambas están
	if exts.Len() != 2 {
		t.Errorf("Len() = %d, want 2", exts.Len())
	}

	if !exts.Has(extensions.ExtensionTypeApplicationID) {
		t.Error("Missing ApplicationId extension")
	}

	if !exts.Has(extensions.ExtensionTypeExternalPub) {
		t.Error("Missing ExternalPub extension")
	}
}

// TestExtensions_Remove prueba eliminación.
func TestExtensions_Remove(t *testing.T) {
	exts := extensions.NewExtensions()

	exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")})
	exts.Add(extensions.Extension{Type: extensions.ExtensionTypeExternalPub, Data: []byte{0x04}})

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

// TestExtensions_Get prueba obtención.
func TestExtensions_Get(t *testing.T) {
	exts := extensions.NewExtensions()
	expected := extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")}
	exts.Add(expected)

	ext, ok := exts.Get(extensions.ExtensionTypeApplicationID)
	if !ok {
		t.Fatal("Get returned false")
	}

	if ext.Type != expected.Type {
		t.Errorf("Type mismatch: got %d, want %d", ext.Type, expected.Type)
	}
}

// TestExtensions_All prueba obtención de todas.
func TestExtensions_All(t *testing.T) {
	exts := extensions.NewExtensions()
	exts.Add(extensions.Extension{Type: extensions.ExtensionTypeExternalPub, Data: []byte{0x04}})
	exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")})

	all := exts.All()
	if len(all) != 2 {
		t.Errorf("All() returned %d extensions, want 2", len(all))
	}

	// Verificar orden ascendente
	if all[0].Type != extensions.ExtensionTypeApplicationID {
		t.Error("Extensions not in ascending order")
	}
}

// TestExtensions_Clone prueba clonado.
func TestExtensions_Clone(t *testing.T) {
	exts := extensions.NewExtensions()
	exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")})

	cloned := exts.Clone()

	if cloned.Len() != exts.Len() {
		t.Errorf("Clone Len mismatch: got %d, want %d", cloned.Len(), exts.Len())
	}

	// Modificar original no debería afectar clone
	exts.Remove(extensions.ExtensionTypeApplicationID)
	if cloned.Len() != 1 {
		t.Error("Clone affected by original modification")
	}
}

// TestExtensions_MultipleAdds prueba múltiples agregados.
func TestExtensions_MultipleAdds(t *testing.T) {
	exts := extensions.NewExtensions()

	// Agregar misma extensión múltiples veces
	exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test1")})
	exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test2")})

	// Debería reemplazar, no duplicar
	if exts.Len() != 1 {
		t.Errorf("Len() = %d, want 1 (should replace)", exts.Len())
	}

	ext, _ := exts.Get(extensions.ExtensionTypeApplicationID)
	if string(ext.Data) != "test2" {
		t.Errorf("Data = %s, want test2 (should be replaced)", ext.Data)
	}
}

// TestExtensions_EmptyMarshal prueba marshal de colección vacía.
func TestExtensions_EmptyMarshal(t *testing.T) {
	exts := extensions.NewExtensions()
	data := exts.Marshal()

	// Just verify marshal doesn't panic
	if data == nil {
		t.Error("Marshal returned nil")
	}
}

// TestExtensions_UnmarshalInvalid prueba unmarshal inválido.
func TestExtensions_UnmarshalInvalid(t *testing.T) {
	// Datos truncados
	_, err := extensions.UnmarshalExtensions([]byte{0x05, 0x00})
	if err == nil {
		t.Error("UnmarshalExtensions should fail on truncated data")
	}
}

// TestExtensions_OrderDeterministic prueba que el orden es determinístico.
func TestExtensions_OrderDeterministic(t *testing.T) {
	// Crear extensiones en orden aleatorio
	createExts := func() []byte {
		exts := extensions.NewExtensions()
		exts.Add(extensions.Extension{Type: extensions.ExtensionTypeExternalPub, Data: []byte{0x04}})
		exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")})
		exts.Add(extensions.Extension{Type: extensions.ExtensionTypeRatchetTree, Data: []byte{0x01}})
		return exts.Marshal()
	}

	data1 := createExts()
	data2 := createExts()
	data3 := createExts()

	if string(data1) != string(data2) || string(data2) != string(data3) {
		t.Error("Marshal order is not deterministic")
	}
}

// TestExtensions_GetNonExistent prueba obtención de extensión inexistente.
func TestExtensions_GetNonExistent(t *testing.T) {
	exts := extensions.NewExtensions()
	exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")})

	_, ok := exts.Get(extensions.ExtensionTypeExternalPub)
	if ok {
		t.Error("Get returned true for non-existent extension")
	}
}

// TestExtensions_Has prueba verificación de existencia.
func TestExtensions_Has(t *testing.T) {
	exts := extensions.NewExtensions()
	exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")})

	if !exts.Has(extensions.ExtensionTypeApplicationID) {
		t.Error("Has returned false for existing extension")
	}

	if exts.Has(extensions.ExtensionTypeExternalPub) {
		t.Error("Has returned true for non-existent extension")
	}
}

// TestExtensions_RemoveNonExistent prueba eliminación de extensión inexistente.
func TestExtensions_RemoveNonExistent(t *testing.T) {
	exts := extensions.NewExtensions()
	exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")})

	// Eliminar extensión que no existe no debería hacer nada
	exts.Remove(extensions.ExtensionTypeExternalPub)

	if exts.Len() != 1 {
		t.Errorf("Remove non-existent changed Len: got %d, want 1", exts.Len())
	}
}
