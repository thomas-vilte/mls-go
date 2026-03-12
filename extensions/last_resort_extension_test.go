package extensions_test

import (
	"testing"

	"github.com/mls-go/extensions"
)

// TestLastResortExtension_Create prueba creación.
func TestLastResortExtension_Create(t *testing.T) {
	ext := extensions.NewLastResortExtension()
	if ext == nil {
		t.Fatal("NewLastResortExtension returned nil")
	}
}

// TestLastResortExtension_MarshalUnmarshal prueba serialización.
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

	// Verificar igualdad
	if !ext.Equal(ext2) {
		t.Error("Unmarshaled extension not equal to original")
	}
}

// TestLastResortExtension_Validate prueba validación.
func TestLastResortExtension_Validate(t *testing.T) {
	ext := extensions.NewLastResortExtension()
	err := ext.Validate()
	if err != nil {
		t.Errorf("Validate() failed: %v", err)
	}
}

// TestLastResortExtension_Equal prueba comparación.
func TestLastResortExtension_Equal(t *testing.T) {
	ext1 := extensions.NewLastResortExtension()
	ext2 := extensions.NewLastResortExtension()
	ext3 := extensions.NewLastResortExtension()

	if !ext1.Equal(ext2) {
		t.Error("All LastResortExtension should be equal")
	}
	if !ext2.Equal(ext3) {
		t.Error("All LastResortExtension should be equal")
	}
	if !ext1.Equal(ext3) {
		t.Error("All LastResortExtension should be equal")
	}
}

// TestLastResortExtension_ToExtension prueba conversión.
func TestLastResortExtension_ToExtension(t *testing.T) {
	ext := extensions.NewLastResortExtension()

	genericExt, err := ext.ToExtension()
	if err != nil {
		t.Fatalf("ToExtension failed: %v", err)
	}

	if genericExt.Type != extensions.ExtensionTypeLastResort {
		t.Errorf("Wrong extension type: got %d, want %d", genericExt.Type, extensions.ExtensionTypeLastResort)
	}

	// Convertir de vuelta
	ext2, err := extensions.FromLastResortExtension(genericExt)
	if err != nil {
		t.Fatalf("FromLastResortExtension failed: %v", err)
	}

	if !ext.Equal(ext2) {
		t.Error("Round-trip conversion not equal")
	}
}

// TestLastResortExtension_String prueba representación string.
func TestLastResortExtension_String(t *testing.T) {
	ext := extensions.NewLastResortExtension()
	str := ext.String()
	if str != "LastResortExtension" {
		t.Errorf("String() = %s, want LastResortExtension", str)
	}
}

// TestLastResortExtension_IsLastResort prueba verificación.
func TestLastResortExtension_IsLastResort(t *testing.T) {
	ext := extensions.NewLastResortExtension()
	genericExt, _ := ext.ToExtension()

	if !extensions.IsLastResort(genericExt) {
		t.Error("IsLastResort() returned false for LastResort extension")
	}

	// Probar con otra extensión
	appIdExt := extensions.NewApplicationIdExtension([]byte("test"))
	appIdGeneric, _ := appIdExt.ToExtension()

	if extensions.IsLastResort(appIdGeneric) {
		t.Error("IsLastResort() returned true for non-LastResort extension")
	}
}

// TestLastResortExtension_FromExtension_WrongType prueba error de tipo.
func TestLastResortExtension_FromExtension_WrongType(t *testing.T) {
	appIdExt := extensions.NewApplicationIdExtension([]byte("test"))
	genericExt, _ := appIdExt.ToExtension()

	_, err := extensions.FromLastResortExtension(genericExt)
	if err == nil {
		t.Error("FromLastResortExtension should fail for wrong type")
	}
}

// TestLastResortExtension_EmptyMarshal prueba marshal vacío.
func TestLastResortExtension_EmptyMarshal(t *testing.T) {
	ext := extensions.NewLastResortExtension()
	data := ext.Marshal()

	// Debería ser vector de longitud 0
	if len(data) == 0 {
		t.Error("Marshal should return data even if empty")
	}
}

// TestLastResortExtension_UnmarshalNil prueba unmarshal con nil.
func TestLastResortExtension_UnmarshalNil(t *testing.T) {
	ext, err := extensions.UnmarshalLastResortExtension(nil)
	if err != nil {
		t.Fatalf("UnmarshalLastResortExtension(nil) failed: %v", err)
	}
	if ext == nil {
		t.Error("UnmarshalLastResortExtension(nil) returned nil")
	}
}

// TestLastResortExtension_UnmarshalEmpty prueba unmarshal con datos vacíos.
func TestLastResortExtension_UnmarshalEmpty(t *testing.T) {
	ext, err := extensions.UnmarshalLastResortExtension([]byte{})
	if err != nil {
		t.Fatalf("UnmarshalLastResortExtension([]byte{}) failed: %v", err)
	}
	if ext == nil {
		t.Error("UnmarshalLastResortExtension([]byte{}) returned nil")
	}
}

// TestLastResortExtension_ValidateAlwaysValid prueba que siempre es válida.
func TestLastResortExtension_ValidateAlwaysValid(t *testing.T) {
	ext := extensions.NewLastResortExtension()

	// Validar múltiples veces
	for i := 0; i < 10; i++ {
		if err := ext.Validate(); err != nil {
			t.Errorf("Validate() iteration %d failed: %v", i, err)
		}
	}
}

// TestLastResortExtension_ConsistentMarshal prueba consistencia de marshal.
func TestLastResortExtension_ConsistentMarshal(t *testing.T) {
	ext := extensions.NewLastResortExtension()

	data1 := ext.Marshal()
	data2 := ext.Marshal()
	data3 := ext.Marshal()

	if string(data1) != string(data2) || string(data2) != string(data3) {
		t.Error("Marshal is not consistent")
	}
}

// TestLastResortExtension_AddToExtensions prueba agregar a colección.
func TestLastResortExtension_AddToExtensions(t *testing.T) {
	exts := extensions.NewExtensions()

	lastResort := extensions.NewLastResortExtension()
	lastResortExt, _ := lastResort.ToExtension()

	err := exts.Add(*lastResortExt)
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	if !exts.Has(extensions.ExtensionTypeLastResort) {
		t.Error("Extension not added to collection")
	}

	if exts.Len() != 1 {
		t.Errorf("Len() = %d, want 1", exts.Len())
	}
}
