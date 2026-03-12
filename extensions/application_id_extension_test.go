package extensions_test

import (
	"bytes"
	"testing"

	"github.com/mls-go/extensions"
)

// TestApplicationIdExtension_MarshalUnmarshal prueba serialización y deserialización.
func TestApplicationIdExtension_MarshalUnmarshal(t *testing.T) {
	// Crear extensión
	ext := extensions.NewApplicationIdExtension([]byte("com.example.chat"))

	// Marshal
	data := ext.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal returned empty data")
	}

	// Unmarshal
	ext2, err := extensions.UnmarshalApplicationIdExtension(data)
	if err != nil {
		t.Fatalf("UnmarshalApplicationIdExtension failed: %v", err)
	}

	// Verificar igualdad
	if !ext.Equal(ext2) {
		t.Error("Unmarshaled extension not equal to original")
	}
}

// TestApplicationIdExtension_Validate prueba validación.
func TestApplicationIdExtension_Validate(t *testing.T) {
	tests := []struct {
		name    string
		appId   []byte
		wantErr bool
	}{
		{"valid", []byte("test-app"), false},
		{"valid empty", []byte(""), true}, // Empty should fail
		{"nil", nil, true},
		{"large", make([]byte, 65536), true}, // Too large
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := extensions.NewApplicationIdExtension(tt.appId)
			err := ext.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestApplicationIdExtension_Equal prueba comparación.
func TestApplicationIdExtension_Equal(t *testing.T) {
	ext1 := extensions.NewApplicationIdExtension([]byte("test"))
	ext2 := extensions.NewApplicationIdExtension([]byte("test"))
	ext3 := extensions.NewApplicationIdExtension([]byte("other"))

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

// TestApplicationIdExtension_ToExtension prueba conversión a Extension genérica.
func TestApplicationIdExtension_ToExtension(t *testing.T) {
	ext := extensions.NewApplicationIdExtension([]byte("test"))

	genericExt, err := ext.ToExtension()
	if err != nil {
		t.Fatalf("ToExtension failed: %v", err)
	}

	if genericExt.Type != extensions.ExtensionTypeApplicationID {
		t.Errorf("Wrong extension type: got %d, want %d", genericExt.Type, extensions.ExtensionTypeApplicationID)
	}

	// Convertir de vuelta
	ext2, err := extensions.FromApplicationIdExtension(genericExt)
	if err != nil {
		t.Fatalf("FromApplicationIdExtension failed: %v", err)
	}

	if !ext.Equal(ext2) {
		t.Error("Round-trip conversion not equal")
	}
}

// TestApplicationIdExtension_String prueba representación string.
func TestApplicationIdExtension_String(t *testing.T) {
	ext := extensions.NewApplicationIdExtension([]byte("com.example.chat"))
	str := ext.String()
	if str != "com.example.chat" {
		t.Errorf("String() = %s, want com.example.chat", str)
	}

	// Test nil
	var nilExt *extensions.ApplicationIdExtension
	if nilExt.String() != "" {
		t.Error("Nil extension String not empty")
	}
}

// TestApplicationIdExtension_FromString prueba creación desde string.
func TestApplicationIdExtension_FromString(t *testing.T) {
	ext := extensions.NewApplicationIdExtensionFromString("com.example.chat")
	if ext.String() != "com.example.chat" {
		t.Errorf("FromString failed: got %s", ext.String())
	}
}

// TestApplicationIdExtension_Len prueba longitud.
func TestApplicationIdExtension_Len(t *testing.T) {
	ext := extensions.NewApplicationIdExtension([]byte("test"))
	if ext.Len() != 4 {
		t.Errorf("Len() = %d, want 4", ext.Len())
	}

	var nilExt *extensions.ApplicationIdExtension
	if nilExt.Len() != 0 {
		t.Error("Nil extension Len not 0")
	}
}

// TestNewApplicationIdExtension prueba creación.
func TestNewApplicationIdExtension(t *testing.T) {
	appId := []byte("test-app-id")
	ext := extensions.NewApplicationIdExtension(appId)

	if !bytes.Equal(ext.ApplicationId, appId) {
		t.Error("ApplicationId not set correctly")
	}
}
