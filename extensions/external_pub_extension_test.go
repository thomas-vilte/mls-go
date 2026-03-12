package extensions_test

import (
	"bytes"
	"testing"

	"github.com/mls-go/extensions"
)

// TestExternalPubExtension_MarshalUnmarshal prueba serialización y deserialización.
func TestExternalPubExtension_MarshalUnmarshal(t *testing.T) {
	// Crear extensión con public key P-256 (65 bytes)
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

	// Verificar igualdad
	if !ext.Equal(ext2) {
		t.Error("Unmarshaled extension not equal to original")
	}
}

// TestExternalPubExtension_Validate prueba validación.
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

// TestExternalPubExtension_Equal prueba comparación.
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

// TestExternalPubExtension_ToExtension prueba conversión a Extension genérica.
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

	// Convertir de vuelta
	ext2, err := extensions.FromExternalPubExtension(genericExt)
	if err != nil {
		t.Fatalf("FromExternalPubExtension failed: %v", err)
	}

	if !ext.Equal(ext2) {
		t.Error("Round-trip conversion not equal")
	}
}

// TestExternalPubExtension_String prueba representación string.
func TestExternalPubExtension_String(t *testing.T) {
	publicKey := []byte{0x04, 0x12, 0x34, 0x56, 0x78}
	ext := extensions.NewExternalPubExtension(publicKey)
	str := ext.String()
	if str == "" {
		t.Error("String() returned empty")
	}

	// Test nil
	var nilExt *extensions.ExternalPubExtension
	if nilExt.String() != "ExternalPub(<nil>)" {
		t.Errorf("Nil extension String = %s, want ExternalPub(<nil>)", nilExt.String())
	}
}

// TestExternalPubExtension_Len prueba longitud.
func TestExternalPubExtension_Len(t *testing.T) {
	publicKey := []byte{0x04, 0x01, 0x02, 0x03}
	ext := extensions.NewExternalPubExtension(publicKey)
	if ext.Len() != 4 {
		t.Errorf("Len() = %d, want 4", ext.Len())
	}

	var nilExt *extensions.ExternalPubExtension
	if nilExt.Len() != 0 {
		t.Error("Nil extension Len not 0")
	}
}

// TestExternalPubExtension_IsP256 prueba detección de P-256.
func TestExternalPubExtension_IsP256(t *testing.T) {
	// P-256 key (65 bytes, starts with 0x04)
	p256Key := make([]byte, 65)
	p256Key[0] = 0x04
	ext := extensions.NewExternalPubExtension(p256Key)

	if !ext.IsP256() {
		t.Error("IsP256() returned false for P-256 key")
	}
	if ext.IsX25519() {
		t.Error("IsX25519() returned true for P-256 key")
	}

	// X25519 key (32 bytes)
	x25519Key := make([]byte, 32)
	ext2 := extensions.NewExternalPubExtension(x25519Key)

	if ext2.IsP256() {
		t.Error("IsP256() returned true for X25519 key")
	}
	if !ext2.IsX25519() {
		t.Error("IsX25519() returned false for X25519 key")
	}
}

// TestExternalPubExtension_PublicKeyBytes prueba obtención de bytes.
func TestExternalPubExtension_PublicKeyBytes(t *testing.T) {
	publicKey := []byte{0x04, 0x01, 0x02, 0x03}
	ext := extensions.NewExternalPubExtension(publicKey)

	retrieved := ext.PublicKeyBytes()
	if !bytes.Equal(retrieved, publicKey) {
		t.Error("PublicKeyBytes() returned different key")
	}

	// Verificar que es una copia
	retrieved[0] = 0xFF
	if ext.PublicKeyBytes()[0] == 0xFF {
		t.Error("PublicKeyBytes() returned reference, not copy")
	}
}

// TestNewExternalPubExtension prueba creación.
func TestNewExternalPubExtension(t *testing.T) {
	publicKey := []byte{0x04, 0x01, 0x02}
	ext := extensions.NewExternalPubExtension(publicKey)

	if !bytes.Equal(ext.ExternalPub, publicKey) {
		t.Error("ExternalPub not set correctly")
	}
}
