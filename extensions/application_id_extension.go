// Package extensions - Application ID Extension (RFC 9420 §11.2.1)
package extensions

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/mls-go/internal/tls"
)

// ApplicationIdExtension permite agregar identificadores específicos de la aplicación
// a un KeyPackage.
//
// # ¿Para qué sirve?
//
// Esta extensión se usa para identificar la aplicación o servicio que está usando
// el cliente MLS. Es útil cuando múltiples aplicaciones comparten la misma infraestructura
// MLS pero necesitan distinguirse entre sí.
//
// # Estructura (RFC 9420 §11.2.1)
//
// ```
// ┌─────────────────────────────────────────┐
// │    ApplicationIdExtension               │
// ├─────────────────────────────────────────┤
// │  application_id: opaque<V>              │  ← Identificador de la app
// └─────────────────────────────────────────┘
// ```
//
// # Ubicación
//
// - **KeyPackage**: Sí ✅
// - **GroupInfo**: No ❌
// - **GroupContext**: No ❌
// - **LeafNode**: Sí ✅
//
// # Ejemplos de Uso
//
// // Crear con ID de aplicación
// ext := NewApplicationIdExtension([]byte("my-app-identifier"))
//
// // Crear desde string
// ext := NewApplicationIdExtensionFromString("com.example.chat")
//
// // Validar
//
//	if err := ext.Validate(); err != nil {
//	    return err  // Extensión inválida
//	}
//
// // Serializar
// data := ext.Marshal()
//
// // Deserializar
// ext2, err := UnmarshalApplicationIdExtension(data)
//
// # Formatos Comunes
//
// - **String UTF-8**: "com.example.chat", "discord-voice"
// - **Bytes arbitrarios**: identificadores binarios específicos
// - **Reverse DNS**: "com.company.app" (recomendado)
//
// # RFC Compliance
//
// RFC 9420 §11.2.1:
// "The ApplicationId extension allows applications to add an explicit,
// application-defined identifier to a KeyPackage."
type ApplicationIdExtension struct {
	ApplicationId []byte // Identificador de la aplicación (opaque<V>)
}

// NewApplicationIdExtension crea una nueva ApplicationIdExtension.
//
// El application_id puede ser cualquier secuencia de bytes hasta 65535 bytes.
// Se recomienda usar un formato legible como reverse DNS ("com.example.app").
//
// # Ejemplo
//
// ext := NewApplicationIdExtension([]byte("com.example.chat"))
func NewApplicationIdExtension(appId []byte) *ApplicationIdExtension {
	return &ApplicationIdExtension{
		ApplicationId: appId,
	}
}

// NewApplicationIdExtensionFromString crea una ApplicationIdExtension desde string.
//
// Útil para identifiers legibles como "com.example.chat" o "discord-voice".
// El string se convierte a UTF-8.
//
// # Ejemplo
//
// ext := NewApplicationIdExtensionFromString("com.example.chat")
func NewApplicationIdExtensionFromString(appId string) *ApplicationIdExtension {
	return NewApplicationIdExtension([]byte(appId))
}

// Marshal serializa la extensión a formato TLS.
//
// # Encoding
//
// ```
// ┌─────────────────────────────────────────┐
// │  application_id_length: varint          │
// ├─────────────────────────────────────────┤
// │  application_id: opaque[]               │
// └─────────────────────────────────────────┘
// ```
//
// # Ejemplo
//
// ext := NewApplicationIdExtension([]byte("test"))
// data := ext.Marshal()
// // data: [0x04, 't', 'e', 's', 't']
func (a *ApplicationIdExtension) Marshal() []byte {
	buf := tls.NewWriter()
	buf.WriteVLBytes(a.ApplicationId)
	return buf.Bytes()
}

// UnmarshalApplicationIdExtension parsea una ApplicationIdExtension desde TLS.
//
// # Decoding
//
// Lee application_id como variable-length bytes.
//
// # Ejemplo
//
// data := []byte{0x04, 't', 'e', 's', 't'}
// ext, err := UnmarshalApplicationIdExtension(data)
//
//	if err != nil {
//	    return err
//	}
//
// // ext.ApplicationId == []byte("test")
func UnmarshalApplicationIdExtension(data []byte) (*ApplicationIdExtension, error) {
	buf := tls.NewReader(data)
	appId, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading application_id: %w", err)
	}
	return &ApplicationIdExtension{
		ApplicationId: appId,
	}, nil
}

// Validate valida la extensión.
//
// # Reglas de Validación
//
// - ✅ ApplicationId no debe ser nil
// - ✅ ApplicationId no debe estar vacío
// - ✅ ApplicationId <= 65535 bytes (límite de varint)
//
// # Ejemplo
//
// ext := NewApplicationIdExtension([]byte("test"))
//
//	if err := ext.Validate(); err != nil {
//	    return err  // Extensión inválida
//	}
func (a *ApplicationIdExtension) Validate() error {
	if a.ApplicationId == nil {
		return errors.New("application_id cannot be nil")
	}
	if len(a.ApplicationId) == 0 {
		return errors.New("application_id cannot be empty")
	}
	if len(a.ApplicationId) > 65535 {
		return fmt.Errorf("application_id too long: %d bytes (max 65535)", len(a.ApplicationId))
	}
	return nil
}

// Equal compara dos ApplicationIdExtension para igualdad.
//
// Compara los ApplicationId bytes usando comparación constante.
//
// # Ejemplo
//
// ext1 := NewApplicationIdExtension([]byte("test"))
// ext2 := NewApplicationIdExtension([]byte("test"))
// ext3 := NewApplicationIdExtension([]byte("other"))
//
// ext1.Equal(ext2)  // true
// ext1.Equal(ext3)  // false
func (a *ApplicationIdExtension) Equal(other *ApplicationIdExtension) bool {
	if a == nil || other == nil {
		return a == other
	}
	return bytes.Equal(a.ApplicationId, other.ApplicationId)
}

// ToExtension convierte a Extension genérica.
//
// Útil para agregar a una colección Extensions.
//
// # Ejemplo
//
// ext := NewApplicationIdExtension([]byte("test"))
// genericExt, err := ext.ToExtension()
//
//	if err != nil {
//	    return err
//	}
//
// exts := NewExtensions()
// exts.Add(*genericExt)
func (a *ApplicationIdExtension) ToExtension() (*Extension, error) {
	data := a.Marshal()
	return &Extension{
		Type: ExtensionTypeApplicationID,
		Data: data,
	}, nil
}

// FromExtension crea desde Extension genérica.
//
// Devuelve error si el Type no es ExtensionTypeApplicationID.
//
// # Ejemplo
//
// genericExt := &Extension{Type: ExtensionTypeApplicationID, Data: []byte{0x04, 't', 'e', 's', 't'}}
// ext, err := FromApplicationIdExtension(genericExt)
//
//	if err != nil {
//	    return err
//	}
//
// // ext.ApplicationId == []byte("test")
func FromApplicationIdExtension(ext *Extension) (*ApplicationIdExtension, error) {
	if ext.Type != ExtensionTypeApplicationID {
		return nil, fmt.Errorf("wrong extension type: %d", ext.Type)
	}
	return UnmarshalApplicationIdExtension(ext.Data)
}

// String devuelve el ApplicationId como string legible.
//
// Intenta decodificar como UTF-8. Si no es válido UTF-8,
// devuelve representación hexadecimal.
//
// # Ejemplo
//
// ext := NewApplicationIdExtension([]byte("com.example.chat"))
// fmt.Println(ext.String())  // "com.example.chat"
func (a *ApplicationIdExtension) String() string {
	if a == nil || a.ApplicationId == nil {
		return ""
	}
	// Try UTF-8 first
	if validUTF8(a.ApplicationId) {
		return string(a.ApplicationId)
	}
	// Fallback to hex
	return hex.EncodeToString(a.ApplicationId)
}

// Len devuelve la longitud del ApplicationId en bytes.
//
// # Ejemplo
//
// ext := NewApplicationIdExtension([]byte("test"))
// // ext.Len() == 4
func (a *ApplicationIdExtension) Len() int {
	if a == nil {
		return 0
	}
	return len(a.ApplicationId)
}

// Helper function to check valid UTF-8
func validUTF8(b []byte) bool {
	for i := 0; i < len(b); {
		c := b[i]
		if c < 0x80 {
			// ASCII
			i++
			continue
		}
		// Multi-byte UTF-8
		n := utf8Len(c)
		if n == 0 || i+n > len(b) {
			return false
		}
		for j := 1; j < n; j++ {
			if b[i+j]&0xC0 != 0x80 {
				return false
			}
		}
		i += n
	}
	return true
}

func utf8Len(c byte) int {
	if c&0xE0 == 0xC0 {
		return 2
	}
	if c&0xF0 == 0xE0 {
		return 3
	}
	if c&0xF8 == 0xF0 {
		return 4
	}
	return 0
}
