// Package extensions - Last Resort Extension (RFC 9420 §11.2.5)
package extensions

import (
	"fmt"

	"github.com/mls-go/internal/tls"
)

// LastResortExtension marca un KeyPackage para uso en escenarios "last resort".
//
// # ¿Para qué sirve?
//
// Esta extensión se usa para marcar KeyPackages que deben ser usados
// únicamente cuando no hay otras opciones disponibles. Es útil para:
//
//   - KeyPackages de respaldo
//   - Situaciones de emergencia
//   - Fallback cuando los KeyPackages normales se agotan
//
// # Estructura (RFC 9420 §11.2.5)
//
//	.----------------------------------------------.
//	|          LastResortExtension                 |
//	|----------------------------------------------|
//	|  (sin datos - es solo un marker)             |
//	'----------------------------------------------'
//
// # Ubicación
//
// - **KeyPackage**: Sí ✅
// - **GroupInfo**: No ❌
// - **GroupContext**: No ❌
//
// # ¿Cómo funciona?
//
//	.----------------------------------------------.
//	|              FLUJO DE USO                    |
//	|----------------------------------------------|
//	|  1. Cliente genera KeyPackages normales      |
//	|  2. Cliente genera KeyPackages "last resort" |
//	|  3. Sube ambos al delivery service           |
//	|  4. DS usa normales primero                  |
//	|  5. Si se agotan, usa los "last resort"      |
//	'----------------------------------------------'
//
// # Ejemplo de Uso
//
// // Crear extensión last resort
// ext := extensions.NewLastResortExtension()
//
// // Validar
//
//	if err := ext.Validate(); err != nil {
//	    return err
//	}
//
// // Convertir a extensión genérica
// genericExt, _ := ext.ToExtension()
//
// # RFC Compliance
//
// RFC 9420 §11.2.5:
// "The LastResort extension is used to mark KeyPackages that should
// only be used as a last resort, when no other KeyPackages are available."
type LastResortExtension struct {
	// LastResortExtension no tiene datos - es solo un marker
	// La presencia de la extensión indica que es last resort
}

// NewLastResortExtension crea una nueva LastResortExtension.
//
// # Ejemplo
//
// ext := extensions.NewLastResortExtension()
func NewLastResortExtension() *LastResortExtension {
	return &LastResortExtension{}
}

// Marshal serializa la extensión a formato TLS.
//
// # Encoding
//
// LastResortExtension no tiene datos, por lo que Marshal devuelve
// un vector de longitud 0.
//
//	.----------------------------------------------.
//	|              TLS ENCODING                    |
//	|----------------------------------------------|
//	|  length (varint) : 0x00                      |
//	|  data            : (0 bytes)                 |
//	|  Total           : 1 byte                    |
//	'----------------------------------------------'
//
// # Ejemplo
//
// ext := extensions.NewLastResortExtension()
// data := ext.Marshal()
// // data: []byte{0x00} (varint encoding of 0)
func (l *LastResortExtension) Marshal() []byte {
	buf := tls.NewWriter()
	buf.WriteVLBytes([]byte{}) // Empty data
	return buf.Bytes()
}

// UnmarshalLastResortExtension parsea una LastResortExtension desde TLS.
//
// # Decoding
//
// LastResortExtension no tiene datos, por lo que solo verifica que
// los datos estén presentes (aunque sean vacíos).
//
// # Ejemplo
//
// data := []byte{0x00}
// ext, err := UnmarshalLastResortExtension(data)
//
//	if err != nil {
//	    return err
//	}
func UnmarshalLastResortExtension(data []byte) (*LastResortExtension, error) {
	// LastResortExtension no tiene datos, cualquier input es válido
	// (incluso nil o vacío)
	return &LastResortExtension{}, nil
}

// Validate valida la extensión.
//
// # Reglas de Validación
//
// LastResortExtension siempre es válida - no tiene datos que validar.
//
// # Ejemplo
//
// ext := extensions.NewLastResortExtension()
//
//	if err := ext.Validate(); err != nil {
//	    return err  // Nunca falla
//	}
func (l *LastResortExtension) Validate() error {
	// LastResortExtension siempre es válida
	return nil
}

// Equal compara dos LastResortExtension para igualdad.
//
// Todas las LastResortExtension son iguales (no tienen datos).
//
// # Ejemplo
//
// ext1 := extensions.NewLastResortExtension()
// ext2 := extensions.NewLastResortExtension()
//
// ext1.Equal(ext2)  // true
func (l *LastResortExtension) Equal(other *LastResortExtension) bool {
	// Todas las LastResortExtension son iguales
	return true
}

// ToExtension convierte a Extension genérica.
//
// Útil para agregar a una colección Extensions.
//
// # Ejemplo
//
// ext := extensions.NewLastResortExtension()
// genericExt, err := ext.ToExtension()
//
//	if err != nil {
//	    return err
//	}
//
// exts := extensions.NewExtensions()
// exts.Add(*genericExt)
func (l *LastResortExtension) ToExtension() (*Extension, error) {
	data := l.Marshal()
	return &Extension{
		Type: ExtensionTypeLastResort,
		Data: data,
	}, nil
}

// FromLastResortExtension crea desde Extension genérica.
//
// Devuelve error si el Type no es ExtensionTypeLastResort.
//
// # Ejemplo
//
// genericExt := &Extension{Type: ExtensionTypeLastResort, Data: []byte{0x00}}
// ext, err := FromLastResortExtension(genericExt)
//
//	if err != nil {
//	    return err
//	}
func FromLastResortExtension(ext *Extension) (*LastResortExtension, error) {
	if ext.Type != ExtensionTypeLastResort {
		return nil, fmt.Errorf("wrong extension type: %d", ext.Type)
	}
	return UnmarshalLastResortExtension(ext.Data)
}

// String devuelve una representación string de la extensión.
//
// # Ejemplo
//
// ext := extensions.NewLastResortExtension()
// fmt.Println(ext.String())  // "LastResortExtension"
func (l *LastResortExtension) String() string {
	return "LastResortExtension"
}

// IsLastResort verifica si una extensión genérica es LastResort.
//
// # Ejemplo
//
// genericExt := &Extension{Type: ExtensionTypeLastResort, Data: []byte{0x00}}
//
//	if extensions.IsLastResort(genericExt) {
//	    // Es una extensión last resort
//	}
func IsLastResort(ext *Extension) bool {
	return ext.Type == ExtensionTypeLastResort
}
