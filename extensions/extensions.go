// Package extensions implementa extensiones MLS según RFC 9420 §13.
//
// # ¿Qué son las extensiones?
//
// Las extensiones permiten agregar información opcional a mensajes y objetos MLS.
// Se usan en tres lugares principales:
//
//   - KeyPackages: para describir capacidades del cliente
//   - GroupInfo: para informar parámetros del grupo a nuevos miembros
//   - GroupContext: para asegurar que todos los miembros tengan la misma vista
//
// # Estructura de una Extensión
//
//	.--------------------------------------------------.
//	|           EXTENSION (RFC 9420)                   |
//	|--------------------------------------------------|
//	|  extension_type  : uint16  (identificador)       |
//	|  extension_data  : opaque<V> (datos del tipo)    |
//	'--------------------------------------------------'
//
// # Tipos de Extensiones Soportados
//
// | Type | ID | Ubicación | RFC | Descripción |
// |------|-----|-----------|-----|-------------|
// | ApplicationId | 0x0001 | KeyPackage | §11.2.1 | Datos específicos de la app |
// | RatchetTree | 0x0002 | GroupInfo | §11.2.2 | Árbol de ratchet completo |
// | RequiredCapabilities | 0x0003 | GroupContext | §11.2.3 | Capacidades requeridas |
// | ExternalPub | 0x0004 | GroupInfo | §11.2.4 | Public key para External Commit |
// | ExternalSenders | 0x0005 | GroupContext | §12.1.8.1 | Remitentes externos |
//
// # Ejemplo de Uso
//
// // Crear colección de extensiones
// exts := extensions.NewExtensions()
//
// // Agregar ApplicationId
// appId := extensions.NewApplicationIdExtension([]byte("my-app"))
// exts.Add(appId.ToExtension())
//
// // Agregar RequiredCapabilities
// req := extensions.NewRequiredCapabilities()
// req.AddProtocolVersion(0x01)  // MLS 1.0
// req.AddCipherSuite(0x0002)     // MLS_128_DHKEMP256...
// exts.Add(req.ToExtension())
//
// // Serializar (orden determinístico garantizado)
// data := exts.Marshal()
//
// // Deserializar
// exts2, err := extensions.UnmarshalExtensions(data)
//
// # RFC Compliance
//
// Este package implementa:
//   - RFC 9420 §13: Extensiones
//   - RFC 9420 §11.2: Extensiones en objetos MLS
//   - RFC 9420 §13.4: Orden de serialización
//   - RFC 9420 §13.5: GREASE handling
//
// # Consideraciones de Implementación
//
// **Orden de Serialización:** Las extensiones se serializan en orden ascendente
// por ExtensionType (RFC 9420 §13.4). Esto es CRÍTICO para que el hash del
// GroupContext sea determinístico entre todos los miembros.
//
// **Duplicados:** No se permiten extensiones duplicadas. Si intentás agregar
// una extensión del mismo tipo, se reemplaza la existente.
//
// **GREASE:** Se incluyen constantes GREASE (0x0A0A, 0x1A1A, etc.) para testing
// de extensibilidad. Las implementaciones deben manejar tipos desconocidos.
package extensions

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/openmls/go/internal/tls"
)

// Extension errors
var (
	ErrDuplicateExtension   = errors.New("extensions: duplicate extension type")
	ErrInvalidExtension     = errors.New("extensions: invalid extension")
	ErrExtensionNotFound    = errors.New("extensions: extension not found")
	ErrInvalidExtensionType = errors.New("extensions: invalid extension type")
	ErrEmptyExtensionData   = errors.New("extensions: empty extension data")
)

// ExtensionType identifica el tipo de una extensión MLS.
//
// Los tipos de extensión están registrados en el IANA registry (RFC 9420 §17.3).
//
// # Valores GREASE
//
// Los valores GREASE (0x0A0A, 0x1A1A, etc.) se usan para testing de extensibilidad.
// Aseguran que las implementaciones manejen correctamente tipos desconocidos.
//
//	.----------------------------------------------.
//	|         GREASE VALUES (RFC 9420 §13.5)       |
//	|----------------------------------------------|
//	|  Patrón: 0xXA0A donde X = 0-E                |
//	|                                              |
//	|  GREASE0: 0x0A0A    GREASE1: 0x1A1A         |
//	|  GREASE2: 0x2A2A    GREASE3: 0x3A3A         |
//	|  GREASE4: 0x4A4A    GREASE5: 0x5A5A         |
//	|  GREASE6: 0x6A6A    GREASE7: 0x7A7A         |
//	|  GREASE8: 0x8A8A    GREASE9: 0x9A9A         |
//	|  GREASEA: 0xAAAA    GREASEB: 0xBABA         |
//	|  GREASEC: 0xCACA    GREASED: 0xDADA         |
//	|  GREASEE: 0xEAEA                            |
//	'----------------------------------------------'
//
// Ver RFC 9420 §13.5 para más detalles sobre GREASE.
type ExtensionType uint16

const (
	// ExtensionTypeApplicationID se usa para datos específicos de la aplicación.
	// RFC 9420 §11.2.1
	//
	// Ubicación: KeyPackage
	// Datos: opaque application_id<V>
	ExtensionTypeApplicationID ExtensionType = 0x0001

	// ExtensionTypeRatchetTree contiene el árbol de ratchet completo.
	// RFC 9420 §11.2.2
	//
	// Ubicación: GroupInfo
	// Uso: Ayudar a nuevos miembros a unirse vía External Commit
	ExtensionTypeRatchetTree ExtensionType = 0x0002

	// ExtensionTypeRequiredCapabilities especifica capacidades requeridas por el grupo.
	// RFC 9420 §11.2.3
	//
	// Ubicación: GroupContext
	// Uso: Asegurar que todos los miembros soporten las mismas features
	ExtensionTypeRequiredCapabilities ExtensionType = 0x0003

	// ExtensionTypeExternalPub contiene una public key HPKE externa.
	// RFC 9420 §11.2.4
	//
	// Ubicación: GroupInfo
	// Uso: Permitir External Commit para nuevos miembros
	ExtensionTypeExternalPub ExtensionType = 0x0004

	// ExtensionTypeExternalSenders lista remitentes externos permitidos.
	// RFC 9420 §12.1.8.1
	//
	// Ubicación: GroupContext
	// Uso: DAVE (Discord Audio Voice Encryption) usa esto para delivery service
	ExtensionTypeExternalSenders ExtensionType = 0x0005

	// ExtensionTypeEncryptionKey contiene una encryption key para el grupo.
	// RFC 9420 §11.2.5
	ExtensionTypeEncryptionKey ExtensionType = 0x0006

	// ExtensionTypeConfirmationKey contiene una confirmation key.
	// RFC 9420 §11.2.6
	ExtensionTypeConfirmationKey ExtensionType = 0x0007

	// ExtensionTypeMilestoneCommit marca un milestone en el grupo.
	// RFC 9420 §11.2.7
	ExtensionTypeMilestoneCommit ExtensionType = 0x0008

	// ExtensionTypeGroupContextExtensions contiene extensiones para GroupContext.
	// RFC 9420 §11.2.8
	ExtensionTypeGroupContextExtensions ExtensionType = 0x0009

	// ExtensionTypeLastResort marca un KeyPackage como last resort.
	// RFC 9420 §11.2.5
	//
	// Ubicación: KeyPackage
	// Uso: KeyPackages de respaldo para cuando se agotan los normales
	ExtensionTypeLastResort ExtensionType = 0x000A
)

// Extension representa una extensión MLS genérica.
//
// # Estructura (RFC 9420 §13)
//
// ```
//
//	struct {
//	    ExtensionType extension_type;    // uint16 - identifica el tipo
//	    opaque extension_data<V>;        // variable-length - datos específicos
//	} Extension;
//
// ```
//
// # Ejemplo
//
// // Crear extensión manualmente
//
//	ext := &Extension{
//	    Type: ExtensionTypeApplicationID,
//	    Data: []byte("my-app-id"),
//	}
//
// // Validar
//
//	if err := ext.Validate(); err != nil {
//	    return err
//	}
//
// // Serializar
// data := ext.Marshal()
type Extension struct {
	Type ExtensionType // Tipo de extensión (determina cómo se interpretan los datos)
	Data []byte        // Datos de la extensión (formato específico del tipo)
}

// Marshal serializa una Extension a formato TLS.
//
// # Encoding
//
//	.--------------------------------------------------.
//	|              TLS ENCODING                        |
//	|--------------------------------------------------|
//	|  extension_type        : uint16 (2 bytes)        |
//	|  extension_data_length : varint (1-2 bytes)      |
//	|  extension_data        : opaque (variable)       |
//	'--------------------------------------------------'
//
// # Ejemplo
//
// ext := &Extension{Type: ExtensionTypeApplicationID, Data: []byte("test")}
// data := ext.Marshal()
// // data: [0x00, 0x01, 0x04, 't', 'e', 's', 't']
func (e *Extension) Marshal() []byte {
	buf := tls.NewWriter()
	buf.WriteUint16(uint16(e.Type))
	buf.WriteVLBytes(e.Data)
	return buf.Bytes()
}

// UnmarshalExtension parsea una Extension desde formato TLS.
//
// # Decoding
//
// Lee extension_type (2 bytes) seguido de extension_data (variable-length).
//
// # Ejemplo
//
// data := []byte{0x00, 0x01, 0x04, 't', 'e', 's', 't'}
// ext, err := UnmarshalExtension(data)
//
//	if err != nil {
//	    return err
//	}
//
// // ext.Type == ExtensionTypeApplicationID
// // ext.Data == []byte("test")
func UnmarshalExtension(data []byte) (*Extension, error) {
	buf := tls.NewReader(data)

	extType, err := buf.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("reading extension_type: %w", err)
	}

	extData, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading extension_data: %w", err)
	}

	return &Extension{
		Type: ExtensionType(extType),
		Data: extData,
	}, nil
}

// Extensions es una colección de extensiones MLS.
//
// # Estructura Interna
//
//	.--------------------------------------------------.
//	|           EXTENSIONS STRUCT                      |
//	|--------------------------------------------------|
//	|  extensions : map[Type]Extension                 |
//	|             (lookup rápido O(1))                 |
//	|  ordered    : []Type                             |
//	|             (orden para serialización)           |
//	'--------------------------------------------------'
//
// # ¿Por qué dos estructuras?
//
// - **map**: Permite lookup rápido por tipo (O(1))
// - **ordered slice**: Mantiene orden de inserción para serialización determinística
//
// RFC 9420 §13.4 requiere que las extensiones se serialicen en orden ascendente
// por ExtensionType. Esto es CRÍTICO para que el hash del GroupContext sea
// determinístico entre todos los miembros.
//
// # Ejemplo
//
// // Crear colección
// exts := NewExtensions()
//
// // Agregar extensiones (orden automático)
// exts.Add(Extension{Type: ExtensionTypeExternalSenders, Data: []byte{0x03}})
// exts.Add(Extension{Type: ExtensionTypeApplicationId, Data: []byte{0x01}})
// exts.Add(Extension{Type: ExtensionTypeRatchetTree, Data: []byte{0x02}})
//
// // Marshal siempre produce el mismo orden: ApplicationId, RatchetTree, ExternalSenders
// data := exts.Marshal()
type Extensions struct {
	extensions map[ExtensionType]Extension // Lookup rápido por tipo
	ordered    []ExtensionType             // Orden ascendente para serialización
}

// NewExtensions crea una nueva colección de extensiones vacía.
//
// # Ejemplo
//
// exts := NewExtensions()
// // exts.Len() == 0
func NewExtensions() *Extensions {
	return &Extensions{
		extensions: make(map[ExtensionType]Extension),
		ordered:    make([]ExtensionType, 0),
	}
}

// Add agrega una extensión a la colección.
//
// # Comportamiento
//
// - Si la extensión ya existe: se REEMPLAZA (no se permiten duplicados)
// - Si es nueva: se agrega y se mantiene orden ascendente
//
// # Orden de Serialización
//
// Las extensiones se mantienen en orden ascendente por ExtensionType.
// Esto es requerido por RFC 9420 §13.4 para serialización determinística.
//
//	.----------------------------------------------.
//	|           ORDEN DE INSERCIÓN                 |
//	|----------------------------------------------|
//	|  Antes:   ordered = [0x0001, 0x0003, 0x0005] |
//	|  Add:     Type = 0x0002                      |
//	|  Después: ordered = [0x0001, 0x0002, ...]    |
//	|                   ^                          |
//	|                   insertado en orden         |
//	'----------------------------------------------'
//
// # Ejemplo
//
// exts := NewExtensions()
// exts.Add(Extension{Type: ExtensionTypeExternalSenders, Data: []byte{0x03}})
// exts.Add(Extension{Type: ExtensionTypeApplicationId, Data: []byte{0x01}})
//
// // exts.Len() == 2
// // exts.All() retorna en orden: [ApplicationId, ExternalSenders]
func (e *Extensions) Add(ext Extension) error {
	if err := ext.Validate(); err != nil {
		return fmt.Errorf("invalid extension: %w", err)
	}

	// check if extension already exists
	if _, exists := e.extensions[ext.Type]; !exists {
		// new extension - add to ordered slice
		e.ordered = append(e.ordered, ext.Type)
		// sort to maintain ascending order (required by RFC)
		sort.Slice(e.ordered, func(i, j int) bool {
			return e.ordered[i] < e.ordered[j]
		})
	}

	e.extensions[ext.Type] = ext
	return nil
}

// Get recupera una extensión por tipo.
//
// Devuelve la extensión y true si existe, o Extension vacío y false si no existe.
//
// # Ejemplo
//
// exts := NewExtensions()
// exts.Add(Extension{Type: ExtensionTypeApplicationId, Data: []byte("test")})
//
// ext, ok := exts.Get(ExtensionTypeApplicationId)
//
//	if ok {
//	    // ext.Data == []byte("test")
//	}
func (e *Extensions) Get(typ ExtensionType) (Extension, bool) {
	ext, ok := e.extensions[typ]
	return ext, ok
}

// Has verifica si existe una extensión del tipo dado.
//
// # Ejemplo
//
// exts := NewExtensions()
// exts.Add(Extension{Type: ExtensionTypeApplicationId, Data: []byte("test")})
//
//	if exts.Has(ExtensionTypeApplicationId) {
//	    // La extensión existe
//	}
func (e *Extensions) Has(typ ExtensionType) bool {
	_, ok := e.extensions[typ]
	return ok
}

// Remove elimina una extensión por tipo.
//
// Si la extensión no existe, es no-op (no hace nada).
//
// # Ejemplo
//
// exts := NewExtensions()
// exts.Add(Extension{Type: ExtensionTypeApplicationId, Data: []byte("test")})
//
// exts.Remove(ExtensionTypeApplicationId)
// // exts.Has(ExtensionTypeApplicationId) == false
func (e *Extensions) Remove(typ ExtensionType) {
	if _, exists := e.extensions[typ]; !exists {
		return
	}

	delete(e.extensions, typ)

	// remove form ordered slice
	for i, t := range e.ordered {
		if t == typ {
			e.ordered = append(e.ordered[:i], e.ordered[i+1:]...)
			break
		}
	}
}

// Len devuelve el número de extensiones.
//
// # Ejemplo
//
// exts := NewExtensions()
// exts.Add(Extension{Type: ExtensionTypeApplicationId, Data: []byte("test")})
// // exts.Len() == 1
func (e *Extensions) Len() int {
	return len(e.extensions)
}

// All devuelve todas las extensiones como slice.
//
// IMPORTANTE: Las extensiones se retornan en orden ascendente por ExtensionType,
// no en orden de inserción. Esto es requerido por RFC 9420 §13.4.
//
// # Ejemplo
//
// exts := NewExtensions()
// exts.Add(Extension{Type: ExtensionTypeExternalSenders, Data: []byte{0x03}})
// exts.Add(Extension{Type: ExtensionTypeApplicationId, Data: []byte{0x01}})
//
// all := exts.All()
// // all[0].Type == ExtensionTypeApplicationId (0x0001)
// // all[1].Type == ExtensionTypeExternalSenders (0x0005)
func (e *Extensions) All() []Extension {
	result := make([]Extension, 0, len(e.ordered))
	for _, typ := range e.ordered {
		result = append(result, e.extensions[typ])
	}
	return result
}

// Marshal serializa todas las extensiones a formato TLS.
//
// # Encoding (RFC 9420 §13.4)
//
//	.--------------------------------------------------.
//	|          EXTENSIONS ENCODING (RFC 9420 §13.4)    |
//	|--------------------------------------------------|
//	|  extensions_length       : varint                |
//	|  Extension[]                                     |
//	|   - extension_type       : uint16                |
//	|   - extension_data_length: varint                |
//	|   - extension_data       : opaque<V>             |
//	'--------------------------------------------------'
//
// Las extensiones se serializan en orden ASCENDENTE por ExtensionType.
// Esto es CRÍTICO para que el hash del GroupContext sea determinístico.
//
// # Ejemplo
//
// exts := NewExtensions()
// exts.Add(Extension{Type: ExtensionTypeExternalSenders, Data: []byte{0x03}})
// exts.Add(Extension{Type: ExtensionTypeApplicationId, Data: []byte{0x01}})
//
// data := exts.Marshal()
// // data siempre es: [len, 0x00, 0x01, len, 0x01, 0x00, 0x05, len, 0x03]
// //                   ↑ AppId primero (0x0001 < 0x0005)
func (e *Extensions) Marshal() []byte {
	buf := tls.NewWriter()
	extBuf := tls.NewWriter()
	// Iterate in ordered fashion for deterministic serialization
	for _, typ := range e.ordered {
		ext := e.extensions[typ]
		extBuf.WriteRaw(ext.Marshal())
	}
	buf.WriteVLBytes(extBuf.Bytes())
	return buf.Bytes()
}

// UnmarshalExtensions parsea un vector de Extensiones desde formato TLS.
//
// # Decoding
//
// Lee un vector de extensiones y las agrega a una nueva colección Extensions.
// El orden de las extensiones en el data de entrada se mantiene.
//
// # Ejemplo
//
// data := []byte{...}  // datos serializados
// exts, err := UnmarshalExtensions(data)
//
//	if err != nil {
//	    return err
//	}
//
// // exts.Len() == número de extensiones en data
func UnmarshalExtensions(data []byte) (*Extensions, error) {
	exts := NewExtensions()

	if len(data) == 0 {
		return exts, nil
	}

	buf := tls.NewReader(data)

	for buf.Remaining() > 0 {
		ext, err := UnmarshalExtension(buf.BytesAfterPosition())
		if err != nil {
			return nil, fmt.Errorf("parsing extension: %w", err)
		}

		// Skip the bytes we just read
		buf.Skip(len(ext.Marshal()))

		if err := exts.Add(*ext); err != nil {
			return nil, fmt.Errorf("adding extension: %w", err)
		}
	}

	return exts, nil
}

// Validate valida una Extension.
//
// # Reglas de Validación
//
// - Data no debe ser nil
// - Type debe ser conocido (o GREASE para extensibilidad)
//
// # Ejemplo
//
// ext := &Extension{Type: ExtensionTypeApplicationId, Data: []byte("test")}
//
//	if err := ext.Validate(); err != nil {
//	    return err  // Extensión inválida
//	}
func (e *Extension) Validate() error {
	if e.Data == nil {
		return fmt.Errorf("%w: extension data is nil", ErrInvalidExtension)
	}
	// Check for known extension types
	switch e.Type {
	case ExtensionTypeApplicationID,
		ExtensionTypeRatchetTree,
		ExtensionTypeRequiredCapabilities,
		ExtensionTypeExternalPub,
		ExtensionTypeExternalSenders:
		// Known types are valid
	default:
		// Unknown types are allowed (extensibility) but log warning in debug
	}
	return nil
}

// Equal compara dos extensiones para igualdad.
//
// Compara Type y Data usando comparación constante para Type.
//
// # Ejemplo
//
// ext1 := &Extension{Type: ExtensionTypeApplicationId, Data: []byte("test")}
// ext2 := &Extension{Type: ExtensionTypeApplicationId, Data: []byte("test")}
// ext3 := &Extension{Type: ExtensionTypeApplicationId, Data: []byte("other")}
//
// ext1.Equal(ext2)  // true
// ext1.Equal(ext3)  // false (Data diferente)
func (e *Extension) Equal(other *Extension) bool {
	if e == nil || other == nil {
		return e == other
	}

	if e.Type != other.Type {
		return false
	}

	return bytes.Equal(e.Data, other.Data)
}

// Clone crea una copia profunda de las Extensions.
//
// La copia es independiente del original - modificar una no afecta la otra.
//
// # Ejemplo
//
// exts := NewExtensions()
// exts.Add(Extension{Type: ExtensionTypeApplicationId, Data: []byte("test")})
//
// cloned := exts.Clone()
// // cloned.Len() == exts.Len()
// // pero son objetos diferentes
func (e *Extensions) Clone() *Extensions {
	result := NewExtensions()
	for _, typ := range e.ordered {
		ext := e.extensions[typ]
		result.Add(Extension{
			Type: ext.Type,
			Data: append([]byte(nil), ext.Data...),
		})
	}
	return result
}

// GREASE extension types for testing extensibility (RFC 9420 §13.5)
const (
	ExtensionTypeGREASE0 ExtensionType = 0x0A0A
	ExtensionTypeGREASE1 ExtensionType = 0x1A1A
	ExtensionTypeGREASE2 ExtensionType = 0x2A2A
	ExtensionTypeGREASE3 ExtensionType = 0x3A3A
	ExtensionTypeGREASE4 ExtensionType = 0x4A4A
	ExtensionTypeGREASE5 ExtensionType = 0x5A5A
	ExtensionTypeGREASE6 ExtensionType = 0x6A6A
	ExtensionTypeGREASE7 ExtensionType = 0x7A7A
	ExtensionTypeGREASE8 ExtensionType = 0x8A8A
	ExtensionTypeGREASE9 ExtensionType = 0x9A9A
	ExtensionTypeGREASEA ExtensionType = 0xAAAA
	ExtensionTypeGREASEB ExtensionType = 0xBABA
	ExtensionTypeGREASEC ExtensionType = 0xCACA
	ExtensionTypeGREASED ExtensionType = 0xDADA
	ExtensionTypeGREASEE ExtensionType = 0xEAEA
)
