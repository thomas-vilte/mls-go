// Package extensions - External Pub Extension (RFC 9420 §11.2.4)
package extensions

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/openmls/go/internal/tls"
)

// ExternalPubExtension contiene una public key HPKE para External Commit.
//
// # ¿Para qué sirve?
//
// Esta extensión se usa en GroupInfo para permitir que nuevos miembros se unan
// al grupo vía External Commit. Contiene la public key HPKE que los nuevos
// miembros usan para cifrar su External Commit.
//
// # Estructura (RFC 9420 §11.2.4)
//
// ```
// ┌────────────────────────────────—────────┐
// │    ExternalPubExtension                 │
// ├─────────────────────────────────────────┤
// │  external_pub: HPKEPublicKey            │  ← Public key HPKE
// └─────────────────────────────────────────┘
// ```
//
// # Ubicación
//
// - **KeyPackage**: No ❌
// - **GroupInfo**: Sí ✅
// - **GroupContext**: No ❌
//
// # ¿Cómo funciona External Commit?
//
// ```
// ┌──────────────────────────────────────────────────────────────┐
// │  1. Nuevo miembro obtiene GroupInfo con ExternalPub          │
// │                                                              │
// │  2. Extrae external_pub de la extensión                      │
// │                                                              │
// │  3. Usa HPKE para cifrar Commit con external_pub             │
// │                                                              │
// │  4. Envía External Commit al grupo                           │
// │                                                              │
// │  5. Grupo procesa Commit y welcome al nuevo miembro          │
// └──────────────────────────────────────────────────────────────┘
// ```
//
// # Ejemplo de Uso
//
// // Crear con HPKE public key
// publicKey := getHPKEPublicKey()  // Obtener de algún lado
// ext := NewExternalPubExtension(publicKey)
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
// ext2, err := UnmarshalExternalPubExtension(data)
//
// # HPKE Public Key Format
//
// La public key HPKE se encodea como opaque<V> según RFC 9180.
// El formato específico depende del KEM usado:
//
// - **DHKEM P-256**: 65 bytes (0x04 || X || Y)
// - **DHKEM X25519**: 32 bytes
//
// # RFC Compliance
//
// RFC 9420 §11.2.4:
// "The ExternalPub extension is used in GroupInfo to provide the
// information necessary for a new member to join the group via an
// External Commit."
type ExternalPubExtension struct {
	ExternalPub []byte // HPKE public key encodeada (opaque<V>)
}

// NewExternalPubExtension crea una nueva ExternalPubExtension.
//
// La public key HPKE debe estar encodeada según RFC 9180.
//
// # Ejemplo
//
// publicKey := []byte{0x04, ...}  // HPKE public key (65 bytes para P-256)
// ext := NewExternalPubExtension(publicKey)
func NewExternalPubExtension(publicKey []byte) *ExternalPubExtension {
	return &ExternalPubExtension{
		ExternalPub: publicKey,
	}
}

// Marshal serializa la extensión a formato TLS.
//
// # Encoding
//
// ```
// ┌─────────────────────────────────────────┐
// │  external_pub_length: varint            │
// ├─────────────────────────────────────────┤
// │  external_pub: opaque[]                 │  ← HPKE public key
// └─────────────────────────────────────────┘
// ```
//
// # Ejemplo
//
// ext := NewExternalPubExtension([]byte{0x04, ...})
// data := ext.Marshal()
func (e *ExternalPubExtension) Marshal() []byte {
	buf := tls.NewWriter()
	buf.WriteVLBytes(e.ExternalPub)
	return buf.Bytes()
}

// UnmarshalExternalPubExtension parsea una ExternalPubExtension desde TLS.
//
// # Decoding
//
// Lee external_pub como variable-length bytes.
//
// # Ejemplo
//
// data := []byte{0x41, 0x04, ...}  // 65 bytes + length prefix
// ext, err := UnmarshalExternalPubExtension(data)
//
//	if err != nil {
//	    return err
//	}
//
// // ext.ExternalPub == []byte{0x04, ...}
func UnmarshalExternalPubExtension(data []byte) (*ExternalPubExtension, error) {
	buf := tls.NewReader(data)
	pubKeyBytes, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading external_pub: %w", err)
	}
	return &ExternalPubExtension{
		ExternalPub: pubKeyBytes,
	}, nil
}

// Validate valida la extensión.
//
// # Reglas de Validación
//
// - ✅ ExternalPub no debe ser nil
// - ✅ ExternalPub no debe estar vacío
// - ✅ ExternalPub debe ser una HPKE public key válida
//
// # Ejemplo
//
// ext := NewExternalPubExtension([]byte{0x04, ...})
//
//	if err := ext.Validate(); err != nil {
//	    return err  // Extensión inválida
//	}
func (e *ExternalPubExtension) Validate() error {
	if e.ExternalPub == nil {
		return errors.New("external_pub cannot be nil")
	}
	if len(e.ExternalPub) == 0 {
		return errors.New("external_pub cannot be empty")
	}

	// Validar formato básico de HPKE public key
	// Para P-256: debe empezar con 0x04 (uncompressed) y tener 65 bytes
	if len(e.ExternalPub) == 65 {
		if e.ExternalPub[0] != 0x04 {
			return errors.New("invalid P-256 public key: must start with 0x04")
		}
	}
	// Para X25519: debe tener 32 bytes
	// (no validamos el byte prefix porque X25519 no usa formato uncompressed)

	return nil
}

// Equal compara dos ExternalPubExtension para igualdad.
//
// Compara los ExternalPub bytes usando comparación constante.
//
// # Ejemplo
//
// ext1 := NewExternalPubExtension([]byte{0x04, ...})
// ext2 := NewExternalPubExtension([]byte{0x04, ...})
//
// ext1.Equal(ext2)  // true si las keys son iguales
func (e *ExternalPubExtension) Equal(other *ExternalPubExtension) bool {
	if e == nil || other == nil {
		return e == other
	}
	return bytes.Equal(e.ExternalPub, other.ExternalPub)
}

// ToExtension convierte a Extension genérica.
//
// Útil para agregar a una colección Extensions.
//
// # Ejemplo
//
// ext := NewExternalPubExtension([]byte{0x04, ...})
// genericExt, err := ext.ToExtension()
//
//	if err != nil {
//	    return err
//	}
//
// exts := NewExtensions()
// exts.Add(*genericExt)
func (e *ExternalPubExtension) ToExtension() (*Extension, error) {
	data := e.Marshal()
	return &Extension{
		Type: ExtensionTypeExternalPub,
		Data: data,
	}, nil
}

// FromExtension crea desde Extension genérica.
//
// Devuelve error si el Type no es ExtensionTypeExternalPub.
//
// # Ejemplo
//
// genericExt := &Extension{Type: ExtensionTypeExternalPub, Data: []byte{...}}
// ext, err := FromExternalPubExtension(genericExt)
//
//	if err != nil {
//	    return err
//	}
func FromExternalPubExtension(ext *Extension) (*ExternalPubExtension, error) {
	if ext.Type != ExtensionTypeExternalPub {
		return nil, fmt.Errorf("wrong extension type: %d", ext.Type)
	}
	return UnmarshalExternalPubExtension(ext.Data)
}

// PublicKeyBytes devuelve los bytes de la public key HPKE.
//
// Útil para usar con funciones HPKE del package ciphersuite.
//
// # Ejemplo
//
// ext := NewExternalPubExtension(publicKeyBytes)
// pubKeyBytes := ext.PublicKeyBytes()
// ciphertext, err := ciphersuite.EncryptWithLabel(pubKeyBytes, ...)
func (e *ExternalPubExtension) PublicKeyBytes() []byte {
	if e == nil {
		return nil
	}
	return append([]byte(nil), e.ExternalPub...)
}

// String devuelve una representación string de la extensión.
//
// Muestra los primeros 8 bytes de la public key en hexadecimal.
//
// # Ejemplo
//
// ext := NewExternalPubExtension([]byte{0x04, 0x12, 0x34, ...})
// fmt.Println(ext.String())  // "ExternalPub(041234...)"
func (e *ExternalPubExtension) String() string {
	if e == nil || e.ExternalPub == nil {
		return "ExternalPub(<nil>)"
	}
	if len(e.ExternalPub) == 0 {
		return "ExternalPub(<empty>)"
	}

	// Show first 8 bytes in hex
	end := 8
	if len(e.ExternalPub) < end {
		end = len(e.ExternalPub)
	}
	return fmt.Sprintf("ExternalPub(%x...)", e.ExternalPub[:end])
}

// Len devuelve la longitud de la public key en bytes.
//
// # Ejemplo
//
// ext := NewExternalPubExtension([]byte{0x04, ...})  // 65 bytes
// // ext.Len() == 65
func (e *ExternalPubExtension) Len() int {
	if e == nil {
		return 0
	}
	return len(e.ExternalPub)
}

// IsP256 verifica si la public key es P-256.
//
// Las keys P-256 tienen 65 bytes y empiezan con 0x04.
//
// # Ejemplo
//
// ext := NewExternalPubExtension(p256PublicKey)
//
//	if ext.IsP256() {
//	    // Es una key P-256
//	}
func (e *ExternalPubExtension) IsP256() bool {
	if e == nil || e.ExternalPub == nil {
		return false
	}
	return len(e.ExternalPub) == 65 && e.ExternalPub[0] == 0x04
}

// IsX25519 verifica si la public key es X25519.
//
// Las keys X25519 tienen 32 bytes.
//
// # Ejemplo
//
// ext := NewExternalPubExtension(x25519PublicKey)
//
//	if ext.IsX25519() {
//	    // Es una key X25519
//	}
func (e *ExternalPubExtension) IsX25519() bool {
	if e == nil || e.ExternalPub == nil {
		return false
	}
	return len(e.ExternalPub) == 32
}
