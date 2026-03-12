// Package credentials implementa los tipos de credenciales para MLS según RFC 9420 §5.3.
//
// # ¿Qué es esto?
//
// Acá tenés las credenciales que autentican a los miembros en un grupo MLS.
// Cada KeyPackage y cada nodo hoja en el ratchet tree tiene una credencial
// que dice "che, este soy yo, confíen en mí".
//
// # Tipos de Credenciales (RFC 9420 §5.3)
//
// Implementamos dos tipos:
//   - BasicCredential (§11.2.1): La más simple, solo una identidad
//   - X509Credential (§11.2.2): Cadena de certificados X.509 para PKI
//
// # ¿Cómo se usa?
//
// Credential básica (para user IDs):
//
//	cred := credentials.NewBasicCredentialFromUint64(userID)
//	credWithKey, privKey, err := credentials.GenerateCredentialWithKey(identity)
//
// Credential X.509 (para autenticación con certificados):
//
//	certs := [][]byte{certDER1, certDER2}
//	cred := credentials.NewX509Credential(certs)
//	err := cred.ValidateX509()
//
// # Estructura de una Credential
//
// ```
// ┌────────────────────────────────────────────────────────────┐
// │                    Credential (RFC 9420)                   │
// ├────────────────────────────────────────────────────────────┤
// │  credential_type: uint16                                   │
// │    ├─ 0x0001: BasicCredential                              │
// │    ├─ 0x0002: X509Credential                               │
// │    └─ 0x0A0A: GREASE (para testing)                        │
// │                                                            │
// │  credential: select (credential_type)                      │
// │    ├─ basic: opaque identity<V>                            │
// │    └─ x509:  opaque cert_data<V>                           │
// └────────────────────────────────────────────────────────────┘
// ```
//
// # Compliance con RFC
//
//   - RFC 9420 §5.3: Tipos de Credenciales
//   - RFC 9420 §11.2.1: BasicCredential
//   - RFC 9420 §11.2.2: X509Credential
//   - RFC 9420 §13.5: GREASE handling
package credentials

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/mls-go/ciphersuite"
	"github.com/mls-go/internal/tls"
)

// CredentialType representa el tipo de credencial según RFC 9420 §5.3.
//
//	enum {
//	    basic(1),
//	    x509(2),
//	    grease(0x0A0A),
//	    (2^16-1)
//	} CredentialType;
//
// Tipos que manejamos:
//   - BasicCredential (0x0001): La más simple, solo una identidad
//   - X509Credential (0x0002): Cadena de certificados X.509
//   - GREASE (0x0A0A, 0x1A1A, etc.): Para testing de extensibilidad
type CredentialType uint16

const (
	// BasicCredential es el tipo más simple (RFC 9420 §11.2.1).
	// Contiene una identidad opaca como bytes.
	// La podés usar para:
	//   - User ID como uint64 big-endian (8 bytes)
	//   - Username como string UTF-8
	//   - Email como string UTF-8
	BasicCredential CredentialType = 0x0001

	// X509Credential contiene una cadena de certificados X.509 (RFC 9420 §11.2.2).
	// Se usa para autenticación PKI más robusta.
	// El primer certificado es el end-entity, los demás son intermediarios.
	X509Credential CredentialType = 0x0002

	// GREASE_CREDENTIAL_TYPE es para testing de extensibilidad (RFC 9420 §13.5).
	// Los valores GREASE (0x0A0A, 0x1A1A, etc.) aseguran que tu código
	// maneje bien tipos desconocidos sin romperse.
	GREASE_CREDENTIAL_TYPE CredentialType = 0x0A0A
)

// String devuelve un nombre legible para el tipo de credencial.
// Lo usamos para logging y debugging.
func (ct CredentialType) String() string {
	switch ct {
	case BasicCredential:
		return "Basic"
	case X509Credential:
		return "X509"
	default:
		if ct.isGREASE() {
			return "GREASE"
		}
		return fmt.Sprintf("Unknown(0x%04x)", uint16(ct))
	}
}

// isGREASE devuelve true si es un tipo GREASE.
// GREASE son valores como 0x0A0A, 0x1A1A, 0x2A2A, ..., 0xEAEA.
// La gracia es que el byte alto y bajo tienen la misma forma: 0xA0, 0xA.
func (ct CredentialType) isGREASE() bool {
	// GREASE values: 0x0A0A, 0x1A1A, 0x2A2A, ..., 0xEAEA
	return ct >= 0x0A0A && ct <= 0xEAEA && (uint16(ct)&0x0F0F) == 0x0A0A
}

// Credential representa una credencial MLS (RFC 9420 §5.3).
//
// Las credenciales autentican miembros del grupo y contienen información de identidad.
// Cada KeyPackage y nodo hoja tiene una Credential que dice "este soy yo".
//
// # Estructura (TLS encoding)
//
// ```
//
//	struct {
//	    CredentialType credential_type;  // uint16
//	    select (credential_type) {
//	        case basic: opaque identity<V>;    // Variable-length bytes
//	        case x509:  opaque cert_data<V>;   // DER-encoded certs
//	    } credential;
//	} Credential;
//
// ```
//
// # ¿Qué tipo elegir?
//
// **BasicCredential:**
//   - ✅ Simple, liviana
//   - ✅ Perfecta para user IDs
//   - ❌ Sin validación criptográfica
//
// **X509Credential:**
//   - ✅ Validación PKI completa
//   - ✅ Cadena de confianza
//   - ❌ Más pesada, más compleja
type Credential struct {
	CredentialType CredentialType
	Identity       []byte   // Para BasicCredential: identidad opaca
	Certificates   [][]byte // Para X509Credential: certificados DER
}

// NewBasicCredential crea una nueva BasicCredential.
//
// BasicCredential contiene una identidad opaca como bytes.
// Los formatos más comunes son:
//   - User ID como uint64 big-endian (8 bytes) - el más usado
//   - Username como string UTF-8
//   - Email como string UTF-8
//
// # Ejemplo
//
//	// User ID
//	cred := NewBasicCredentialFromUint64(12345678901234567890)
//
//	// Username
//	cred := NewBasicCredentialFromString("alice@example.com")
//
//	// Raw bytes
//	cred := NewBasicCredential([]byte{0x01, 0x02, 0x03})
func NewBasicCredential(identity []byte) *Credential {
	return &Credential{
		CredentialType: BasicCredential,
		Identity:       identity,
	}
}

// NewBasicCredentialFromString crea una BasicCredential desde un string.
//
// Útil para usernames, emails, o cualquier identidad legible.
// El string se guarda como UTF-8.
func NewBasicCredentialFromString(identity string) *Credential {
	return NewBasicCredential([]byte(identity))
}

// NewBasicCredentialFromUint64 crea una BasicCredential desde un uint64.
//
// El ID se encodea como big-endian (network byte order).
// Este es el formato que usan la mayoría de los protocolos para user IDs.
//
// # Ejemplo
//
//	userID := uint64(12345678901234567890)
//	cred := NewBasicCredentialFromUint64(userID)
//	// Identity: []byte{0xAB, 0xCD, ...} (8 bytes)
func NewBasicCredentialFromUint64(id uint64) *Credential {
	identity := make([]byte, 8)
	binary.BigEndian.PutUint64(identity, id)
	return NewBasicCredential(identity)
}

// NewX509Credential crea una nueva X509Credential desde certificados DER.
//
// La cadena de certificados va ordenada así:
//   - certificates[0]: Certificado end-entity (el tuyo)
//   - certificates[1..n]: Certificados CA intermedios
//   - Root CA: Normalmente se omite (se asume que es trusted)
//
// # ¿Cuándo usar esto?
//
// Usá X509Credential cuando necesites:
//   - Validación PKI completa
//   - Cadena de confianza verificable
//   - Autenticación fuerte (ej: servidores, gateways)
//
// # Ejemplo
//
//	certDER, _ := os.ReadFile("server.crt")
//	cred := NewX509Credential([][]byte{certDER})
//	err := cred.Validate()
func NewX509Credential(certificates [][]byte) *Credential {
	return &Credential{
		CredentialType: X509Credential,
		Certificates:   certificates,
	}
}

// Marshal serializa la Credential a formato TLS (RFC 9420 §5.3).
//
// # Encoding
//
// ```
// ┌─────────────────────────────────────────┐
// │  credential_type: uint16                │
//
//	├─────────────────────────────────────────┤
//
// │  credential: variable-length            │
// │    ├─ Basic:  opaque identity<V>        │
// │    └─ X509:   opaque cert_data<V>       │
// └─────────────────────────────────────────┘
// ```
//
// Para X509Credential, los certificados se concatenan con length prefix:
// ```
// cert_data = [len(cert1)][cert1][len(cert2)][cert2]...
// ```
func (c *Credential) Marshal() []byte {
	buf := tls.NewWriter()
	buf.WriteUint16(uint16(c.CredentialType))

	switch c.CredentialType {
	case BasicCredential:
		buf.WriteVLBytes(c.Identity)
	case X509Credential:
		// X509Credential: concatenamos certs con length prefix
		var certData []byte
		for _, cert := range c.Certificates {
			certLen := make([]byte, 2)
			binary.BigEndian.PutUint16(certLen, uint16(len(cert)))
			certData = append(certData, certLen...)
			certData = append(certData, cert...)
		}
		buf.WriteVLBytes(certData)
	default:
		// GREASE o desconocido: escribimos datos vacíos
		buf.WriteVLBytes(nil)
	}

	return buf.Bytes()
}

// UnmarshalCredential parsea una Credential desde formato TLS.
//
// Devuelve la credential o un error si el encoding es inválido.
//
// # Ejemplo
//
//	data := cred.Marshal()
//	parsed, err := UnmarshalCredential(data)
//	if err != nil {
//	    return err
//	}
//	fmt.Printf("Tipo: %s\n", parsed.Type())
func UnmarshalCredential(data []byte) (*Credential, error) {
	buf := tls.NewReader(data)

	credType, err := buf.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("reading credential_type: %w", err)
	}

	ct := CredentialType(credType)

	switch ct {
	case BasicCredential:
		identity, err := buf.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading identity: %w", err)
		}
		return &Credential{
			CredentialType: ct,
			Identity:       identity,
		}, nil

	case X509Credential:
		certData, err := buf.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading cert_data: %w", err)
		}

		// Parsear cadena de certificados
		var certificates [][]byte
		for len(certData) > 0 {
			if len(certData) < 2 {
				return nil, errors.New("invalid certificate chain encoding")
			}
			certLen := binary.BigEndian.Uint16(certData[:2])
			certData = certData[2:]

			if len(certData) < int(certLen) {
				return nil, errors.New("certificate chain truncated")
			}
			cert := make([]byte, certLen)
			copy(cert, certData[:certLen])
			certificates = append(certificates, cert)
			certData = certData[certLen:]
		}

		return &Credential{
			CredentialType: ct,
			Certificates:   certificates,
		}, nil

	default:
		// GREASE o desconocido: skippeamos los datos
		_, err := buf.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading unknown credential data: %w", err)
		}
		return &Credential{
			CredentialType: ct,
		}, nil
	}
}

// UnmarshalCredentialFromReader deserializes a Credential inline from a TLS reader (RFC 9420 §5.3).
// Used when Credential is embedded directly in a struct without an outer VL wrapper.
func UnmarshalCredentialFromReader(r *tls.Reader) (*Credential, error) {
	credType, err := r.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("reading credential_type: %w", err)
	}

	ct := CredentialType(credType)

	switch ct {
	case 0: // nil placeholder (type=0 reserved): discard empty body, return nil
		_, err := r.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading nil credential body: %w", err)
		}
		return nil, nil

	case BasicCredential:
		identity, err := r.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading identity: %w", err)
		}
		return &Credential{
			CredentialType: ct,
			Identity:       identity,
		}, nil

	case X509Credential:
		certData, err := r.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading cert_data: %w", err)
		}
		var certificates [][]byte
		for len(certData) > 0 {
			if len(certData) < 2 {
				return nil, errors.New("invalid certificate chain encoding")
			}
			certLen := binary.BigEndian.Uint16(certData[:2])
			certData = certData[2:]
			if len(certData) < int(certLen) {
				return nil, errors.New("certificate chain truncated")
			}
			cert := make([]byte, certLen)
			copy(cert, certData[:certLen])
			certificates = append(certificates, cert)
			certData = certData[certLen:]
		}
		return &Credential{
			CredentialType: ct,
			Certificates:   certificates,
		}, nil

	default:
		_, err := r.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading unknown credential data: %w", err)
		}
		return &Credential{CredentialType: ct}, nil
	}
}

// IdentityString devuelve la identidad como string legible.
//
// Para IDs numéricas (8 bytes), devuelve la representación decimal.
// Para otros formatos, devuelve el string UTF-8.
//
// # Ejemplo
//
//	cred := NewBasicCredentialFromUint64(42)
//	fmt.Println(cred.IdentityString()) // "42"
//
//	cred := NewBasicCredentialFromString("alice")
//	fmt.Println(cred.IdentityString()) // "alice"
func (c *Credential) IdentityString() string {
	if c.CredentialType != BasicCredential {
		return ""
	}

	// Intentamos decodificar como uint64 si son 8 bytes
	if len(c.Identity) == 8 {
		id := binary.BigEndian.Uint64(c.Identity)
		return fmt.Sprintf("%d", id)
	}

	return string(c.Identity)
}

// Validate valida la credential según las reglas de MLS (RFC 9420 §5.3).
//
// # Qué valida
//
// **BasicCredential:**
//   - ✅ Identidad no vacía
//   - ✅ Identidad <= 65535 bytes
//
// **X509Credential:**
//   - ✅ Al menos un certificado
//   - ✅ Todos los certificados son DER válidos
//   - ✅ Certificado end-entity no expirado
//
// **GREASE:**
//   - ✅ Siempre válido (RFC 9420 §13.5)
//
// # Ejemplo
//
//	cred := NewBasicCredentialFromString("alice")
//	err := cred.Validate()
//	if err != nil {
//	    return err // Credential inválida
//	}
func (c *Credential) Validate() error {
	switch c.CredentialType {
	case BasicCredential:
		return c.validateBasic()
	case X509Credential:
		return c.validateX509()
	default:
		if c.CredentialType.isGREASE() {
			// GREASE siempre es válido (RFC 9420 §13.5)
			return nil
		}
		return fmt.Errorf("unsupported credential type: 0x%04x", uint16(c.CredentialType))
	}
}

// validateBasic valida una BasicCredential.
//
// Checks:
//   - Identidad no vacía
//   - Identidad no demasiado larga (max 65535 bytes)
func (c *Credential) validateBasic() error {
	if len(c.Identity) == 0 {
		return errors.New("BasicCredential: identity cannot be empty")
	}

	if len(c.Identity) > 65535 {
		return errors.New("BasicCredential: identity too long (max 65535 bytes)")
	}

	return nil
}

// validateX509 valida una X509Credential.
//
// Checks:
//   - ✅ Al menos un certificado presente
//   - ✅ Todos los certificados son DER válidos
//   - ✅ Certificado end-entity no expirado
//
// Nota: La validación completa de la cadena requiere trusted roots
// y es específica de cada aplicación. Usá ValidateX509Chain para eso.
func (c *Credential) validateX509() error {
	if len(c.Certificates) == 0 {
		return errors.New("X509Credential: at least one certificate required")
	}

	// Validar certificado end-entity
	endEntity, err := x509.ParseCertificate(c.Certificates[0])
	if err != nil {
		return fmt.Errorf("X509Credential: invalid end-entity certificate: %w", err)
	}

	// Check expiration
	now := time.Now()
	if now.Before(endEntity.NotBefore) {
		return errors.New("X509Credential: certificate not yet valid")
	}
	if now.After(endEntity.NotAfter) {
		return errors.New("X509Credential: certificate expired")
	}

	// Validar certificados intermedios (básico DER check)
	for i, certDER := range c.Certificates[1:] {
		_, err := x509.ParseCertificate(certDER)
		if err != nil {
			return fmt.Errorf("X509Credential: invalid intermediate certificate %d: %w", i+1, err)
		}
	}

	return nil
}

// ValidateX509Chain hace validación completa de la cadena X.509.
//
// # Qué requiere
//
//   - Trusted root CA certificates (roots)
//   - Opcional: Intermediate CA certificates
//   - Opcional: DNS name o IP address a verificar
//
// # Qué valida
//
//   - ✅ Cadena válida y completa
//   - ✅ Todos los certificados no expirados
//   - ✅ Firma criptográfica válida
//   - ✅ Trusted root
//   - ✅ DNS name match (si se provee)
//
// # Ejemplo
//
//	roots, _ := x509.SystemCertPool()
//	err := cred.ValidateX509Chain(roots, "server.example.com")
//	if err != nil {
//	    return err // Cadena inválida o no trusted
//	}
func (c *Credential) ValidateX509Chain(roots *x509.CertPool, dnsName string) error {
	if err := c.validateX509(); err != nil {
		return err
	}

	// Parsear certificados
	certs := make([]*x509.Certificate, len(c.Certificates))
	for i, certDER := range c.Certificates {
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return fmt.Errorf("parsing certificate %d: %w", i, err)
		}
		certs[i] = cert
	}

	// Armar cadena de certificados
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	// Verificar cadena
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}

	if dnsName != "" {
		opts.DNSName = dnsName
	}

	_, err := certs[0].Verify(opts)
	return err
}

// Hash computa el hash de una credential.
//
// Se usa para KeyPackage references y otros identificadores.
// Hash(Credential) = SHA-256(MLSByte(credential_type) || credential_data)
//
// # Ejemplo
//
//	hash := cred.Hash()
//	// hash: []byte de 32 bytes (SHA-256)
func (c *Credential) Hash() []byte {
	data := c.Marshal()
	hash := sha256.Sum256(data)
	return hash[:]
}

// CredentialWithKey empareja una Credential con su key pair de firma.
//
// Esto se usa cuando generás KeyPackages y firmás mensajes MLS.
// La Credential te identifica, las keys te permiten firmar.
//
// # Estructura
//
// ```
// ┌─────────────────────────────────────────┐
// │         CredentialWithKey               │
// ├─────────────────────────────────────────┤
// │  Credential:    tu identidad            │
// │  SignatureKey:  public key (P-256)      │
// │  PrivateKey:    private key (secreto)   │
// └─────────────────────────────────────────┘
// ```
type CredentialWithKey struct {
	Credential        *Credential
	SignatureKey      *ecdsa.PublicKey
	PrivateKey        *ecdsa.PrivateKey  // Private key para firmar (¡mantenela secreta!) — nil for Ed25519
	Ed25519PrivateKey ed25519.PrivateKey // non-nil for CS1/CS3 (Ed25519 scheme)
	SignatureKeyBytes []byte             // raw public key bytes (works for both ECDSA and Ed25519)
}

// GenerateCredentialWithKey genera una nueva credential con su key pair asociado.
//
// Devuelve la credential con keys, y la private key por separado para conveniencia.
// La private key tenés que guardarla de forma segura y usarla solo para firmar.
//
// Usa la curva P-256 como requiere MLS (RFC 9420 §5.1).
//
// # Ejemplo
//
//	credWithKey, privKey, err := GenerateCredentialWithKey([]byte("alice"))
//	if err != nil {
//	    return err
//	}
//	// Guardar privKey de forma segura
//	// Usar credWithKey para crear KeyPackage
func GenerateCredentialWithKey(identity []byte) (*CredentialWithKey, *ecdsa.PrivateKey, error) {
	// Generar key pair P-256 (requerido para MLS)
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating key pair: %w", err)
	}

	cred := NewBasicCredential(identity)

	credWithKey := &CredentialWithKey{
		Credential:   cred,
		SignatureKey: &privKey.PublicKey,
		PrivateKey:   privKey,
	}

	return credWithKey, privKey, nil
}

// GenerateCredentialWithKeyForCS generates a credential with a key pair appropriate for the given cipher suite.
// For CS1/CS3 (Ed25519 signature scheme): uses Ed25519.
// For CS2 (ECDSA): uses P-256.
func GenerateCredentialWithKeyForCS(identity []byte, cs ciphersuite.CipherSuite) (*CredentialWithKey, *ciphersuite.SignaturePrivateKey, error) {
	switch cs.SignatureScheme() {
	case ciphersuite.ED25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generating Ed25519 key: %w", err)
		}
		cred := NewBasicCredential(identity)
		sigPriv := ciphersuite.NewEd25519SignaturePrivateKey(priv)
		credWithKey := &CredentialWithKey{
			Credential:        cred,
			SignatureKey:      nil,
			PrivateKey:        nil,
			Ed25519PrivateKey: priv,
			SignatureKeyBytes: []byte(pub),
		}
		return credWithKey, sigPriv, nil
	default: // ECDSA_SECP256R1_SHA256 (CS2)
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generating P-256 key: %w", err)
		}
		cred := NewBasicCredential(identity)
		sigPriv := ciphersuite.NewSignaturePrivateKey(privKey)
		credWithKey := &CredentialWithKey{
			Credential:   cred,
			SignatureKey: &privKey.PublicKey,
			PrivateKey:   privKey,
		}
		return credWithKey, sigPriv, nil
	}
}

// GenerateX509CredentialWithKey genera una X509Credential con su key pair.
//
// Esto es útil para testing y para entidades que necesitan autenticación X.509
// (ej: servidores, gateways).
//
// Nota: Para producción, los certificados deberían ser emitidos por una CA trusted.
func GenerateX509CredentialWithKey(certDER []byte, privKey *ecdsa.PrivateKey) (*CredentialWithKey, error) {
	cred := NewX509Credential([][]byte{certDER})

	return &CredentialWithKey{
		Credential:   cred,
		SignatureKey: &privKey.PublicKey,
		PrivateKey:   privKey,
	}, nil
}

// Sign firma datos con la private key de la credential.
//
// El formato de firma es ECDSA-SHA256 como requiere MLS (RFC 9420 §5.1.2).
// La firma se encodea como R || S raw (64 bytes para P-256).
//
// # Encoding de la firma
//
// ```
// ┌─────────────────────────────────────────┐
// │      Signature (64 bytes)               │
// ├─────────────────────────────────────────┤
// │  R: 32 bytes (big-endian)               │
// │  S: 32 bytes (big-endian)               │
// └─────────────────────────────────────────┘
// ```
//
// Nota: Esto difiere de DER encoding. MLS usa raw encoding por eficiencia.
//
// # Ejemplo
//
//	signature, err := Sign(privKey, []byte("message"))
//	if err != nil {
//	    return err
//	}
//	// signature: 64 bytes
func Sign(privKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	// Encodear como R || S (64 bytes para P-256)
	// FillBytes asegura que siempre sean 32 bytes c/u
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])

	return signature, nil
}

// Verify verifica una firma usando la public key de la credential.
//
// Espera la firma en formato R || S (64 bytes para P-256).
// Devuelve true si la firma es válida, false si no.
//
// # Ejemplo
//
//	valid := Verify(pubKey, data, signature)
//	if !valid {
//	    return errors.New("firma inválida")
//	}
func Verify(pubKey *ecdsa.PublicKey, data, signature []byte) bool {
	hash := sha256.Sum256(data)

	// Decodificar firma (formato R || S, 64 bytes para P-256)
	if len(signature) != 64 {
		return false
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	return ecdsa.Verify(pubKey, hash[:], r, s)
}

// IsGREASE devuelve true si la credential es tipo GREASE.
//
// GREASE (Generate Random Extensions And Sustain Extensibility)
// se usa para asegurar que las implementaciones manejen bien tipos desconocidos.
// Ver RFC 9420 §13.5.
//
// Los valores GREASE son: 0x0A0A, 0x1A1A, 0x2A2A, ..., 0xEAEA.
func (c *Credential) IsGREASE() bool {
	return c.CredentialType.isGREASE()
}

// Type devuelve el tipo de credential.
//
// Útil para switch/case y logging.
func (c *Credential) Type() CredentialType {
	return c.CredentialType
}
