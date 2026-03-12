// Copyright 2024 MLS-Go Authors. All rights reserved.
// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE file.

// Package credentials implements MLS credential types per RFC 9420 §5.3.
//
// # Overview
//
// Credentials authenticate group members in MLS. Each KeyPackage and leaf node
// in the ratchet tree has a credential that proves identity.
//
// # Credential Types (RFC 9420 §5.3)
//
// Two types are implemented:
//   - BasicCredential (§11.2.1): Simple identity (user ID, username, email)
//   - X509Credential (§11.2.2): X.509 certificate chain for PKI authentication
//
// # Usage
//
// Basic credential (for user IDs):
//
//	cred := credentials.NewBasicCredentialFromUint64(userID)
//	credWithKey, privKey, err := credentials.GenerateCredentialWithKey(identity)
//
// X.509 credential (for PKI authentication):
//
//	certs := [][]byte{certDER1, certDER2}
//	cred := credentials.NewX509Credential(certs)
//	err := cred.ValidateX509()
//
// # Credential Structure (RFC 9420 §5.3)
//
// ```text
// ┌────────────────────────────────────────────────────────────┐
// │                    Credential (RFC 9420)                   │
// ├────────────────────────────────────────────────────────────┤
// │  credential_type: uint16                                   │
// │    ├─ 0x0001: BasicCredential                              │
// │    ├─ 0x0002: X509Credential                               │
// │    └─ 0x0A0A: GREASE (extensibility testing)               │
// │                                                            │
// │  credential: select (credential_type)                      │
// │    ├─ basic: opaque identity<V>                            │
// │    └─ x509:  opaque cert_data<V>                           │
// └────────────────────────────────────────────────────────────┘
// ```
//
// # RFC Compliance
//
//   - RFC 9420 §5.3: Credential Types
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

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/internal/tls"
)

// CredentialType represents a credential type per RFC 9420 §5.3.
//
//	enum {
//	    basic(1),
//	    x509(2),
//	    grease(0x0A0A),
//	    (2^16-1)
//	} CredentialType;
//
// Supported types:
//   - BasicCredential (0x0001): Simple opaque identity
//   - X509Credential (0x0002): X.509 certificate chain
//   - GREASE (0x0A0A, 0x1A1A, etc.): Extensibility testing
type CredentialType uint16

const (
	// BasicCredential is the simplest credential type (RFC 9420 §11.2.1).
	// Contains an opaque identity as bytes.
	// Common formats:
	//   - User ID as uint64 big-endian (8 bytes)
	//   - Username as UTF-8 string
	//   - Email as UTF-8 string
	BasicCredential CredentialType = 0x0001

	// X509Credential contains an X.509 certificate chain (RFC 9420 §11.2.2).
	// Used for PKI-based authentication.
	// First certificate is end-entity, rest are intermediates.
	X509Credential CredentialType = 0x0002

	// GREASE_CREDENTIAL is for extensibility testing (RFC 9420 §13.5).
	// GREASE values (0x0A0A, 0x1A1A, etc.) ensure implementations
	// handle unknown types gracefully without breaking.
	//
	//nolint:revive // GREASE naming follows RFC 9420 convention
	GREASE_CREDENTIAL CredentialType = 0x0A0A
)

// String returns a human-readable name for the credential type.
// Used for logging and debugging.
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

// isGREASE returns true if this is a GREASE type.
// GREASE values are: 0x0A0A, 0x1A1A, 0x2A2A, ..., 0xEAEA.
// The pattern ensures high and low bytes have the same form: 0xA0, 0xA.
func (ct CredentialType) isGREASE() bool {
	// GREASE values: 0x0A0A, 0x1A1A, 0x2A2A, ..., 0xEAEA
	return ct >= 0x0A0A && ct <= 0xEAEA && (uint16(ct)&0x0F0F) == 0x0A0A
}

// Credential represents an MLS credential per RFC 9420 §5.3.
//
// Credentials authenticate group members and contain identity information.
// Each KeyPackage and leaf node has a Credential that proves "this is me".
//
// # Structure (TLS encoding per RFC 9420 §5.3)
//
// ```text
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
// # Which type to choose?
//
// **BasicCredential:**
//   - ✅ Simple, lightweight
//   - ✅ Perfect for user IDs
//   - ❌ No cryptographic validation
//
// **X509Credential:**
//   - ✅ Full PKI validation
//   - ✅ Verifiable chain of tgo
//   - ❌ Heavier, more complex
type Credential struct {
	CredentialType CredentialType
	Identity       []byte   // For BasicCredential: opaque identity
	Certificates   [][]byte // For X509Credential: DER-encoded certificates
}

// NewBasicCredential creates a new BasicCredential.
//
// BasicCredential contains an opaque identity as bytes.
// Common formats:
//   - User ID as uint64 big-endian (8 bytes) - most common
//   - Username as UTF-8 string
//   - Email as UTF-8 string
//
// # Example
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

// NewBasicCredentialFromString creates a BasicCredential from a string.
//
// Useful for usernames, emails, or any human-readable identity.
// The string is stored as UTF-8.
func NewBasicCredentialFromString(identity string) *Credential {
	return NewBasicCredential([]byte(identity))
}

// NewBasicCredentialFromUint64 creates a BasicCredential from a uint64.
//
// The ID is encoded as big-endian (network byte order).
// This is the format most protocols use for user IDs.
//
// # Example
//
//	userID := uint64(12345678901234567890)
//	cred := NewBasicCredentialFromUint64(userID)
//	// Identity: []byte{0xAB, 0xCD, ...} (8 bytes)
func NewBasicCredentialFromUint64(id uint64) *Credential {
	identity := make([]byte, 8)
	binary.BigEndian.PutUint64(identity, id)
	return NewBasicCredential(identity)
}

// NewX509Credential creates a new X509Credential from DER-encoded certificates.
//
// Certificate chain ordering:
//   - certificates[0]: End-entity certificate (yours)
//   - certificates[1..n]: Intermediate CA certificates
//   - Root CA: Normally omitted (assumed trusted)
//
// # When to use
//
// Use X509Credential when you need:
//   - Full PKI validation
//   - Verifiable chain of tgo
//   - Strong authentication (e.g., servers, gateways)
//
// # Example
//
//	certDER, err := os.ReadFile("server.crt")
//	if err != nil {
//	    return err
//	}
//	cred := NewX509Credential([][]byte{certDER})
//	if err := cred.Validate(); err != nil {
//	    return err
//	}
func NewX509Credential(certificates [][]byte) *Credential {
	return &Credential{
		CredentialType: X509Credential,
		Certificates:   certificates,
	}
}

// Marshal serializes the Credential to TLS format per RFC 9420 §5.3.
//
// # Encoding
//
// ```text
// ┌─────────────────────────────────────────┐
// │  credential_type: uint16                │
// ├─────────────────────────────────────────┤
// │  credential: variable-length            │
// │    ├─ Basic:  opaque identity<V>        │
// │    └─ X509:   opaque cert_data<V>       │
// └─────────────────────────────────────────┘
// ```text
//
// For X509Credential, certificates are concatenated with length prefix:
// ```text
// cert_data = [len(cert1)][cert1][len(cert2)][cert2]...
// ```text.
func (c *Credential) Marshal() []byte {
	buf := tls.NewWriter()
	buf.WriteUint16(uint16(c.CredentialType))

	switch c.CredentialType {
	case BasicCredential:
		buf.WriteVLBytes(c.Identity)
	case X509Credential:
		// X509Credential: concatenate certs with length prefix
		var certData []byte
		for _, cert := range c.Certificates {
			certLen := make([]byte, 2)
			binary.BigEndian.PutUint16(certLen, uint16(len(cert)))
			certData = append(certData, certLen...)
			certData = append(certData, cert...)
		}
		buf.WriteVLBytes(certData)
	default:
		// GREASE or unknown: write empty data
		buf.WriteVLBytes(nil)
	}

	return buf.Bytes()
}

// UnmarshalCredential parses a Credential from TLS format per RFC 9420 §5.3.
//
// Returns the credential or an error if encoding is invalid.
//
// # Example
//
//	data := cred.Marshal()
//	parsed, err := UnmarshalCredential(data)
//	if err != nil {
//	    return err
//	}
//	fmt.Printf("Type: %s\n", parsed.Type())
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

		// Parse certificate chain
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
		// GREASE or unknown: skip data
		_, err := buf.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading unknown credential data: %w", err)
		}
		return &Credential{
			CredentialType: ct,
		}, nil
	}
}

// UnmarshalCredentialFromReader deserializes a Credential inline from a TLS reader per RFC 9420 §5.3.
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

// IdentityString returns the identity as a human-readable string.
//
// For numeric IDs (8 bytes), returns decimal representation.
// For other formats, returns UTF-8 string.
//
// # Example
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

	// Try to decode as uint64 if 8 bytes
	if len(c.Identity) == 8 {
		id := binary.BigEndian.Uint64(c.Identity)
		return fmt.Sprintf("%d", id)
	}

	return string(c.Identity)
}

// Validate validates the credential per MLS rules (RFC 9420 §5.3).
//
// # What is validated
//
// **BasicCredential:**
//   - ✅ Non-empty identity
//   - ✅ Identity <= 65535 bytes
//
// **X509Credential:**
//   - ✅ At least one certificate
//   - ✅ All certificates are valid DER
//   - ✅ End-entity certificate not expired
//
// **GREASE:**
//   - ✅ Always valid (RFC 9420 §13.5)
//
// # Example
//
//	cred := NewBasicCredentialFromString("alice")
//	if err := cred.Validate(); err != nil {
//	    return err // Invalid credential
//	}
func (c *Credential) Validate() error {
	switch c.CredentialType {
	case BasicCredential:
		return c.validateBasic()
	case X509Credential:
		return c.validateX509()
	default:
		if c.CredentialType.isGREASE() {
			// GREASE is always valid (RFC 9420 §13.5)
			return nil
		}
		return fmt.Errorf("unsupported credential type: 0x%04x", uint16(c.CredentialType))
	}
}

// validateBasic validates a BasicCredential.
//
// Checks:
//   - Identity non-empty
//   - Identity not too large (max 65535 bytes)
func (c *Credential) validateBasic() error {
	if len(c.Identity) == 0 {
		return errors.New("BasicCredential: identity cannot be empty")
	}

	if len(c.Identity) > 65535 {
		return errors.New("BasicCredential: identity too long (max 65535 bytes)")
	}

	return nil
}

// validateX509 validates an X509Credential.
//
// Checks:
//   - ✅ At least one certificate present
//   - ✅ All certificates are valid DER
//   - ✅ End-entity certificate not expired
//
// Note: Full chain validation requires trusted roots and is
// application-specific. Use ValidateX509Chain for that.
func (c *Credential) validateX509() error {
	if len(c.Certificates) == 0 {
		return errors.New("X509Credential: at least one certificate required")
	}

	// Validate end-entity certificate
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

	// Validate intermediate certificates (basic DER check)
	for i, certDER := range c.Certificates[1:] {
		_, err := x509.ParseCertificate(certDER)
		if err != nil {
			return fmt.Errorf("X509Credential: invalid intermediate certificate %d: %w", i+1, err)
		}
	}

	return nil
}

// ValidateX509Chain performs full X.509 chain validation.
//
// # Requirements
//
//   - Trusted root CA certificates (roots)
//   - Optional: Intermediate CA certificates
//   - Optional: DNS name or IP address to verify
//
// # What is validated
//
//   - ✅ Valid and complete chain
//   - ✅ All certificates not expired
//   - ✅ Valid cryptographic signatures
//   - ✅ Trusted root
//   - ✅ DNS name match (if provided)
//
// # Example
//
//	roots, err := x509.SystemCertPool()
//	if err != nil {
//	    return err
//	}
//	if err := cred.ValidateX509Chain(roots, "server.example.com"); err != nil {
//	    return err // Invalid or untrusted chain
//	}
func (c *Credential) ValidateX509Chain(roots *x509.CertPool, dnsName string) error {
	if err := c.validateX509(); err != nil {
		return err
	}

	// Parse certificates
	certs := make([]*x509.Certificate, len(c.Certificates))
	for i, certDER := range c.Certificates {
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return fmt.Errorf("parsing certificate %d: %w", i, err)
		}
		certs[i] = cert
	}

	// Build certificate chain
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	// Verify chain
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

// Hash computes the hash of a credential.
//
// Used for KeyPackage references and other identifiers.
// Hash(Credential) = SHA-256(MLSByte(credential_type) || credential_data)
//
// # Example
//
//	hash := cred.Hash()
//	// hash: []byte of 32 bytes (SHA-256)
func (c *Credential) Hash() []byte {
	data := c.Marshal()
	hash := sha256.Sum256(data)
	return hash[:]
}

// CredentialWithKey pairs a Credential with its signature key pair.
//
// Used when generating KeyPackages and signing MLS messages.
// The Credential identifies you, the keys allow you to sign.
//
// # Structure
//
// ```text
// ┌─────────────────────────────────────────┐
// │         CredentialWithKey               │
// ├─────────────────────────────────────────┤
// │  Credential:    your identity           │
// │  SignatureKey:  public key (P-256)      │
// │  PrivateKey:    private key (secret)    │
// └─────────────────────────────────────────┘
// ```text.
type CredentialWithKey struct {
	Credential        *Credential
	SignatureKey      *ecdsa.PublicKey
	PrivateKey        *ecdsa.PrivateKey  // Private key for signing (keep secret!) — nil for Ed25519
	Ed25519PrivateKey ed25519.PrivateKey // non-nil for CS1/CS3 (Ed25519 scheme)
	SignatureKeyBytes []byte             // raw public key bytes (works for both ECDSA and Ed25519)
}

// GenerateCredentialWithKey generates a new credential with associated key pair.
//
// Returns the credential with keys, and the private key separately for convenience.
// Store the private key securely and use it only for signing.
//
// Uses P-256 curve as required by MLS (RFC 9420 §5.1).
//
// # Example
//
//	credWithKey, privKey, err := GenerateCredentialWithKey([]byte("alice"))
//	if err != nil {
//	    return err
//	}
//	// Store privKey securely
//	// Use credWithKey to create KeyPackage
func GenerateCredentialWithKey(identity []byte) (*CredentialWithKey, *ecdsa.PrivateKey, error) {
	// Generate P-256 key pair (required for MLS)
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

// GenerateX509CredentialWithKey generates an X509Credential with its key pair.
//
// Useful for testing and entities requiring X.509 authentication
// (e.g., servers, gateways).
//
// Note: For production, certificates should be issued by a trusted CA.
func GenerateX509CredentialWithKey(certDER []byte, privKey *ecdsa.PrivateKey) (*CredentialWithKey, error) {
	cred := NewX509Credential([][]byte{certDER})

	return &CredentialWithKey{
		Credential:   cred,
		SignatureKey: &privKey.PublicKey,
		PrivateKey:   privKey,
	}, nil
}

// Sign signs data with the credential's private key.
//
// Signature format is ECDSA-SHA256 as required by MLS (RFC 9420 §5.1.2).
// Signature is encoded as R || S raw (64 bytes for P-256).
//
// # Signature Encoding
//
// ```text
// ┌─────────────────────────────────────────┐
// │      Signature (64 bytes)               │
// ├─────────────────────────────────────────┤
// │  R: 32 bytes (big-endian)               │
// │  S: 32 bytes (big-endian)               │
// └─────────────────────────────────────────┘
// ```
//
// Note: This differs from DER encoding. MLS uses raw encoding for efficiency.
//
// # Example
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

	// Encode as R || S (64 bytes for P-256)
	// FillBytes ensures always 32 bytes each
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])

	return signature, nil
}

// Verify verifies a signature using the credential's public key.
//
// Expects signature in R || S format (64 bytes for P-256).
// Returns true if signature is valid, false otherwise.
//
// # Example
//
//	valid := Verify(pubKey, data, signature)
//	if !valid {
//	    return errors.New("invalid signature")
//	}
func Verify(pubKey *ecdsa.PublicKey, data, signature []byte) bool {
	hash := sha256.Sum256(data)

	// Decode signature (R || S format, 64 bytes for P-256)
	if len(signature) != 64 {
		return false
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	return ecdsa.Verify(pubKey, hash[:], r, s)
}

// IsGREASE returns true if the credential is GREASE type.
//
// GREASE (Generate Random Extensions And Sustain Extensibility)
// ensures implementations handle unknown types gracefully.
// See RFC 9420 §13.5.
//
// GREASE values are: 0x0A0A, 0x1A1A, 0x2A2A, ..., 0xEAEA.
func (c *Credential) IsGREASE() bool {
	return c.CredentialType.isGREASE()
}

// Type returns the credential type.
//
// Useful for switch/case and logging.
func (c *Credential) Type() CredentialType {
	return c.CredentialType
}
