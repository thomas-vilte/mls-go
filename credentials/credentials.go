// Package credentials implements MLS credential types.
//
// Credentials are used to authenticate group members and verify signatures.
// This package implements BasicCredential as defined in RFC 9420 §11.2.
package credentials

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/openmls/go/internal/tls"
)

// CredentialType represents the type of credential.
type CredentialType uint16

const (
	// BasicCredential is the simplest credential type (RFC 9420 §11.2.1).
	BasicCredential CredentialType = 0x0001
)

// Credential represents an MLS credential.
//
// Credentials authenticate group members and contain identity information.
type Credential struct {
	CredentialType CredentialType
	Identity       []byte // For BasicCredential: opaque identity<V>
}

// NewBasicCredential creates a new BasicCredential.
//
// BasicCredential contains an opaque identity byte string.
// Common formats include:
//   - User ID as big-endian uint64 (8 bytes)
//   - Username as UTF-8 string
//   - Email address as UTF-8 string
func NewBasicCredential(identity []byte) *Credential {
	return &Credential{
		CredentialType: BasicCredential,
		Identity:       identity,
	}
}

// NewBasicCredentialFromString creates a BasicCredential from a string identity.
func NewBasicCredentialFromString(identity string) *Credential {
	return NewBasicCredential([]byte(identity))
}

// NewBasicCredentialFromUint64 creates a BasicCredential from a uint64 ID.
//
// The ID is encoded as big-endian (network byte order).
func NewBasicCredentialFromUint64(id uint64) *Credential {
	identity := make([]byte, 8)
	binary.BigEndian.PutUint64(identity, id)
	return NewBasicCredential(identity)
}

// Marshal serializes the Credential to TLS format.
//
// struct {
//   CredentialType credential_type;
//   select (credential_type) {
//     case basic: opaque identity<V>;
//   } credential;
// } Credential;
func (c *Credential) Marshal() []byte {
	buf := tls.NewWriter()
	buf.WriteUint16(uint16(c.CredentialType))
	buf.WriteVLBytes(c.Identity)
	return buf.Bytes()
}

// UnmarshalCredential parses a Credential from TLS format.
func UnmarshalCredential(data []byte) (*Credential, error) {
	buf := tls.NewReader(data)

	credType, err := buf.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("reading credential_type: %w", err)
	}

	identity, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading identity: %w", err)
	}

	return &Credential{
		CredentialType: CredentialType(credType),
		Identity:       identity,
	}, nil
}

// IdentityString returns the identity as a string.
//
// For numeric IDs (8 bytes), returns the decimal representation.
// For other formats, returns the UTF-8 string.
func (c *Credential) IdentityString() string {
	if c.CredentialType != BasicCredential {
		return ""
	}

	// Try to decode as uint64 if it's 8 bytes
	if len(c.Identity) == 8 {
		id := binary.BigEndian.Uint64(c.Identity)
		return fmt.Sprintf("%d", id)
	}

	return string(c.Identity)
}

// CredentialWithKey pairs a Credential with its signature key pair.
//
// This is used when generating KeyPackages and signing MLS messages.
type CredentialWithKey struct {
	Credential   *Credential
	SignatureKey *ecdsa.PublicKey
	PrivateKey   *ecdsa.PrivateKey // Private key for signing
}

// GenerateCredentialWithKey generates a new credential with an associated signature key pair.
//
// Returns the credential with keys, and the private key separately for convenience.
// The private key must be kept secret and used for signing.
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

// Sign signs data with the credential's private key.
//
// The signature format is ECDSA-SHA256 as required by MLS.
func Sign(privKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	// Encode as DER
	signature := append(r.Bytes(), s.Bytes()...)
	return signature, nil
}

// Verify verifies a signature using the credential's public key.
func Verify(pubKey *ecdsa.PublicKey, data, signature []byte) bool {
	hash := sha256.Sum256(data)

	// Decode signature (R || S format, 64 bytes for P-256)
	if len(signature) < 64 {
		return false
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	return ecdsa.Verify(pubKey, hash[:], r, s)
}

// Hash computes the hash of a credential.
//
// This is used for KeyPackage references and other identifiers.
func (c *Credential) Hash() []byte {
	data := c.Marshal()
	hash := sha256.Sum256(data)
	return hash[:]
}

// Validate validates the credential according to MLS rules.
func (c *Credential) Validate() error {
	if c.CredentialType != BasicCredential {
		return errors.New("unsupported credential type")
	}

	if len(c.Identity) == 0 {
		return errors.New("identity cannot be empty")
	}

	if len(c.Identity) > 65535 {
		return errors.New("identity too long")
	}

	return nil
}
