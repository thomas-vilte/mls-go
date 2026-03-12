// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE file.

// Package extensions - External Senders Extension (RFC 9420 §12.1.8.1)
package extensions

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/internal/tls"
)

// ExternalSender represents an external sender allowed to send proposals.
//
// External senders are entities that can send proposals to a group without
// being full members. This is used by DAVE (Discord Audio Voice Encryption)
// to allow the delivery service to manage group membership.
//
// # Structure (RFC 9420 §12.1.8.1)
//
// ```text
//
//	struct {
//	    SignaturePublicKey credential_public_key;
//	    opaque credential<V>;
//	} ExternalSender;
//
// ```
//
// # Location
//
// - **KeyPackage**: No ❌
// - **GroupInfo**: No ❌
// - **GroupContext**: Yes ✅
//
// # Purpose
//
// External senders allow non-members to send proposals to a group.
// This is useful for:
//   - Delivery services managing group membership
//   - Bots or automated systems
//   - Gateway services
type ExternalSender struct {
	Credential     *credentials.Credential
	PublicKey      *ecdsa.PublicKey // Signature public key
	publicKeyBytes []byte           // Raw bytes of the public key
}

// ExternalSendersExtension contains a list of external senders.
//
// # Structure (RFC 9420 §12.1.8.1)
//
// ```text
//
//	struct {
//	    ExternalSender senders<V>;
//	} ExternalSendersExtension;
//
// ```
//
// # Example
//
// // Create extension
// ext := NewExternalSendersExtension()
//
// // Add sender
//
//	sender := ExternalSender{
//	    Credential: cred,
//	    PublicKey:  pubKey,
//	}
//
//	if err := ext.AddSender(sender); err != nil {
//	    return err
//	}
//
// // Validate
//
//	if err := ext.Validate(); err != nil {
//	    return err
//	}
//
// // Serialize
// data := ext.Marshal()
type ExternalSendersExtension struct {
	Senders []ExternalSender
}

// NewExternalSendersExtension creates a new ExternalSendersExtension.
func NewExternalSendersExtension() *ExternalSendersExtension {
	return &ExternalSendersExtension{
		Senders: make([]ExternalSender, 0),
	}
}

// AddSender adds an external sender to the extension.
func (e *ExternalSendersExtension) AddSender(sender ExternalSender) error {
	// Extract public key bytes if not already set
	if len(sender.publicKeyBytes) == 0 && sender.PublicKey != nil {
		ecdhKey, err := sender.PublicKey.ECDH()
		if err == nil {
			sender.publicKeyBytes = ecdhKey.Bytes()
		}
	}

	if err := sender.Validate(); err != nil {
		return fmt.Errorf("invalid sender: %w", err)
	}

	e.Senders = append(e.Senders, sender)
	return nil
}

// FindSender finds an external sender by credential.
func (e *ExternalSendersExtension) FindSender(cred *credentials.Credential) (*ExternalSender, bool) {
	for i := range e.Senders {
		if e.Senders[i].Credential != nil && cred != nil {
			if bytes.Equal(e.Senders[i].Credential.Marshal(), cred.Marshal()) {
				return &e.Senders[i], true
			}
		}
	}
	return nil, false
}

// FindSenderByPublicKey finds an external sender by public key.
func (e *ExternalSendersExtension) FindSenderByPublicKey(pubKey *ecdsa.PublicKey) (*ExternalSender, bool) {
	if pubKey == nil {
		return nil, false
	}

	// Convert input key to ECDH for comparison
	ecdhKey2, err2 := pubKey.ECDH()
	if err2 != nil {
		return nil, false
	}

	for i := range e.Senders {
		if len(e.Senders[i].publicKeyBytes) > 0 {
			// Compare using raw bytes
			if bytes.Equal(e.Senders[i].publicKeyBytes, ecdhKey2.Bytes()) {
				return &e.Senders[i], true
			}
		}
	}
	return nil, false
}

// Marshal serializes the ExternalSendersExtension to TLS format.
//
// # Encoding
//
// ```text
// ┌─────────────────────────────────────────────────────────────┐
// │      ExternalSendersExtension Encoding                      │
// ├─────────────────────────────────────────────────────────────┤
// │  senders<V>                                                 │
// │    ├─ public_key<V>  : opaque (ECDSA uncompressed point)    │
// │    └─ credential<V>  : opaque (Credential encoding)         │
// └─────────────────────────────────────────────────────────────┘
// ```
func (e *ExternalSendersExtension) Marshal() []byte {
	buf := tls.NewWriter()

	// senders<V>
	sendersBuf := tls.NewWriter()
	for _, sender := range e.Senders {
		// SignaturePublicKey (ECDSA uncompressed point)
		switch {
		case len(sender.publicKeyBytes) > 0:
			sendersBuf.WriteVLBytes(sender.publicKeyBytes)
		case sender.PublicKey != nil:
			// Fallback: convert from ecdsa.PublicKey
			ecdhKey, err := sender.PublicKey.ECDH()
			if err == nil {
				sendersBuf.WriteVLBytes(ecdhKey.Bytes())
			} else {
				sendersBuf.WriteVLBytes([]byte{})
			}
		default:
			sendersBuf.WriteVLBytes([]byte{})
		}

		// credential<V>
		if sender.Credential != nil {
			sendersBuf.WriteVLBytes(sender.Credential.Marshal())
		} else {
			sendersBuf.WriteVLBytes([]byte{})
		}
	}
	buf.WriteVLBytes(sendersBuf.Bytes())

	return buf.Bytes()
}

// UnmarshalExternalSendersExtension parses an ExternalSendersExtension from TLS format.
//
// # Decoding
//
// Reads a vector of ExternalSender structures.
//
// # Example
//
// data := []byte{...}  // serialized data
// ext, err := UnmarshalExternalSendersExtension(data)
//
//	if err != nil {
//	    return err
//	}
//
// // ext.Senders contains parsed senders
func UnmarshalExternalSendersExtension(data []byte) (*ExternalSendersExtension, error) {
	ext := NewExternalSendersExtension()

	if len(data) == 0 {
		return ext, nil
	}

	buf := tls.NewReader(data)

	for buf.Remaining() > 0 {
		// SignaturePublicKey<V>
		pubKeyBytes, err := buf.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading public_key: %w", err)
		}

		var pubKey *ecdsa.PublicKey
		if len(pubKeyBytes) > 0 {
			pubKey, err = unmarshalECDSAPublicKey(pubKeyBytes)
			if err != nil {
				return nil, fmt.Errorf("parsing public key: %w", err)
			}
		}

		// credential<V>
		credBytes, err := buf.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading credential: %w", err)
		}

		var cred *credentials.Credential
		if len(credBytes) > 0 {
			cred, err = credentials.UnmarshalCredential(credBytes)
			if err != nil {
				return nil, fmt.Errorf("parsing credential: %w", err)
			}
		}

		sender := ExternalSender{
			Credential:     cred,
			PublicKey:      pubKey,
			publicKeyBytes: pubKeyBytes,
		}

		if err := ext.AddSender(sender); err != nil {
			return nil, fmt.Errorf("adding sender: %w", err)
		}
	}

	return ext, nil
}

// Validate validates the ExternalSendersExtension.
func (e *ExternalSendersExtension) Validate() error {
	for i, sender := range e.Senders {
		if err := sender.Validate(); err != nil {
			return fmt.Errorf("sender %d invalid: %w", i, err)
		}
	}

	return nil
}

// Validate validates an ExternalSender.
//
// # Validation Rules
//
// - Credential must not be nil
// - PublicKey must not be nil
// - Credential must be valid
func (s *ExternalSender) Validate() error {
	if s.Credential == nil {
		return errors.New("credential is nil")
	}

	if s.PublicKey == nil {
		return errors.New("public_key is nil")
	}

	if err := s.Credential.Validate(); err != nil {
		return fmt.Errorf("invalid credential: %w", err)
	}

	return nil
}

// Len returns the number of external senders.
func (e *ExternalSendersExtension) Len() int {
	return len(e.Senders)
}

// Equal compares two ExternalSendersExtensions for equality.
func (e *ExternalSendersExtension) Equal(other *ExternalSendersExtension) bool {
	if e == nil || other == nil {
		return e == other
	}

	if len(e.Senders) != len(other.Senders) {
		return false
	}

	for i := range e.Senders {
		if !e.Senders[i].Equal(&other.Senders[i]) {
			return false
		}
	}

	return true
}

// Equal compares two ExternalSenders for equality.
func (s *ExternalSender) Equal(other *ExternalSender) bool {
	if s == nil || other == nil {
		return s == other
	}

	if !credentialsEqual(s.Credential, other.Credential) {
		return false
	}

	if !ecdsaPublicKeyEqual(s.PublicKey, other.PublicKey) {
		return false
	}

	return true
}

// ExtensionType returns the type code for this extension.
func (e *ExternalSendersExtension) ExtensionType() ExtensionType {
	return ExtensionTypeExternalSenders
}

// ToExtension converts this to a generic Extension.
func (e *ExternalSendersExtension) ToExtension() (*Extension, error) {
	data := e.Marshal()
	return &Extension{
		Type: ExtensionTypeExternalSenders,
		Data: data,
	}, nil
}

// FromExternalSendersExtension creates an ExternalSendersExtension from a generic Extension.
func FromExternalSendersExtension(ext *Extension) (*ExternalSendersExtension, error) {
	if ext.Type != ExtensionTypeExternalSenders {
		return nil, fmt.Errorf("wrong extension type: %d", ext.Type)
	}

	return UnmarshalExternalSendersExtension(ext.Data)
}

// Helper functions

func unmarshalECDSAPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	if len(data) != 65 || data[0] != 0x04 {
		return nil, errors.New("invalid ECDSA public key format")
	}
	return &ecdsa.PublicKey{}, nil
}

func credentialsEqual(a, b *credentials.Credential) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return bytes.Equal(a.Marshal(), b.Marshal())
}

func ecdsaPublicKeyEqual(a, b *ecdsa.PublicKey) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	ecdhA, errA := a.ECDH()
	ecdhB, errB := b.ECDH()
	if errA == nil && errB == nil {
		return bytes.Equal(ecdhA.Bytes(), ecdhB.Bytes())
	}
	// If ECDH conversion fails, keys cannot be compared
	return false
}
