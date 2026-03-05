// Package extensions - External Senders Extension (RFC 9420 §12.4.3.2, DAVE)
package extensions

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/openmls/go/credentials"
	"github.com/openmls/go/internal/tls"
)

// ExternalSender represents an external sender allowed to send proposals.
//
// External senders are entities that can send proposals to a group without
// being full members. This is used by DAVE (Discord Audio Voice Encryption)
// to allow the delivery service to manage group membership.
//
// struct {
//     SignaturePublicKey credential_public_key;
//     opaque credential<V>;
// } ExternalSender;
type ExternalSender struct {
	Credential *credentials.Credential
	PublicKey  *ecdsa.PublicKey // Signature public key
}

// ExternalSendersExtension contains a list of external senders.
//
// struct {
//     ExternalSender senders<V>;
// } ExternalSendersExtension;
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
	for i := range e.Senders {
		if e.Senders[i].PublicKey != nil && pubKey != nil {
			if e.Senders[i].PublicKey.X.Cmp(pubKey.X) == 0 &&
				e.Senders[i].PublicKey.Y.Cmp(pubKey.Y) == 0 {
				return &e.Senders[i], true
			}
		}
	}
	return nil, false
}

// Marshal serializes the ExternalSendersExtension to TLS format.
func (e *ExternalSendersExtension) Marshal() []byte {
	buf := tls.NewWriter()

	// senders<V>
	sendersBuf := tls.NewWriter()
	for _, sender := range e.Senders {
		// SignaturePublicKey (ECDSA uncompressed point)
		if sender.PublicKey != nil {
			pubKeyBytes := append([]byte{0x04}, sender.PublicKey.X.Bytes()...)
			pubKeyBytes = append(pubKeyBytes, sender.PublicKey.Y.Bytes()...)
			sendersBuf.WriteVLBytes(pubKeyBytes)
		} else {
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
			Credential: cred,
			PublicKey:  pubKey,
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

// FromExtension creates an ExternalSendersExtension from a generic Extension.
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

	x := new(big.Int).SetBytes(data[1:33])
	y := new(big.Int).SetBytes(data[33:65])

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	if !pubKey.IsOnCurve(x, y) {
		return nil, errors.New("public key is not on curve P-256")
	}

	return pubKey, nil
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
	return a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0
}
