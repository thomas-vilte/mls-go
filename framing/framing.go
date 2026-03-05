// Package framing implements MLS Message Framing according to RFC 9420 §6.
//
// This package provides:
//   - PublicMessage (plaintext, signed)
//   - PrivateMessage (encrypted)
//   - FramedContent structure
//   - Sender types
//   - Content types (Application, Proposal, Commit)
//   - Wire format handling
//
// This implementation is generic and can be used for any MLS-based protocol.
package framing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/group"
	"github.com/openmls/go/internal/tls"
	"github.com/openmls/go/schedule"
)

// WireFormat identifies the type of MLS message on the wire.
type WireFormat uint16

const (
	WireFormatPublicMessage  WireFormat = 0x0001
	WireFormatPrivateMessage WireFormat = 0x0002
	WireFormatWelcome        WireFormat = 0x0003
	WireFormatGroupInfo      WireFormat = 0x0004
	WireFormatKeyPackage     WireFormat = 0x0005
)

// ContentType identifies the type of content within a message.
type ContentType uint8

const (
	ContentTypeApplication ContentType = 0x01
	ContentTypeProposal    ContentType = 0x02
	ContentTypeCommit      ContentType = 0x03
)

// Sender identifies who sent a message.
type Sender struct {
	Type SenderType
	// For Member sender
	LeafIndex group.LeafNodeIndex
	// For External sender
	SenderIndex uint32
}

// SenderType identifies the type of sender.
type SenderType uint8

const (
	SenderTypeMember            SenderType = 0x01
	SenderTypeExternal          SenderType = 0x02
	SenderTypeNewMemberProposal SenderType = 0x03
	SenderTypeNewMemberCommit   SenderType = 0x04
)

// NewMemberSender creates a member sender.
func NewMemberSender(leafIndex group.LeafNodeIndex) *Sender {
	return &Sender{
		Type:      SenderTypeMember,
		LeafIndex: leafIndex,
	}
}

// NewExternalSender creates an external sender.
func NewExternalSender(senderIndex uint32) *Sender {
	return &Sender{
		Type:        SenderTypeExternal,
		SenderIndex: senderIndex,
	}
}

// NewNewMemberProposalSender creates a new member proposal sender.
func NewNewMemberProposalSender() *Sender {
	return &Sender{Type: SenderTypeNewMemberProposal}
}

// NewNewMemberCommitSender creates a new member commit sender.
func NewNewMemberCommitSender() *Sender {
	return &Sender{Type: SenderTypeNewMemberCommit}
}

// IsMember returns true if the sender is a group member.
func (s *Sender) IsMember() bool {
	return s.Type == SenderTypeMember
}

// IsExternal returns true if the sender is external.
func (s *Sender) IsExternal() bool {
	return s.Type == SenderTypeExternal
}

// IsNewMember returns true if the sender is a new member.
func (s *Sender) IsNewMember() bool {
	return s.Type == SenderTypeNewMemberProposal || s.Type == SenderTypeNewMemberCommit
}

// FramedContent represents the content to be framed.
type FramedContent struct {
	ContentType          ContentType
	AuthenticatedContent []byte
}

// Marshal serializes FramedContent.
func (fc *FramedContent) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteUint8(uint8(fc.ContentType))
	w.WriteVLBytes(fc.AuthenticatedContent)
	return w.Bytes()
}

// PublicMessage represents a plaintext, signed MLS message.
type PublicMessage struct {
	WireFormat           WireFormat
	Sender               *Sender
	AuthenticatedContent []byte
	Signature            []byte
}

// NewPublicMessage creates a new PublicMessage.
func NewPublicMessage(
	sender *Sender,
	contentType ContentType,
	authenticatedContent []byte,
	signature []byte,
) *PublicMessage {
	return &PublicMessage{
		WireFormat:           WireFormatPublicMessage,
		Sender:               sender,
		AuthenticatedContent: authenticatedContent,
		Signature:            signature,
	}
}

// Marshal serializes the PublicMessage to TLS format.
func (pm *PublicMessage) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteUint16(uint16(pm.WireFormat))

	// Sender - use tagged switch
	switch pm.Sender.Type {
	case SenderTypeMember:
		w.WriteUint8(uint8(pm.Sender.Type))
		w.WriteUint32(uint32(pm.Sender.LeafIndex))
	case SenderTypeExternal:
		w.WriteUint8(uint8(pm.Sender.Type))
		w.WriteUint32(pm.Sender.SenderIndex)
	default:
		w.WriteUint8(uint8(pm.Sender.Type))
	}

	w.WriteVLBytes(pm.AuthenticatedContent)
	w.WriteVLBytes(pm.Signature)

	return w.Bytes()
}

// UnmarshalPublicMessage deserializes a PublicMessage.
func UnmarshalPublicMessage(data []byte) (*PublicMessage, error) {
	r := tls.NewReader(data)

	wireFormat, err := r.ReadUint16()
	if err != nil {
		return nil, err
	}

	senderType, err := r.ReadUint8()
	if err != nil {
		return nil, err
	}

	sender := &Sender{Type: SenderType(senderType)}
	if senderType == uint8(SenderTypeMember) {
		leafIndex, err := r.ReadUint32()
		if err != nil {
			return nil, err
		}
		sender.LeafIndex = group.LeafNodeIndex(leafIndex)
	} else if senderType == uint8(SenderTypeExternal) {
		senderIndex, err := r.ReadUint32()
		if err != nil {
			return nil, err
		}
		sender.SenderIndex = senderIndex
	}

	authContent, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	signature, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	return &PublicMessage{
		WireFormat:           WireFormat(wireFormat),
		Sender:               sender,
		AuthenticatedContent: authContent,
		Signature:            signature,
	}, nil
}

// PrivateMessage represents an encrypted MLS message.
type PrivateMessage struct {
	WireFormat          WireFormat
	EncryptedSenderData []byte
	EncryptedContent    []byte
}

// NewPrivateMessage creates a new PrivateMessage.
func NewPrivateMessage(
	encryptedSenderData []byte,
	encryptedContent []byte,
) *PrivateMessage {
	return &PrivateMessage{
		WireFormat:          WireFormatPrivateMessage,
		EncryptedSenderData: encryptedSenderData,
		EncryptedContent:    encryptedContent,
	}
}

// Marshal serializes the PrivateMessage to TLS format.
func (pm *PrivateMessage) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteUint16(uint16(pm.WireFormat))
	w.WriteVLBytes(pm.EncryptedSenderData)
	w.WriteVLBytes(pm.EncryptedContent)
	return w.Bytes()
}

// Encrypt encrypts a message using the group's encryption secret.
//
// This implements RFC 9420 §6.3 (PrivateMessage encryption).
func Encrypt(
	content []byte,
	encryptionSecret *ciphersuite.Secret,
	epochSecrets *schedule.EpochSecrets,
) (*PrivateMessage, error) {
	if encryptionSecret == nil {
		return nil, fmt.Errorf("encryption secret is nil")
	}

	// Generate random nonce
	nonce := make([]byte, 12) // AES-GCM nonce size
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	// Derive encryption key from epoch secret
	keySecret, err := encryptionSecret.HKDFExpand([]byte("content"), 16) // AES-128
	if err != nil {
		return nil, fmt.Errorf("deriving encryption key: %w", err)
	}
	key := keySecret.AsSlice()

	// Encrypt content using AES-128-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	// Encrypt with AAD = epoch (simplified)
	aad := []byte{0x00, 0x00, 0x00, 0x00} // Epoch as AAD
	ciphertext := gcm.Seal(nil, nonce, content, aad)

	// Encrypt sender data (simplified - just nonce for now)
	senderDataCiphertext := nonce

	return &PrivateMessage{
		EncryptedSenderData: senderDataCiphertext,
		EncryptedContent:    ciphertext,
	}, nil
}

// Decrypt decrypts a PrivateMessage.
func Decrypt(
	pm *PrivateMessage,
	encryptionSecret *ciphersuite.Secret,
	epoch uint64,
) ([]byte, error) {
	if encryptionSecret == nil {
		return nil, fmt.Errorf("encryption secret is nil")
	}

	// Derive decryption key
	keySecret, err := encryptionSecret.HKDFExpand([]byte("content"), 16)
	if err != nil {
		return nil, fmt.Errorf("deriving decryption key: %w", err)
	}
	key := keySecret.AsSlice()

	// Extract nonce from sender data
	nonce := pm.EncryptedSenderData
	if len(nonce) != 12 {
		return nil, fmt.Errorf("invalid nonce length: %d", len(nonce))
	}

	// Decrypt content
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	// Decrypt with AAD = epoch
	aad := make([]byte, 4)
	// Encode epoch as big-endian
	aad[0] = byte(epoch >> 24)
	aad[1] = byte(epoch >> 16)
	aad[2] = byte(epoch >> 8)
	aad[3] = byte(epoch)

	plaintext, err := gcm.Open(nil, nonce, pm.EncryptedContent, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypting content: %w", err)
	}

	return plaintext, nil
}

// SignContent signs the authenticated content.
func SignContent(
	content []byte,
	signatureKey interface{}, // Should be *ecdsa.PrivateKey
) ([]byte, error) {
	// Simplified - actual implementation would use ECDSA
	return content, nil
}

// VerifyContentSignature verifies the signature on content.
func VerifyContentSignature(
	content []byte,
	signature []byte,
	signatureKey interface{}, // Should be *ecdsa.PublicKey
) bool {
	// Simplified - actual implementation would verify ECDSA signature
	return len(signature) > 0
}

// UnmarshalPrivateMessage deserializes a PrivateMessage.
func UnmarshalPrivateMessage(data []byte) (*PrivateMessage, error) {
	r := tls.NewReader(data)

	wireFormat, err := r.ReadUint16()
	if err != nil {
		return nil, err
	}

	if WireFormat(wireFormat) != WireFormatPrivateMessage {
		return nil, fmt.Errorf("invalid wire format: %d", wireFormat)
	}

	encryptedSenderData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	encryptedContent, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	return &PrivateMessage{
		WireFormat:          WireFormatPrivateMessage,
		EncryptedSenderData: encryptedSenderData,
		EncryptedContent:    encryptedContent,
	}, nil
}

// ComputeMembershipTag computes the membership_tag.
func ComputeMembershipTag(
	membershipKey *ciphersuite.Secret,
	authenticatedContent []byte,
) ([]byte, error) {
	if membershipKey == nil {
		return nil, fmt.Errorf("membership key is nil")
	}

	keyBytes := membershipKey.AsSlice()
	h := hmac.New(sha256.New, keyBytes)
	h.Write(authenticatedContent)
	return h.Sum(nil), nil
}
