package framing

import (
	"fmt"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/group"
	"github.com/openmls/go/internal/tls"
	"github.com/openmls/go/schedule"
)

// PublicMessage implements RFC 9420 §6.2.
// It is an unencrypted, signed MLS message.
type PublicMessage struct {
	Content       FramedContent
	Auth          FramedContentAuthData
	MembershipTag []byte // only for sender_type == member
}

// NewPublicMessage creates and signs a PublicMessage.
//
// gc is required for signing (included in FramedContentTBS per RFC §6.1).
// membershipKey is nil for non-Member senders.
func NewPublicMessage(
	content FramedContent,
	sigKey *ciphersuite.SignaturePrivateKey,
	gc *group.GroupContext,
	membershipKey *ciphersuite.Secret,
) (*PublicMessage, error) {
	ac := &AuthenticatedContent{
		WireFormat:   WireFormatPublicMessage,
		Content:      content,
		GroupContext: gc,
	}
	sig, err := ciphersuite.SignWithLabel(sigKey, "FramedContentTBS", ac.MarshalTBS())
	if err != nil {
		return nil, fmt.Errorf("framing: signing content: %w", err)
	}
	auth := FramedContentAuthData{Signature: sig}
	pm := &PublicMessage{Content: content, Auth: auth}

	// membership_tag only for Member senders (RFC §6.2)
	if content.Sender.Type == SenderTypeMember && membershipKey != nil {
		ac.Auth = auth
		tbm := marshalAuthenticatedContentTBM(ac)
		tag, err := membershipKey.Hmac(tbm)
		if err != nil {
			return nil, fmt.Errorf("framing: computing membership_tag: %w", err)
		}
		pm.MembershipTag = tag
	}
	return pm, nil
}

// VerifyMembershipTag verifies the membership_tag using schedule.VerifyMembershipTag.
func (pm *PublicMessage) VerifyMembershipTag(membershipKey *ciphersuite.Secret) error {
	if pm.Content.Sender.Type != SenderTypeMember {
		return nil // not applicable for non-Member senders
	}
	ac := &AuthenticatedContent{
		WireFormat: WireFormatPublicMessage,
		Content:    pm.Content,
		Auth:       pm.Auth,
	}
	tbm := marshalAuthenticatedContentTBM(ac)
	if !schedule.VerifyMembershipTag(membershipKey.AsSlice(), tbm, pm.MembershipTag) {
		return ErrInvalidMembershipTag
	}
	return nil
}

// Marshal serializes the PublicMessage for transmission.
func (pm *PublicMessage) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteUint16(uint16(WireFormatPublicMessage))
	w.WriteRaw(pm.Content.Marshal())
	w.WriteRaw(pm.Auth.Marshal(pm.Content.ContentType()))
	if pm.Content.Sender.Type == SenderTypeMember {
		w.WriteVLBytes(pm.MembershipTag)
	}
	return w.Bytes()
}

// UnmarshalPublicMessage parses a PublicMessage from its wire representation.
// The leading wire_format uint16 must be included in data.
func UnmarshalPublicMessage(data []byte) (*PublicMessage, error) {
	r := tls.NewReader(data)

	wf, err := r.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("framing: reading wire_format: %w", err)
	}
	if WireFormat(wf) != WireFormatPublicMessage {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidWireFormat, wf)
	}

	content, err := unmarshalFramedContentFromReader(r)
	if err != nil {
		return nil, err
	}

	// Auth: signature<V> [ + confirmation_tag<V> if Commit ]
	sigBytes, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("framing: reading signature: %w", err)
	}
	auth := FramedContentAuthData{Signature: ciphersuite.NewSignature(sigBytes)}
	if content.ContentType() == ContentTypeCommit && r.Remaining() > 0 {
		tag, err := r.ReadVLBytes()
		if err == nil && len(tag) > 0 {
			auth.ConfirmationTag = tag
		}
	}

	pm := &PublicMessage{Content: *content, Auth: auth}

	// membership_tag present only for Member sender
	if content.Sender.Type == SenderTypeMember && r.Remaining() > 0 {
		tag, err := r.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("framing: reading membership_tag: %w", err)
		}
		pm.MembershipTag = tag
	}

	return pm, nil
}
