package framing

import (
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/internal/tls"
	"github.com/thomas-vilte/mls-go/schedule"
)

// PublicMessage implements RFC 9420 §6.2.
// A PublicMessage is an MLS message transmitted in cleartext with signatures.
//
// Structure:
//
//	struct {
//	    FramedContent content;
//	    FramedContentAuthData auth;
//	    select (sender.sender_type) {
//	        case member:  MAC membership_tag;
//	        case external:
//	        case new_member_proposal:
//	        case new_member_commit:  struct{};
//	    };
//	} PublicMessage;
type PublicMessage struct {
	Content       FramedContent
	Auth          FramedContentAuthData
	MembershipTag []byte // only for sender_type == member
}

// NewPublicMessage creates and signs a PublicMessage.
//
// gc is required for signing (included in FramedContentTBS per RFC §6.1).
// membershipKey is nil for non-member senders.
func NewPublicMessage(
	content FramedContent,
	sigKey *ciphersuite.SignaturePrivateKey,
	gc []byte, // serialized GroupContext
	membershipKey *ciphersuite.Secret,
	cs ciphersuite.CipherSuite,
) (*PublicMessage, error) {
	// RFC §6.1: sender/content-type compatibility
	if err := validateSenderContentType(content.Sender.Type, content.ContentType()); err != nil {
		return nil, err
	}
	// RFC §6.1: GroupContext required for member and new_member_commit senders
	st := content.Sender.Type
	if (st == SenderTypeMember || st == SenderTypeNewMemberCommit) && len(gc) == 0 {
		return nil, fmt.Errorf("%w: required when signing for sender type %d", ErrMissingGroupContext, st)
	}

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

	// membership_tag only for member senders (RFC §6.2)
	if content.Sender.Type == SenderTypeMember && membershipKey != nil {
		ac.Auth = auth
		tbm := marshalAuthenticatedContentTBM(ac)
		tag := schedule.ComputeMembershipTag(cs, membershipKey.AsSlice(), tbm)
		pm.MembershipTag = tag
	}
	return pm, nil
}

// VerifyMembershipTag verifies the membership_tag using schedule.VerifyMembershipTag.
func (pm *PublicMessage) VerifyMembershipTag(cs ciphersuite.CipherSuite, membershipKey *ciphersuite.Secret) error {
	return pm.VerifyMembershipTagWithContext(cs, membershipKey, nil)
}

// VerifyMembershipTagWithContext verifies membership_tag using the provided GroupContext bytes.
func (pm *PublicMessage) VerifyMembershipTagWithContext(
	cs ciphersuite.CipherSuite,
	membershipKey *ciphersuite.Secret,
	gc []byte,
) error {
	if pm.Content.Sender.Type != SenderTypeMember {
		return nil // Not applicable for non-member senders
	}
	ac := &AuthenticatedContent{
		WireFormat:   WireFormatPublicMessage,
		Content:      pm.Content,
		Auth:         pm.Auth,
		GroupContext: gc,
	}
	tbm := marshalAuthenticatedContentTBM(ac)
	if !schedule.VerifyMembershipTag(cs, membershipKey.AsSlice(), tbm, pm.MembershipTag) {
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
// The initial wire_format uint16 must be included in the data.
func UnmarshalPublicMessage(data []byte) (*PublicMessage, error) {
	r := tls.NewReader(data)

	wf, err := r.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("framing: reading wire_format: %w", err)
	}
	if WireFormat(wf) != WireFormatPublicMessage {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidWireFormat, wf)
	}

	content, err := unmarshalFramedContentFromReaderWithMode(r, true, true)
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

	// RFC §6.2: membership_tag MUST be present for member senders
	if content.Sender.Type == SenderTypeMember {
		if r.Remaining() == 0 {
			return nil, fmt.Errorf("framing: missing membership_tag for member sender")
		}
		tag, err := r.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("framing: reading membership_tag: %w", err)
		}
		pm.MembershipTag = tag
	}

	return pm, nil
}
