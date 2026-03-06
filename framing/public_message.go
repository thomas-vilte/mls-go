package framing

import (
	"fmt"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/group"
	"github.com/openmls/go/internal/tls"
	"github.com/openmls/go/schedule"
)

// PublicMessage implementa RFC 9420 §6.2.
// Es un mensaje MLS sin cifrar y firmado.
type PublicMessage struct {
	Content       FramedContent
	Auth          FramedContentAuthData
	MembershipTag []byte // only for sender_type == member
}

// NewPublicMessage crea y firma un PublicMessage.
//
// gc es requerido para firmar (incluido en FramedContentTBS según RFC §6.1).
// membershipKey es nil para remitentes que no son miembros.
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

	// membership_tag únicamente para remitentes miembro (RFC §6.2)
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

// VerifyMembershipTag verifica el membership_tag utilizando schedule.VerifyMembershipTag.
func (pm *PublicMessage) VerifyMembershipTag(membershipKey *ciphersuite.Secret) error {
	if pm.Content.Sender.Type != SenderTypeMember {
		return nil // no aplica para remitentes que no son miembros
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

// Marshal serializa el PublicMessage para transmisión.
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

// UnmarshalPublicMessage parsea un PublicMessage desde su representación wire.
// El wire_format uint16 inicial debe estar incluido en los datos.
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

	// Auth: signature<V> [ + confirmation_tag<V> si es Commit ]
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

	// membership_tag presente únicamente para remitente miembro
	if content.Sender.Type == SenderTypeMember && r.Remaining() > 0 {
		tag, err := r.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("framing: reading membership_tag: %w", err)
		}
		pm.MembershipTag = tag
	}

	return pm, nil
}
