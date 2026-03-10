package framing

import (
	"fmt"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/internal/tls"
	keypackages "github.com/openmls/go/keypackages"
)

// FramedContentAuthData implementa RFC 9420 §6.1.
// ConfirmationTag es no-nil únicamente cuando ContentType == Commit.
type FramedContentAuthData struct {
	Signature       *ciphersuite.Signature // message signature
	ConfirmationTag []byte                 // nil unless content_type == commit
}

// Marshal serializa los datos de autenticación; incluye confirmation_tag únicamente para Commit.
func (a *FramedContentAuthData) Marshal(ct ContentType) []byte {
	w := tls.NewWriter()
	var sigBytes []byte
	if a.Signature != nil {
		sigBytes = a.Signature.AsSlice()
	}
	w.WriteVLBytes(sigBytes)
	if ct == ContentTypeCommit && len(a.ConfirmationTag) > 0 {
		w.WriteVLBytes(a.ConfirmationTag)
	}
	return w.Bytes()
}

// AuthenticatedContent implementa RFC 9420 §6.1.
// Es el input del proceso de firma, no se envía directamente por el wire.
type AuthenticatedContent struct {
	WireFormat   WireFormat
	Content      FramedContent
	Auth         FramedContentAuthData
	GroupContext []byte // serialized GroupContext; required for PublicMessage TBS; nil for PrivateMessage
}

// Marshal serializes AuthenticatedContent for ProposalRef computation (RFC 9420 §12.4).
// wire_format || FramedContent || FramedContentAuthData
func (ac *AuthenticatedContent) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteUint16(uint16(ac.WireFormat))
	w.WriteRaw(ac.Content.Marshal())
	w.WriteRaw(ac.Auth.Marshal(ac.Content.ContentType()))
	return w.Bytes()
}

// MarshalForSigning serializa wire_format + content (utilizado en membership tag TBM).
func (ac *AuthenticatedContent) MarshalForSigning() []byte {
	w := tls.NewWriter()
	w.WriteUint16(uint16(ac.WireFormat))
	w.WriteRaw(ac.Content.Marshal())
	return w.Bytes()
}

// MarshalTBS serializa FramedContentTBS para firmar (RFC 9420 §6.1).
//
//	struct {
//	    ProtocolVersion version = mls10;
//	    WireFormat wire_format;
//	    FramedContent content;
//	    select (FramedContent.sender.sender_type) {
//	        case member:
//	        case new_member_commit:  GroupContext group_context;
//	        case external:
//	        case new_member_proposal: struct{};
//	    };
//	} FramedContentTBS;
func (ac *AuthenticatedContent) MarshalTBS() []byte {
	w := tls.NewWriter()
	w.WriteUint16(uint16(keypackages.MLS10)) // version = mls10
	w.WriteUint16(uint16(ac.WireFormat))
	w.WriteRaw(ac.Content.Marshal())
	// RFC §6.1: GroupContext incluido cuando sender_type == member o new_member_commit
	st := ac.Content.Sender.Type
	if (st == SenderTypeMember || st == SenderTypeNewMemberCommit) && len(ac.GroupContext) > 0 {
		w.WriteRaw(ac.GroupContext)
	}
	return w.Bytes()
}

// UnmarshalAuthenticatedContent parsea un AuthenticatedContent desde su representación wire:
// WireFormat (uint16) + FramedContent + FramedContentAuthData (signature [+ confirmation_tag for commit]).
// Este formato es el usado en transcript-hashes test vectors.
func UnmarshalAuthenticatedContent(data []byte) (*AuthenticatedContent, error) {
	r := tls.NewReader(data)

	wf, err := r.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("framing: reading wire_format: %w", err)
	}

	content, err := unmarshalFramedContentFromReaderWithMode(r, true, false)
	if err != nil {
		return nil, fmt.Errorf("framing: reading framed_content: %w", err)
	}

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

	return &AuthenticatedContent{
		WireFormat: WireFormat(wf),
		Content:    *content,
		Auth:       auth,
	}, nil
}

// PrivateMessageContent es el plaintext que se encripta con AEAD en un PrivateMessage (RFC 9420 §6.3).
//
//	struct {
//	    select (content_type) {
//	        case application:  ApplicationData application_data;
//	        case proposal:     Proposal proposal;
//	        case commit:       Commit commit;
//	    }
//	    FramedContentAuthData auth;
//	    opaque padding[length_of_padding];  // currently always 0
//	} PrivateMessageContent;
type PrivateMessageContent struct {
	Body FramedContentBody
	Auth FramedContentAuthData
}

// marshalPrivateMessageContent serializa el plaintext para encriptación de PrivateMessage.
// paddingSize == 0 significa sin padding; > 0 agrega ceros para alinear al bloque (RFC §6.3).
func marshalPrivateMessageContent(body FramedContentBody, auth FramedContentAuthData, paddingSize int) []byte {
	w := tls.NewWriter()
	body.marshal(w)
	w.WriteRaw(auth.Marshal(body.ContentType()))
	if paddingSize > 0 {
		// padding_length = (paddingSize - (plaintext_len % paddingSize)) % paddingSize
		plainLen := len(w.Bytes())
		padLen := (paddingSize - (plainLen % paddingSize)) % paddingSize
		w.WriteRaw(make([]byte, padLen)) // RFC §6.3: padding MUST be all-zero
	}
	return w.Bytes()
}

// unmarshalPrivateMessageContent parsea el plaintext descifrado de PrivateMessage.
func unmarshalPrivateMessageContent(data []byte, ct ContentType) (*PrivateMessageContent, error) {
	r := tls.NewReader(data)

	body, err := readFramedContentBody(r, ct, false, true)
	if err != nil {
		return nil, err
	}

	sigBytes, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("framing: reading signature: %w", err)
	}
	auth := FramedContentAuthData{Signature: ciphersuite.NewSignature(sigBytes)}

	// confirmation_tag presente solo para Commit
	if ct == ContentTypeCommit && r.Remaining() > 0 {
		tag, err := r.ReadVLBytes()
		if err == nil && len(tag) > 0 {
			auth.ConfirmationTag = tag
		}
	}

	// RFC §6.3: los bytes restantes son padding, deben ser todos cero
	for r.Remaining() > 0 {
		b, err := r.ReadUint8()
		if err != nil {
			return nil, fmt.Errorf("framing: reading padding: %w", err)
		}
		if b != 0 {
			return nil, fmt.Errorf("%w: non-zero padding byte", ErrInvalidMessage)
		}
	}

	return &PrivateMessageContent{Body: body, Auth: auth}, nil
}
