package framing

import (
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/internal/tls"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// FramedContentAuthData represents authentication data for framed content (RFC 9420 §6.1).
//
// Structure:
//
//	struct {
//	    opaque signature<V>;
//	    select (content_type) {
//	        case commit:  MAC confirmation_tag;
//	        default:      struct{};
//	    };
//	} FramedContentAuthData;
//
// ConfirmationTag is non-nil only when ContentType == Commit.
type FramedContentAuthData struct {
	Signature       *ciphersuite.Signature // Message signature
	ConfirmationTag []byte                 // nil unless content_type == commit
}

// Marshal serializes the authentication data.
// Includes confirmation_tag only for Commit content type.
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

// AuthenticatedContent represents authenticated framed content (RFC 9420 §6.1).
//
// This structure is the input to the signing process. It is not sent directly
// on the wire but serialized as part of transcript hashes or signature inputs.
//
// Structure:
//
//	struct {
//	    WireFormat wire_format;
//	    FramedContent content;
//	    FramedContentAuthData auth;
//	} AuthenticatedContent;
type AuthenticatedContent struct {
	WireFormat   WireFormat
	Content      FramedContent
	Auth         FramedContentAuthData
	GroupContext []byte // serialized GroupContext; required for PublicMessage TBS; nil for PrivateMessage
}

// Marshal serializes AuthenticatedContent for ProposalRef computation (RFC 9420 §12.4).
// Format: wire_format || FramedContent || FramedContentAuthData
func (ac *AuthenticatedContent) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteUint16(uint16(ac.WireFormat))
	w.WriteRaw(ac.Content.Marshal())
	w.WriteRaw(ac.Auth.Marshal(ac.Content.ContentType()))
	return w.Bytes()
}

// MarshalForSigning serializes wire_format + content (used for membership tag TBM).
func (ac *AuthenticatedContent) MarshalForSigning() []byte {
	w := tls.NewWriter()
	w.WriteUint16(uint16(ac.WireFormat))
	w.WriteRaw(ac.Content.Marshal())
	return w.Bytes()
}

// MarshalTBS serializes FramedContentTBS for signing (RFC 9420 §6.1).
//
// Structure:
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
	w.WriteUint16(uint16(keypackages.MLS10)) // MLS protocol version: mls10
	w.WriteUint16(uint16(ac.WireFormat))
	w.WriteRaw(ac.Content.Marshal())
	// RFC §6.1: GroupContext included when sender_type == member or new_member_commit
	st := ac.Content.Sender.Type
	if st == SenderTypeMember || st == SenderTypeNewMemberCommit {
		w.WriteRaw(ac.GroupContext)
	}
	return w.Bytes()
}

// UnmarshalAuthenticatedContent parses an AuthenticatedContent from its wire representation.
// Format: WireFormat (uint16) + FramedContent + FramedContentAuthData (signature [+ confirmation_tag for commit]).
// This format is used in transcript hash test vectors.
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

// PrivateMessageContent represents the plaintext encrypted with AEAD in a PrivateMessage (RFC 9420 §6.3).
//
// Structure:
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

// marshalPrivateMessageContent serializes the plaintext for PrivateMessage encryption.
// paddingSize == 0 means no padding; > 0 adds zeros for alignment (RFC §6.3).
func marshalPrivateMessageContent(body FramedContentBody, auth FramedContentAuthData, paddingSize int) []byte {
	w := tls.NewWriter()
	body.marshal(w)
	w.WriteRaw(auth.Marshal(body.ContentType()))
	if paddingSize > 0 {
		// Compute the padding length to align to the block size
		plainLen := len(w.Bytes())
		padLen := (paddingSize - (plainLen % paddingSize)) % paddingSize
		w.WriteRaw(make([]byte, padLen)) // RFC §6.3: padding MUST be all-zero
	}
	return w.Bytes()
}

// unmarshalPrivateMessageContent parses the decrypted plaintext from PrivateMessage.
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

	// confirmation_tag present only for Commit
	if ct == ContentTypeCommit && r.Remaining() > 0 {
		tag, err := r.ReadVLBytes()
		if err == nil && len(tag) > 0 {
			auth.ConfirmationTag = tag
		}
	}

	// RFC §6.3: remaining bytes are padding, must be all zeros
	for r.Remaining() > 0 {
		b, err := r.ReadUint8()
		if err != nil {
			return nil, fmt.Errorf("framing: reading padding: %w", err)
		}
		if b != 0 {
			return nil, fmt.Errorf("%w: non-zero padding byte", ErrInvalidPadding)
		}
	}

	return &PrivateMessageContent{Body: body, Auth: auth}, nil
}
