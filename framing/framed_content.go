package framing

import (
	"fmt"

	"github.com/thomas-vilte/mls-go/internal/tls"
)

// FramedContentBody represents the select(content_type) body of FramedContent (RFC §6.1).
// Only one of the three concrete types can be present at a time.
type FramedContentBody interface {
	ContentType() ContentType
	marshal(w *tls.Writer)
}

// ApplicationData represents the body for application messages.
type ApplicationData struct{ Data []byte }

// ProposalBody represents the body for proposals (serialized).
type ProposalBody struct{ Data []byte }

// CommitBody represents the body for commits (serialized).
type CommitBody struct{ Data []byte }

// ContentType returns ContentTypeApplication for ApplicationData.
func (a ApplicationData) ContentType() ContentType { return ContentTypeApplication }

// ContentType returns ContentTypeProposal for ProposalBody.
func (p ProposalBody) ContentType() ContentType { return ContentTypeProposal }

// ContentType returns ContentTypeCommit for CommitBody.
func (c CommitBody) ContentType() ContentType { return ContentTypeCommit }

func (a ApplicationData) marshal(w *tls.Writer) { w.WriteVLBytes(a.Data) }
func (p ProposalBody) marshal(w *tls.Writer)    { w.WriteRaw(p.Data) }
func (c CommitBody) marshal(w *tls.Writer)      { w.WriteRaw(c.Data) }

// FramedContent implements the core framed content structure (RFC 9420 §6.1).
//
// Structure:
//
//	struct {
//	    opaque group_id<V>;
//	    uint64 epoch;
//	    Sender sender;
//	    opaque authenticated_data<V>;
//	    ContentType content_type;
//	    select (FramedContent.content_type) {
//	        case application:  opaque application_data<V>;
//	        case proposal:     Proposal proposal;
//	        case commit:       Commit commit;
//	    };
//	} FramedContent;
type FramedContent struct {
	GroupID           []byte            // Group identifier, variable length
	Epoch             uint64            // Current epoch of the group
	Sender            Sender            // Message sender
	AuthenticatedData []byte            // Additional authenticated data
	Body              FramedContentBody // The actual content (app/proposal/commit)
}

// ContentType returns the content type of the body.
func (fc *FramedContent) ContentType() ContentType {
	return fc.Body.ContentType()
}

// ApplicationData returns the application payload if the body type is application.
func (fc *FramedContent) ApplicationData() ([]byte, bool) {
	app, ok := fc.Body.(ApplicationData)
	if !ok {
		return nil, false
	}
	return app.Data, true
}

// Marshal serializes FramedContent according to TLS encoding in the RFC.
func (fc *FramedContent) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteVLBytes(fc.GroupID)
	w.WriteUint64(fc.Epoch)
	MarshalSender(&fc.Sender, w)
	w.WriteVLBytes(fc.AuthenticatedData)
	w.WriteUint8(uint8(fc.ContentType()))
	fc.Body.marshal(w)
	return w.Bytes()
}

// UnmarshalFramedContent parses bytes into a FramedContent.
func UnmarshalFramedContent(data []byte) (*FramedContent, error) {
	r := tls.NewReader(data)
	return unmarshalFramedContentFromReader(r)
}

// unmarshalFramedContentFromReader parses a FramedContent from an existing reader.
// Used internally when parsing composite wire formats (PublicMessage).
func unmarshalFramedContentFromReader(r *tls.Reader) (*FramedContent, error) {
	return unmarshalFramedContentFromReaderWithMode(r, false, false)
}

func unmarshalFramedContentFromReaderWithMode(r *tls.Reader, expectsTrailingAuth, withMembershipTag bool) (*FramedContent, error) {
	groupID, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("framing: reading group_id: %w", err)
	}
	epoch, err := r.ReadUint64()
	if err != nil {
		return nil, fmt.Errorf("framing: reading epoch: %w", err)
	}
	sender, err := UnmarshalSender(r)
	if err != nil {
		return nil, fmt.Errorf("framing: reading sender: %w", err)
	}
	authData, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("framing: reading authenticated_data: %w", err)
	}
	ct, err := r.ReadUint8()
	if err != nil {
		return nil, fmt.Errorf("framing: reading content_type: %w", err)
	}
	hasMembershipTag := withMembershipTag && sender.Type == SenderTypeMember
	body, err := readFramedContentBody(r, ContentType(ct), hasMembershipTag, expectsTrailingAuth)
	if err != nil {
		return nil, err
	}
	return &FramedContent{
		GroupID:           groupID,
		Epoch:             epoch,
		Sender:            *sender,
		AuthenticatedData: authData,
		Body:              body,
	}, nil
}
