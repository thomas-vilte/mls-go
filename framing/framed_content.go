package framing

import (
	"fmt"

	"github.com/openmls/go/internal/tls"
)

// FramedContentBody es la interface que representa el select(content_type) del RFC §6.1
// Solo uno de los tres tipos concretos puede estar presente
type FramedContentBody interface {
	ContentType() ContentType
	marshal(w *tls.Writer)
}

// ApplicationData es el body para mensajes de aplicación
type ApplicationData struct{ Data []byte }

// ProposalBody es el body para propuestas (serializado)
type ProposalBody struct{ Data []byte }

// CommitBody es el body para commits (serializado)
type CommitBody struct{ Data []byte }

func (a ApplicationData) ContentType() ContentType { return ContentTypeApplication }
func (p ProposalBody) ContentType() ContentType    { return ContentTypeProposal }
func (c CommitBody) ContentType() ContentType      { return ContentTypeCommit }
func (a ApplicationData) marshal(w *tls.Writer)    { w.WriteVLBytes(a.Data) }
func (p ProposalBody) marshal(w *tls.Writer)       { w.WriteVLBytes(p.Data) }
func (c CommitBody) marshal(w *tls.Writer)         { w.WriteVLBytes(c.Data) }

// FramedContent implementa RFC 9420 §6.1 completo
// Es el núcleo de todo mensaje MLS
type FramedContent struct {
	GroupID           []byte            // ID del grupo, variable length
	Epoch             uint64            // Época actual del grupo
	Sender            Sender            // Quién manda el mensaje
	AuthenticatedData []byte            // Datos autenticados adicionales
	Body              FramedContentBody // El contenido posta (app/proposal/commit)
}

// ContentType devuelve el tipo de contenido del body
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

// Marshal serializa FramedContent según TLS encoding del RFC
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

// UnmarshalFramedContent parsea bytes en un FramedContent.
func UnmarshalFramedContent(data []byte) (*FramedContent, error) {
	r := tls.NewReader(data)
	return unmarshalFramedContentFromReader(r)
}

// unmarshalFramedContentFromReader parsea un FramedContent desde un reader existente.
// Utilizado internamente al parsear formatos wire compuestos (PublicMessage).
func unmarshalFramedContentFromReader(r *tls.Reader) (*FramedContent, error) {
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
	bodyData, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("framing: reading body: %w", err)
	}
	var body FramedContentBody
	switch ContentType(ct) {
	case ContentTypeApplication:
		body = ApplicationData{Data: bodyData}
	case ContentTypeProposal:
		body = ProposalBody{Data: bodyData}
	case ContentTypeCommit:
		body = CommitBody{Data: bodyData}
	default:
		return nil, fmt.Errorf("%w: %d", ErrInvalidContentType, ct)
	}
	return &FramedContent{
		GroupID:           groupID,
		Epoch:             epoch,
		Sender:            *sender,
		AuthenticatedData: authData,
		Body:              body,
	}, nil
}
