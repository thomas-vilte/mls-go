package framing

import (
	"fmt"

	"github.com/openmls/go/group"
	"github.com/openmls/go/internal/tls"
	keypackages "github.com/openmls/go/key_packages"
)

// MLSMessage represents a generic MLS message on the wire.
//
// This is the top-level message type that can be any of the MLS message types.
type MLSMessage struct {
	Version uint16 // Protocol version
	Body    MLSMessageBody
}

// MLSMessageBody represents the body of an MLS message.
type MLSMessageBody struct {
	// Only one of these should be set
	PublicMessage  *PublicMessage
	PrivateMessage *PrivateMessage
	Welcome        *group.Welcome
	GroupInfo      *group.GroupInfo
	KeyPackage     *keypackages.KeyPackage
}

// WireFormat returns the wire format of the message.
func (m *MLSMessage) WireFormat() WireFormat {
	switch {
	case m.Body.PublicMessage != nil:
		return WireFormatPublicMessage
	case m.Body.PrivateMessage != nil:
		return WireFormatPrivateMessage
	case m.Body.Welcome != nil:
		return WireFormatWelcome
	case m.Body.GroupInfo != nil:
		return WireFormatGroupInfo
	case m.Body.KeyPackage != nil:
		return WireFormatKeyPackage
	default:
		return 0
	}
}

// Marshal serializes the MLSMessage to TLS format.
func (m *MLSMessage) Marshal() []byte {
	w := tls.NewWriter()
	// Version
	w.WriteUint16(m.Version)
	// Wire format
	w.WriteUint16(uint16(m.WireFormat()))
	// Body
	switch m.WireFormat() {
	case WireFormatPublicMessage:
		w.WriteRaw(m.Body.PublicMessage.Marshal())
	case WireFormatPrivateMessage:
		w.WriteRaw(m.Body.PrivateMessage.Marshal())
	case WireFormatWelcome:
		w.WriteRaw(m.Body.Welcome.Marshal())
	case WireFormatGroupInfo:
		// TODO: Implement GroupInfo serialization
		w.WriteVLBytes([]byte{})
	case WireFormatKeyPackage:
		w.WriteRaw(m.Body.KeyPackage.Marshal())
	}
	return w.Bytes()
}

// UnmarshalMLSMessage deserializes an MLSMessage from TLS format.
func UnmarshalMLSMessage(data []byte) (*MLSMessage, error) {
	r := tls.NewReader(data)
	// Version
	version, err := r.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("reading version: %w", err)
	}
	// Wire format
	wireFormat, err := r.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("reading wire format: %w", err)
	}
	msg := &MLSMessage{
		Version: version,
	}
	// Read remaining data as body
	bodyData := r.BytesAfterPosition()
	switch WireFormat(wireFormat) {
	case WireFormatPublicMessage:
		pm, err := UnmarshalPublicMessage(bodyData)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling public message: %w", err)
		}
		msg.Body = MLSMessageBody{PublicMessage: pm}
	case WireFormatPrivateMessage:
		pm, err := UnmarshalPrivateMessage(bodyData)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling private message: %w", err)
		}
		msg.Body = MLSMessageBody{PrivateMessage: pm}
	case WireFormatWelcome:
		// TODO: Implement Welcome deserialization
		return nil, fmt.Errorf("welcome deserialization not implemented")
	case WireFormatGroupInfo:
		// TODO: Implement GroupInfo deserialization
		return nil, fmt.Errorf("groupinfo deserialization not implemented")
	case WireFormatKeyPackage:
		kp, err := keypackages.UnmarshalKeyPackage(bodyData)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling key package: %w", err)
		}
		msg.Body = MLSMessageBody{KeyPackage: kp}
	default:
		return nil, fmt.Errorf("unknown wire format: %d", wireFormat)
	}
	return msg, nil
}

// NewPublicMLSMessage creates a new MLS message containing a public message.
func NewPublicMLSMessage(pm *PublicMessage) *MLSMessage {
	return &MLSMessage{
		Version: 1, // MLS 1.0
		Body:    MLSMessageBody{PublicMessage: pm},
	}
}

// NewPrivateMLSMessage creates a new MLS message containing a private message.
func NewPrivateMLSMessage(pm *PrivateMessage) *MLSMessage {
	return &MLSMessage{
		Version: 1, // MLS 1.0
		Body:    MLSMessageBody{PrivateMessage: pm},
	}
}
