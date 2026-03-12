package framing

import (
	"fmt"

	"github.com/mls-go/internal/tls"
	"github.com/mls-go/keypackages"
)

// MLSMessage is the top-level wrapper for all MLS messages (RFC 9420 §6).
//
// On the wire, messages are always transmitted as MLSMessage — never as
// PublicMessage or PrivateMessage alone.
//
// Structure:
//
//	struct {
//	    ProtocolVersion version = mls10;
//	    WireFormat wire_format;
//	    select (MLSMessage.wire_format) {
//	        case mls_public_message:  PublicMessage public_message;
//	        case mls_private_message: PrivateMessage private_message;
//	        case mls_welcome:         Welcome welcome;
//	        case mls_group_info:      GroupInfo group_info;
//	        case mls_key_package:     KeyPackage key_package;
//	    };
//	} MLSMessage;
//
// For Welcome, GroupInfo, and KeyPackage (not yet implemented) opaque payloads are used.
type MLSMessage struct {
	// Exactly one of these fields is non-nil.
	PublicMessage  *PublicMessage
	PrivateMessage *PrivateMessage
	// Opaque payloads until Welcome/GroupInfo/KeyPackage are implemented.
	Welcome    []byte
	GroupInfo  []byte
	KeyPackage []byte
}

// NewMLSMessagePublic creates an MLSMessage from a PublicMessage.
func NewMLSMessagePublic(pm *PublicMessage) *MLSMessage {
	return &MLSMessage{PublicMessage: pm}
}

// NewMLSMessagePrivate creates an MLSMessage from a PrivateMessage.
func NewMLSMessagePrivate(pm *PrivateMessage) *MLSMessage {
	return &MLSMessage{PrivateMessage: pm}
}

// WireFormat returns the wire_format of the message.
func (m *MLSMessage) WireFormat() WireFormat {
	switch {
	case m.PublicMessage != nil:
		return WireFormatPublicMessage
	case m.PrivateMessage != nil:
		return WireFormatPrivateMessage
	case m.Welcome != nil:
		return WireFormatWelcome
	case m.GroupInfo != nil:
		return WireFormatGroupInfo
	case m.KeyPackage != nil:
		return WireFormatKeyPackage
	default:
		return 0
	}
}

// AsPrivate returns the PrivateMessage and true if the message is encrypted.
func (m *MLSMessage) AsPrivate() (*PrivateMessage, bool) {
	if m.PrivateMessage != nil {
		return m.PrivateMessage, true
	}
	return nil, false
}

// AsPublic returns the PublicMessage and true if the message is cleartext.
func (m *MLSMessage) AsPublic() (*PublicMessage, bool) {
	if m.PublicMessage != nil {
		return m.PublicMessage, true
	}
	return nil, false
}

// Marshal serializes the MLSMessage for transmission.
//
// Wire encoding: version(2) + wire_format(2) + payload.
// Since PublicMessage.Marshal() and PrivateMessage.Marshal() already include
// the wire_format as the first field, we simply prepend the version.
func (m *MLSMessage) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteUint16(uint16(keypackages.MLS10))
	switch {
	case m.PublicMessage != nil:
		// PublicMessage.Marshal() = wire_format(2) + content + auth + [tag]
		w.WriteRaw(m.PublicMessage.Marshal())
	case m.PrivateMessage != nil:
		// PrivateMessage.Marshal() = wire_format(2) + group_id + epoch + ...
		w.WriteRaw(m.PrivateMessage.Marshal())
	case m.Welcome != nil:
		w.WriteUint16(uint16(WireFormatWelcome))
		w.WriteRaw(m.Welcome)
	case m.GroupInfo != nil:
		w.WriteUint16(uint16(WireFormatGroupInfo))
		w.WriteRaw(m.GroupInfo)
	case m.KeyPackage != nil:
		w.WriteUint16(uint16(WireFormatKeyPackage))
		w.WriteRaw(m.KeyPackage)
	}
	return w.Bytes()
}

// UnmarshalMLSMessage parses an MLSMessage from its wire representation.
// Includes the version prefix (2 bytes) at the beginning.
func UnmarshalMLSMessage(data []byte) (*MLSMessage, error) {
	r := tls.NewReader(data)

	version, err := r.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("framing: reading version: %w", err)
	}
	if keypackages.ProtocolVersion(version) != keypackages.MLS10 {
		return nil, fmt.Errorf("%w: unsupported protocol version %d", ErrInvalidMessage, version)
	}

	// Peek wire_format to choose parser; then delegate with remaining data
	// (which starts with wire_format, as expected by UnmarshalPublicMessage/PrivateMessage).
	remaining := r.BytesAfterPosition()

	if len(remaining) < 2 {
		return nil, fmt.Errorf("framing: MLSMessage too short")
	}
	wf := WireFormat(uint16(remaining[0])<<8 | uint16(remaining[1]))

	switch wf {
	case WireFormatPublicMessage:
		pm, err := UnmarshalPublicMessage(remaining)
		if err != nil {
			return nil, err
		}
		return &MLSMessage{PublicMessage: pm}, nil

	case WireFormatPrivateMessage:
		pm, err := UnmarshalPrivateMessage(remaining)
		if err != nil {
			return nil, err
		}
		return &MLSMessage{PrivateMessage: pm}, nil

	case WireFormatWelcome:
		payload := remaining[2:]
		cp := make([]byte, len(payload))
		copy(cp, payload)
		return &MLSMessage{Welcome: cp}, nil

	case WireFormatGroupInfo:
		payload := remaining[2:]
		cp := make([]byte, len(payload))
		copy(cp, payload)
		return &MLSMessage{GroupInfo: cp}, nil

	case WireFormatKeyPackage:
		payload := remaining[2:]
		cp := make([]byte, len(payload))
		copy(cp, payload)
		return &MLSMessage{KeyPackage: cp}, nil

	default:
		return nil, fmt.Errorf("%w: %d", ErrInvalidWireFormat, wf)
	}
}
