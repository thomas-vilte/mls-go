package framing

import (
	"fmt"

	"github.com/openmls/go/internal/tls"
	keypackages "github.com/openmls/go/keypackages"
)

// MLSMessage es el wrapper de nivel superior para todos los mensajes MLS (RFC 9420 §6).
//
// En el wire, siempre se transmite como MLSMessage — nunca PublicMessage o PrivateMessage solos.
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
// Para Welcome, GroupInfo y KeyPackage (aún no implementados) se usan payloads opacos.
type MLSMessage struct {
	// Exactamente uno de estos campos es no-nil.
	PublicMessage  *PublicMessage
	PrivateMessage *PrivateMessage
	// Payloads opacos hasta que Welcome/GroupInfo/KeyPackage estén implementados.
	Welcome    []byte
	GroupInfo  []byte
	KeyPackage []byte
}

// NewMLSMessagePublic crea un MLSMessage desde un PublicMessage.
func NewMLSMessagePublic(pm *PublicMessage) *MLSMessage {
	return &MLSMessage{PublicMessage: pm}
}

// NewMLSMessagePrivate crea un MLSMessage desde un PrivateMessage.
func NewMLSMessagePrivate(pm *PrivateMessage) *MLSMessage {
	return &MLSMessage{PrivateMessage: pm}
}

// WireFormat retorna el wire_format del mensaje.
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

// AsPrivate retorna el PrivateMessage y true si el mensaje es cifrado.
func (m *MLSMessage) AsPrivate() (*PrivateMessage, bool) {
	if m.PrivateMessage != nil {
		return m.PrivateMessage, true
	}
	return nil, false
}

// AsPublic retorna el PublicMessage y true si el mensaje es en claro.
func (m *MLSMessage) AsPublic() (*PublicMessage, bool) {
	if m.PublicMessage != nil {
		return m.PublicMessage, true
	}
	return nil, false
}

// Marshal serializa el MLSMessage para transmisión.
//
// Wire encoding: version(2) + wire_format(2) + payload.
// Como PublicMessage.Marshal() y PrivateMessage.Marshal() ya incluyen el wire_format
// como primer campo, simplemente se antepone la versión.
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

// UnmarshalMLSMessage parsea un MLSMessage desde su representación wire.
// Incluye el version prefix (2 bytes) al inicio.
func UnmarshalMLSMessage(data []byte) (*MLSMessage, error) {
	r := tls.NewReader(data)

	version, err := r.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("framing: reading version: %w", err)
	}
	if keypackages.ProtocolVersion(version) != keypackages.MLS10 {
		return nil, fmt.Errorf("%w: unsupported protocol version %d", ErrInvalidMessage, version)
	}

	// Peek wire_format para elegir el parser; luego delegamos con los datos restantes
	// (que empiezan con wire_format, tal como esperan UnmarshalPublicMessage/PrivateMessage).
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
