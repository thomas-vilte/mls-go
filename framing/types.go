package framing

// ContentType define el tipo de contenido del mensaje segun RFC §6.1
type ContentType uint8

const (
	ContentTypeApplication ContentType = 1
	ContentTypeProposal    ContentType = 2
	ContentTypeCommit      ContentType = 3
)

// WireFormat identifies the type of MLS message on the wire (RFC 9420 §6).
type WireFormat uint16

const (
	WireFormatPublicMessage  WireFormat = 1
	WireFormatPrivateMessage WireFormat = 2
	WireFormatWelcome        WireFormat = 3
	WireFormatGroupInfo      WireFormat = 4
	WireFormatKeyPackage     WireFormat = 5
)

// SenderType especifica quien manda el mensaje
type SenderType uint8

const (
	SenderTypeMember            SenderType = 1
	SenderTypeExternal          SenderType = 2
	SenderTypeNewMemberProposal SenderType = 3
	SenderTypeNewMemberCommit   SenderType = 4
)

// Sender identifica al remitente del mensaje
type Sender struct {
	Type        SenderType
	LeafIndex   uint32 // solo para Member
	SenderIndex uint32 // solo para External
}
