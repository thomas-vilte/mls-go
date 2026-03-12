package framing

// ContentType defines the type of content within an MLS message (RFC 9420 §6.1).
type ContentType uint8

const (
	// ContentTypeApplication indicates application data content.
	ContentTypeApplication ContentType = 1
	// ContentTypeProposal indicates a proposal content.
	ContentTypeProposal ContentType = 2
	// ContentTypeCommit indicates a commit content.
	ContentTypeCommit ContentType = 3
)

// WireFormat identifies the type of MLS message on the wire (RFC 9420 §6).
type WireFormat uint16

const (
	// WireFormatPublicMessage indicates a cleartext public message.
	WireFormatPublicMessage WireFormat = 1
	// WireFormatPrivateMessage indicates an encrypted private message.
	WireFormatPrivateMessage WireFormat = 2
	// WireFormatWelcome indicates a welcome message.
	WireFormatWelcome WireFormat = 3
	// WireFormatGroupInfo indicates a group info message.
	WireFormatGroupInfo WireFormat = 4
	// WireFormatKeyPackage indicates a key package message.
	WireFormatKeyPackage WireFormat = 5
)

// SenderType specifies the type of message sender (RFC 9420 §6.1).
type SenderType uint8

const (
	// SenderTypeMember indicates a message from an existing group member.
	SenderTypeMember SenderType = 1
	// SenderTypeExternal indicates a message from an external sender.
	SenderTypeExternal SenderType = 2
	// SenderTypeNewMemberProposal indicates a proposal from a new member.
	SenderTypeNewMemberProposal SenderType = 3
	// SenderTypeNewMemberCommit indicates a commit from a new member.
	SenderTypeNewMemberCommit SenderType = 4
)

// Sender identifies the sender of an MLS message (RFC 9420 §6.1).
//
// The fields used depend on the SenderType:
//   - SenderTypeMember: LeafIndex is valid
//   - SenderTypeExternal: SenderIndex is valid
//   - SenderTypeNewMemberProposal, SenderTypeNewMemberCommit: no additional fields
type Sender struct {
	Type        SenderType
	LeafIndex   uint32 // Valid only for SenderTypeMember
	SenderIndex uint32 // Valid only for SenderTypeExternal
}
