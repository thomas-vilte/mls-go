package framing

import "errors"

// Sentinel errors for the framing package.
var (
	ErrInvalidWireFormat    = errors.New("framing: invalid wire format")
	ErrInvalidContentType   = errors.New("framing: invalid content type")
	ErrInvalidSenderType    = errors.New("framing: invalid sender type")
	ErrDecryptionFailed     = errors.New("framing: decryption failed")
	ErrVerificationFailed   = errors.New("framing: signature verification failed")
	ErrInvalidMembershipTag = errors.New("framing: invalid membership tag")
	ErrInvalidMessage       = errors.New("framing: invalid message")
	ErrInvalidPadding       = errors.New("framing: invalid padding")
	ErrMissingGroupContext  = errors.New("framing: missing group context for member/new_member_commit sender")
)
