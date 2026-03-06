package framing

import "errors"

var (
	ErrInvalidWireFormat    = errors.New("framing: invalid wire format")
	ErrInvalidContentType   = errors.New("framing: invalid content type")
	ErrInvalidSenderType    = errors.New("framing: invalid sender type")
	ErrDecryptionFailed     = errors.New("framing: decryption failed")
	ErrVerificationFailed   = errors.New("framing: signature verification failed")
	ErrInvalidMembershipTag = errors.New("framing: invalid membership tag")
	ErrInvalidMessage       = errors.New("framing: invalid message")
)
