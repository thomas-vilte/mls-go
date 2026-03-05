package framing

import "fmt"

// FramingError represents framing-related errors.
type FramingError string

const (
	ErrInvalidWireFormat     FramingError = "invalid wire format"
	ErrInvalidContentType    FramingError = "invalid content type"
	ErrInvalidSenderType     FramingError = "invalid sender type"
	ErrDecryptionFailed      FramingError = "decryption failed"
	ErrVerificationFailed    FramingError = "signature verification failed"
	ErrInvalidMessage        FramingError = "invalid message"
	ErrSerializationFailed   FramingError = "serialization failed"
	ErrDeserializationFailed FramingError = "deserialization failed"
)

func (e FramingError) Error() string {
	return string(e)
}

// NewFramingError creates a new framing error with context.
func NewFramingError(err FramingError, context string) error {
	return fmt.Errorf("%s: %s", err, context)
}
