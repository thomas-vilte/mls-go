package framing

import "errors"

var (
	ErrInvalidWireFormat    = errors.New("framing: wire format inválido")
	ErrInvalidContentType   = errors.New("framing: content type inválido")
	ErrInvalidSenderType    = errors.New("framing: sender type inválido")
	ErrDecryptionFailed     = errors.New("framing: falló el descifrado")
	ErrVerificationFailed   = errors.New("framing: falló la verificación de firma")
	ErrInvalidMembershipTag = errors.New("framing: membership tag inválido")
	ErrInvalidMessage       = errors.New("framing: mensaje inválido")
)
