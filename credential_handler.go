package mls

import (
	"context"
	"errors"

	"github.com/thomas-vilte/mls-go/credentials"
)

// CredentialHandler handles custom credential types for applications that need
// non-standard credential validation (e.g., custom authz, external PKI, LDAP).
type CredentialHandler interface {
	Type() credentials.CredentialType
	Validate(ctx context.Context, raw []byte) error
	Identity(raw []byte) ([]byte, error)
}

// CredentialHandlerRegistry manages custom credential handlers.
type CredentialHandlerRegistry struct {
	handlers map[credentials.CredentialType]CredentialHandler
}

// NewCredentialHandlerRegistry creates a new credential handler registry.
func NewCredentialHandlerRegistry() *CredentialHandlerRegistry {
	return &CredentialHandlerRegistry{
		handlers: make(map[credentials.CredentialType]CredentialHandler),
	}
}

// Register adds a credential handler for a specific credential type.
func (r *CredentialHandlerRegistry) Register(t credentials.CredentialType, h CredentialHandler) {
	if r == nil || h == nil {
		return
	}
	r.handlers[t] = h
}

// Get returns the handler for a specific credential type.
func (r *CredentialHandlerRegistry) Get(t credentials.CredentialType) CredentialHandler {
	if r == nil {
		return nil
	}
	return r.handlers[t]
}

// Validate validates a credential using the appropriate handler.
func (r *CredentialHandlerRegistry) Validate(ctx context.Context, cred *credentials.Credential) error {
	if r == nil || cred == nil {
		return nil
	}
	switch cred.Type() {
	case credentials.BasicCredential, credentials.X509Credential:
		return cred.Validate()
	default:
		h := r.Get(cred.Type())
		if h == nil {
			return ErrUnknownCredentialType
		}
		var data []byte
		if cred.Type() == credentials.X509Credential && len(cred.Certificates) > 0 {
			data = cred.Certificates[0]
		} else {
			data = cred.Identity
		}
		return h.Validate(ctx, data)
	}
}

// ErrUnknownCredentialType is returned when a credential type has no registered handler.
var ErrUnknownCredentialType = errors.New("mls: unknown credential type with no handler registered")
