package group

import (
	"context"
	"errors"

	mlsext "github.com/thomas-vilte/mls-go/extensions"
)

// ExtensionHandler handles custom extension types for applications
// that need non-standard extensions.
type ExtensionHandler interface {
	Type() mlsext.ExtensionType
	Marshal() []byte
	Unmarshal(data []byte) error
	Validate(ctx context.Context, gc *GroupContext) error
}

// ExtensionHandlerRegistry manages custom extension handlers.
type ExtensionHandlerRegistry struct {
	handlers map[mlsext.ExtensionType]ExtensionHandler
}

// NewExtensionHandlerRegistry creates a new extension handler registry.
func NewExtensionHandlerRegistry() *ExtensionHandlerRegistry {
	return &ExtensionHandlerRegistry{
		handlers: make(map[mlsext.ExtensionType]ExtensionHandler),
	}
}

// Register adds an extension handler.
func (r *ExtensionHandlerRegistry) Register(h ExtensionHandler) {
	if r == nil || h == nil {
		return
	}
	r.handlers[h.Type()] = h
}

// Get returns the handler for a specific extension type.
func (r *ExtensionHandlerRegistry) Get(t mlsext.ExtensionType) ExtensionHandler {
	if r == nil {
		return nil
	}
	return r.handlers[t]
}

// ValidateAll validates all registered extensions in the given context.
func (r *ExtensionHandlerRegistry) ValidateAll(ctx context.Context, gc *GroupContext) error {
	if r == nil || gc == nil {
		return nil
	}
	for _, ext := range gc.Extensions {
		if h := r.Get(ext.Type); h != nil {
			if err := h.Validate(ctx, gc); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidateAllStrict validates all extensions in the given context, returning
// [ErrUnknownExtension] for any extension type without a registered handler.
// Use this when the application requires explicit handling of every extension
// type present in the GroupContext.
func (r *ExtensionHandlerRegistry) ValidateAllStrict(ctx context.Context, gc *GroupContext) error {
	if r == nil || gc == nil {
		return nil
	}
	for _, ext := range gc.Extensions {
		h := r.Get(ext.Type)
		if h == nil {
			return ErrUnknownExtension
		}
		if err := h.Validate(ctx, gc); err != nil {
			return err
		}
	}
	return nil
}

// ErrUnknownExtension is returned when an extension type has no registered handler
// and strict validation is enabled. By default, ValidateAll silently skips
// unregistered extension types: this registry only holds *application-defined*
// custom extension handlers (see WithExtensionHandler); RFC 9420's built-in
// extension types (ratchet_tree, required_capabilities, etc.) are validated
// through their own dedicated code paths, not through this registry, so an
// unregistered type here is not necessarily unsupported by the library as a
// whole. This error is provided for consumers that want ValidateAllStrict's
// stronger guarantee that every extension in the GroupContext has an explicit
// application-registered handler.
var ErrUnknownExtension = errors.New("group: unknown extension type with no handler registered")
