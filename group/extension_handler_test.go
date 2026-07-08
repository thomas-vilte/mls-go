package group

import (
	"context"
	"errors"
	"testing"

	mlsext "github.com/thomas-vilte/mls-go/extensions"
)

// stubHandler is a minimal ExtensionHandler for testing.
type stubHandler struct {
	typ        mlsext.ExtensionType
	validateFn func(ctx context.Context, gc *GroupContext) error
}

func (h *stubHandler) Type() mlsext.ExtensionType { return h.typ }
func (h *stubHandler) Marshal() []byte            { return nil }
func (h *stubHandler) Unmarshal(_ []byte) error   { return nil }
func (h *stubHandler) Validate(ctx context.Context, gc *GroupContext) error {
	if h.validateFn != nil {
		return h.validateFn(ctx, gc)
	}
	return nil
}

func TestValidateAll_SkipsUnknownExtensions(t *testing.T) {
	t.Parallel()
	reg := NewExtensionHandlerRegistry()
	// Register handler for type 0xFF01 only.
	reg.Register(&stubHandler{typ: 0xFF01})

	gc := &GroupContext{
		Extensions: []Extension{
			{Type: 0xFF01, Data: []byte("known")},
			{Type: 0xFF02, Data: []byte("unknown")},
		},
	}
	// ValidateAll should NOT return ErrUnknownExtension for unregistered types.
	if err := reg.ValidateAll(context.Background(), gc); err != nil {
		t.Fatalf("ValidateAll should skip unknown extensions, got: %v", err)
	}
}

func TestValidateAll_CallsRegisteredHandler(t *testing.T) {
	t.Parallel()
	called := false
	reg := NewExtensionHandlerRegistry()
	reg.Register(&stubHandler{
		typ: 0xFF01,
		validateFn: func(_ context.Context, _ *GroupContext) error {
			called = true
			return nil
		},
	})

	gc := &GroupContext{
		Extensions: []Extension{
			{Type: 0xFF01, Data: []byte("data")},
		},
	}
	if err := reg.ValidateAll(context.Background(), gc); err != nil {
		t.Fatalf("ValidateAll: %v", err)
	}
	if !called {
		t.Fatal("expected registered handler to be called")
	}
}

func TestValidateAllStrict_ReturnsErrUnknownExtension(t *testing.T) {
	t.Parallel()
	reg := NewExtensionHandlerRegistry()
	// No handlers registered.

	gc := &GroupContext{
		Extensions: []Extension{
			{Type: 0xFF02, Data: []byte("unknown")},
		},
	}
	err := reg.ValidateAllStrict(context.Background(), gc)
	if !errors.Is(err, ErrUnknownExtension) {
		t.Fatalf("expected ErrUnknownExtension, got: %v", err)
	}
}

func TestValidateAllStrict_PassesKnownExtensions(t *testing.T) {
	t.Parallel()
	reg := NewExtensionHandlerRegistry()
	reg.Register(&stubHandler{typ: 0xFF01})

	gc := &GroupContext{
		Extensions: []Extension{
			{Type: 0xFF01, Data: []byte("known")},
		},
	}
	if err := reg.ValidateAllStrict(context.Background(), gc); err != nil {
		t.Fatalf("ValidateAllStrict should pass for registered extensions, got: %v", err)
	}
}

func TestValidateAllStrict_PropagatesHandlerError(t *testing.T) {
	t.Parallel()
	handlerErr := errors.New("validation failed")
	reg := NewExtensionHandlerRegistry()
	reg.Register(&stubHandler{
		typ: 0xFF01,
		validateFn: func(_ context.Context, _ *GroupContext) error {
			return handlerErr
		},
	})

	gc := &GroupContext{
		Extensions: []Extension{
			{Type: 0xFF01, Data: []byte("data")},
		},
	}
	err := reg.ValidateAllStrict(context.Background(), gc)
	if !errors.Is(err, handlerErr) {
		t.Fatalf("expected handler error, got: %v", err)
	}
}

func TestValidateAll_NilRegistry(t *testing.T) {
	t.Parallel()
	var reg *ExtensionHandlerRegistry
	gc := &GroupContext{Extensions: []Extension{{Type: 0xFF01}}}
	if err := reg.ValidateAll(context.Background(), gc); err != nil {
		t.Fatalf("nil ValidateAll should return nil, got: %v", err)
	}
	if err := reg.ValidateAllStrict(context.Background(), gc); err != nil {
		t.Fatalf("nil ValidateAllStrict should return nil, got: %v", err)
	}
}

func TestValidateAll_NilGroupContext(t *testing.T) {
	t.Parallel()
	reg := NewExtensionHandlerRegistry()
	if err := reg.ValidateAll(context.Background(), nil); err != nil {
		t.Fatalf("nil GroupContext should return nil, got: %v", err)
	}
	if err := reg.ValidateAllStrict(context.Background(), nil); err != nil {
		t.Fatalf("nil GroupContext should return nil, got: %v", err)
	}
}
