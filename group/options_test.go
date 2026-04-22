package group

import (
	"bytes"
	"context"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	mlsext "github.com/thomas-vilte/mls-go/extensions"
	"github.com/thomas-vilte/mls-go/keypackages"
)

type testPSKStore struct{}

type testExtensionHandler struct {
	typeID mlsext.ExtensionType
}

func (h testExtensionHandler) Type() mlsext.ExtensionType {
	return h.typeID
}

func (h testExtensionHandler) Marshal() []byte {
	return []byte("test")
}

func (h testExtensionHandler) Unmarshal(_ []byte) error {
	return nil
}

func (h testExtensionHandler) Validate(_ context.Context, _ *GroupContext) error {
	return nil
}

func (testPSKStore) GetPSK(_ []byte) ([]byte, error) {
	return nil, nil
}

func mustNewGroupInputs(t *testing.T) (*GroupID, *keypackages.KeyPackage, *keypackages.KeyPackagePrivateKeys) {
	t.Helper()

	credWithKey, _, err := credentials.GenerateCredentialWithKey([]byte("OptionsUser"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}

	kp, kpPriv, err := keypackages.Generate(credWithKey, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage failed: %v", err)
	}

	groupID, err := NewGroupIDRandom()
	if err != nil {
		t.Fatalf("NewGroupIDRandom failed: %v", err)
	}

	return groupID, kp, kpPriv
}

func TestNewGroupAppliesOptions(t *testing.T) {
	groupID, kp, kpPriv := mustNewGroupInputs(t)
	store := testPSKStore{}
	exts := []Extension{{Type: mlsext.ExtensionTypeApplicationID, Data: []byte("app-a")}}

	g, err := NewGroup(
		groupID,
		ciphersuite.MLS128DHKEMP256,
		kp,
		kpPriv,
		WithExtensions(exts),
		WithPaddingSize(64),
		WithPSKStore(store),
	)
	if err != nil {
		t.Fatalf("NewGroup failed: %v", err)
	}

	if g.PaddingSize() != 64 {
		t.Fatalf("PaddingSize() = %d, want 64", g.PaddingSize())
	}
	if g.PSKStore != store {
		t.Fatal("PSKStore was not applied")
	}

	ctx := g.GroupContext()
	if len(ctx.Extensions) != 1 {
		t.Fatalf("len(GroupContext.Extensions) = %d, want 1", len(ctx.Extensions))
	}
	if ctx.Extensions[0].Type != exts[0].Type {
		t.Fatalf("extension type = %d, want %d", ctx.Extensions[0].Type, exts[0].Type)
	}
	if !bytes.Equal(ctx.Extensions[0].Data, exts[0].Data) {
		t.Fatalf("extension data = %x, want %x", ctx.Extensions[0].Data, exts[0].Data)
	}

	exts[0].Data[0] ^= 0xFF
	if bytes.Equal(g.GroupContext().Extensions[0].Data, exts[0].Data) {
		t.Fatal("group should keep a copy of extension data")
	}
}

func TestNewGroupWithExtensionsIsWrapper(t *testing.T) {
	groupID, kp, kpPriv := mustNewGroupInputs(t)
	exts := []Extension{{Type: mlsext.ExtensionTypeApplicationID, Data: []byte("app-b")}}

	g, err := NewGroupWithExtensions(groupID, ciphersuite.MLS128DHKEMP256, kp, kpPriv, exts)
	if err != nil {
		t.Fatalf("NewGroupWithExtensions failed: %v", err)
	}

	if len(g.GroupContext().Extensions) != 1 {
		t.Fatalf("len(GroupContext.Extensions) = %d, want 1", len(g.GroupContext().Extensions))
	}
	if !bytes.Equal(g.GroupContext().Extensions[0].Data, []byte("app-b")) {
		t.Fatalf("extension data = %x, want %x", g.GroupContext().Extensions[0].Data, []byte("app-b"))
	}

	exts[0].Data[0] ^= 0xFF
	if bytes.Equal(g.GroupContext().Extensions[0].Data, exts[0].Data) {
		t.Fatal("wrapper should not alias caller extension data")
	}
}

func TestWithPaddingSizeNegativeValueClampsToZero(t *testing.T) {
	groupID, kp, kpPriv := mustNewGroupInputs(t)

	g, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kp, kpPriv, WithPaddingSize(-10))
	if err != nil {
		t.Fatalf("NewGroup failed: %v", err)
	}

	if g.PaddingSize() != 0 {
		t.Fatalf("PaddingSize() = %d, want 0", g.PaddingSize())
	}
}

func TestWithExtensionHandlerRegistersHandler(t *testing.T) {
	groupID, kp, kpPriv := mustNewGroupInputs(t)
	h := testExtensionHandler{typeID: mlsext.ExtensionType(0xFF01)}

	g, err := NewGroup(
		groupID,
		ciphersuite.MLS128DHKEMP256,
		kp,
		kpPriv,
		WithExtensionHandler(h),
	)
	if err != nil {
		t.Fatalf("NewGroup failed: %v", err)
	}
	if g.extensionHandlers == nil {
		t.Fatal("extension handlers registry is nil")
	}
	if got := g.extensionHandlers.Get(h.Type()); got == nil {
		t.Fatalf("handler for type 0x%04x was not registered", uint16(h.Type()))
	}
}
