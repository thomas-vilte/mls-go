package extensions_test

import (
	"bytes"
	"testing"

	"github.com/mls-go/credentials"
	"github.com/mls-go/extensions"
)

// TestExtensionMarshalUnmarshal tests basic extension serialization.
func TestExtensionMarshalUnmarshal(t *testing.T) {
	ext := &extensions.Extension{
		Type: extensions.ExtensionTypeApplicationID,
		Data: []byte{0x01, 0x02, 0x03},
	}

	data := ext.Marshal()

	parsed, err := extensions.UnmarshalExtension(data)
	if err != nil {
		t.Fatalf("UnmarshalExtension failed: %v", err)
	}

	if parsed.Type != ext.Type {
		t.Errorf("Type mismatch: got %d, want %d", parsed.Type, ext.Type)
	}

	if !bytes.Equal(parsed.Data, ext.Data) {
		t.Error("Data mismatch")
	}
}

func TestExtensionsMarshal_OrderDeterministic(t *testing.T) {
	// RFC 9420 §13.4: Extensions MUST be serialized in ascending order by type

	exts := extensions.NewExtensions()

	// Add extensions in random order
	exts.Add(extensions.Extension{Type: extensions.ExtensionTypeExternalSenders, Data: []byte{0x03}})
	exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte{0x01}})
	exts.Add(extensions.Extension{Type: extensions.ExtensionTypeRatchetTree, Data: []byte{0x02}})

	// Marshal multiple times
	data1 := exts.Marshal()
	data2 := exts.Marshal()
	data3 := exts.Marshal()

	// Must be deterministic
	if !bytes.Equal(data1, data2) || !bytes.Equal(data2, data3) {
		t.Error("Marshal is not deterministic")
	}

	// Verify order is ascending (ApplicationID=0x0001, RatchetTree=0x0002, ExternalSenders=0x0005)
	all := exts.All()
	if len(all) != 3 {
		t.Fatalf("Expected 3 extensions, got %d", len(all))
	}
	if all[0].Type != extensions.ExtensionTypeApplicationID {
		t.Errorf("First extension should be ApplicationID (0x0001), got %d", all[0].Type)
	}
	if all[1].Type != extensions.ExtensionTypeRatchetTree {
		t.Errorf("Second extension should be RatchetTree (0x0002), got %d", all[1].Type)
	}
	if all[2].Type != extensions.ExtensionTypeExternalSenders {
		t.Errorf("Third extension should be ExternalSenders (0x0005), got %d", all[2].Type)
	}
}

// TestExtensionsCollection tests the Extensions collection.
func TestExtensionsCollection(t *testing.T) {
	exts := extensions.NewExtensions()

	ext1 := extensions.Extension{
		Type: extensions.ExtensionTypeApplicationID,
		Data: []byte{0x01},
	}

	ext2 := extensions.Extension{
		Type: extensions.ExtensionTypeRatchetTree,
		Data: []byte{0x02},
	}

	// Add extensions
	if err := exts.Add(ext1); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	if err := exts.Add(ext2); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// Test Has
	if !exts.Has(extensions.ExtensionTypeApplicationID) {
		t.Error("Should have ApplicationID extension")
	}

	if !exts.Has(extensions.ExtensionTypeRatchetTree) {
		t.Error("Should have RatchetTree extension")
	}

	// Test Get
	retrieved, ok := exts.Get(extensions.ExtensionTypeApplicationID)
	if !ok {
		t.Fatal("Get failed")
	}

	if retrieved.Type != ext1.Type {
		t.Errorf("Wrong type: got %d, want %d", retrieved.Type, ext1.Type)
	}

	// Test Len
	if exts.Len() != 2 {
		t.Errorf("Wrong length: got %d, want 2", exts.Len())
	}

	// Test Remove
	exts.Remove(extensions.ExtensionTypeApplicationID)
	if exts.Len() != 1 {
		t.Errorf("Wrong length after remove: got %d, want 1", exts.Len())
	}

	if exts.Has(extensions.ExtensionTypeApplicationID) {
		t.Error("Should not have ApplicationID after remove")
	}
}

// TestRequiredCapabilitiesExtension tests the RequiredCapabilities extension.
func TestRequiredCapabilitiesExtension(t *testing.T) {
	rc := extensions.NewRequiredCapabilities()

	rc.AddProtocolVersion(1)
	rc.AddCipherSuite(0x0002)
	rc.AddExtension(extensions.ExtensionTypeRatchetTree)
	rc.AddProposal(0x0001)
	rc.AddCredential(credentials.BasicCredential)

	if err := rc.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	data := rc.Marshal()

	parsed, err := extensions.UnmarshalRequiredCapabilities(data)
	if err != nil {
		t.Fatalf("UnmarshalRequiredCapabilities failed: %v", err)
	}

	if !rc.Equal(parsed) {
		t.Error("Parsed extension not equal to original")
	}

	// Test Has methods
	if !rc.HasProtocolVersion(1) {
		t.Error("Should have protocol version 1")
	}

	if !rc.HasCipherSuite(0x0002) {
		t.Error("Should have cipher suite 0x0002")
	}

	if !rc.HasExtension(extensions.ExtensionTypeRatchetTree) {
		t.Error("Should have RatchetTree extension")
	}
}

// TestExternalSendersExtension tests the ExternalSenders extension.
func TestExternalSendersExtension(t *testing.T) {
	t.Skip("ExternalSenders test requires full credential implementation")

	ext := extensions.NewExternalSendersExtension()

	// Create a test sender
	credWithKey, _, err := credentials.GenerateCredentialWithKey([]byte("ExternalSender"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey failed: %v", err)
	}

	sender := extensions.ExternalSender{
		Credential: credWithKey.Credential,
		PublicKey:  credWithKey.SignatureKey,
	}

	if err := ext.AddSender(sender); err != nil {
		t.Fatalf("AddSender failed: %v", err)
	}

	if ext.Len() != 1 {
		t.Errorf("Wrong sender count: got %d, want 1", ext.Len())
	}

	// Test FindSender
	found, ok := ext.FindSender(credWithKey.Credential)
	if !ok {
		t.Fatal("FindSender failed")
	}

	if found.Credential == nil {
		t.Error("Found sender has nil credential")
	}

	// Test Marshal/Unmarshal
	data := ext.Marshal()

	parsed, err := extensions.UnmarshalExternalSendersExtension(data)
	if err != nil {
		t.Fatalf("UnmarshalExternalSendersExtension failed: %v", err)
	}

	if !ext.Equal(parsed) {
		t.Error("Parsed extension not equal to original")
	}
}

// TestRatchetTreeExtension tests the RatchetTree extension.
func TestRatchetTreeExtension(t *testing.T) {
	t.Skip("RatchetTree test requires full treesync implementation")

	// TODO: Implement when treesync is complete
}

// TestExtensionClone tests cloning extensions.
func TestExtensionClone(t *testing.T) {
	exts := extensions.NewExtensions()

	ext := extensions.Extension{
		Type: extensions.ExtensionTypeApplicationID,
		Data: []byte{0x01, 0x02, 0x03},
	}

	if err := exts.Add(ext); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// Clone
	cloned := exts.Clone()

	if cloned.Len() != exts.Len() {
		t.Errorf("Clone has wrong length: got %d, want %d", cloned.Len(), exts.Len())
	}

	retrieved, ok := cloned.Get(extensions.ExtensionTypeApplicationID)
	if !ok {
		t.Fatal("Get from clone failed")
	}

	if !bytes.Equal(retrieved.Data, ext.Data) {
		t.Error("Cloned extension data mismatch")
	}

	// Modify original, clone should be unchanged
	ext.Data[0] = 0xFF
	retrieved2, _ := cloned.Get(extensions.ExtensionTypeApplicationID)
	if retrieved2.Data[0] == 0xFF {
		t.Error("Clone was modified when original changed")
	}
}

// TestExtensionValidate tests extension validation.
func TestExtensionValidate(t *testing.T) {
	// Valid extension
	ext1 := &extensions.Extension{
		Type: extensions.ExtensionTypeApplicationID,
		Data: []byte{0x01},
	}

	if err := ext1.Validate(); err != nil {
		t.Errorf("Valid extension failed validation: %v", err)
	}

	// Nil data should fail
	ext2 := &extensions.Extension{
		Type: extensions.ExtensionTypeApplicationID,
		Data: nil,
	}

	if err := ext2.Validate(); err == nil {
		t.Error("Extension with nil data should fail validation")
	}

	// Unknown extension types are allowed (extensibility)
	ext3 := &extensions.Extension{
		Type: 0x9999, // Unknown type
		Data: []byte{0x01},
	}

	if err := ext3.Validate(); err != nil {
		t.Errorf("Unknown extension type should be allowed: %v", err)
	}
}
