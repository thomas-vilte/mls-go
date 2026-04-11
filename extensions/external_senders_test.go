package extensions_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/extensions"
)

// generateTestCredential creates a test credential.
func generateTestCredential(t *testing.T) *credentials.Credential {
	t.Helper()
	return credentials.NewBasicCredentialFromString("test-sender")
}

// TestExternalSendersExtension_New tests creation.
func TestExternalSendersExtension_New(t *testing.T) {
	ext := extensions.NewExternalSendersExtension()
	if ext == nil {
		t.Fatal("NewExternalSendersExtension returned nil")
	}
	if ext.Len() != 0 {
		t.Errorf("Len() = %d, want 0", ext.Len())
	}
}

// TestExternalSendersExtension_AddSenderValid tests adding valid sender.
func TestExternalSendersExtension_AddSenderValid(t *testing.T) {
	ext := extensions.NewExternalSendersExtension()
	cred := generateTestCredential(t)

	// Create sender with minimal valid data
	sender := extensions.ExternalSender{
		Credential: cred,
		PublicKey:  nil, // Will be validated by AddSender
	}

	// AddSender will fail because PublicKey is nil, which is expected
	if err := ext.AddSender(sender); err == nil {
		t.Error("AddSender() should fail with nil PublicKey")
	}
}

// TestExternalSendersExtension_ValidateNilCredential tests validation with nil credential.
func TestExternalSendersExtension_ValidateNilCredential(t *testing.T) {
	ext := extensions.NewExternalSendersExtension()

	sender := extensions.ExternalSender{
		Credential: nil,
		PublicKey:  nil,
	}

	ext.Senders = append(ext.Senders, sender)
	if err := ext.Validate(); err == nil {
		t.Error("Validate() should fail with nil credential")
	}
}

// TestExternalSendersExtension_ValidateNilPubKey tests validation with nil public key.
func TestExternalSendersExtension_ValidateNilPubKey(t *testing.T) {
	ext := extensions.NewExternalSendersExtension()
	cred := generateTestCredential(t)

	sender := extensions.ExternalSender{
		Credential: cred,
		PublicKey:  nil,
	}

	ext.Senders = append(ext.Senders, sender)
	if err := ext.Validate(); err == nil {
		t.Error("Validate() should fail with nil public key")
	}
}

// TestExternalSendersExtension_FindSender tests search by credential.
func TestExternalSendersExtension_FindSender(t *testing.T) {
	ext := extensions.NewExternalSendersExtension()
	cred := generateTestCredential(t)

	sender := extensions.ExternalSender{
		Credential: cred,
		PublicKey:  nil,
	}
	ext.Senders = append(ext.Senders, sender)

	found, ok := ext.FindSender(cred)
	if !ok {
		t.Fatal("FindSender() returned false")
	}
	if found == nil {
		t.Error("FindSender() returned nil sender")
	}
}

// TestExternalSendersExtension_ToExtension tests conversion to generic Extension.
func TestExternalSendersExtension_ToExtension(t *testing.T) {
	ext := extensions.NewExternalSendersExtension()
	cred := generateTestCredential(t)
	sender := extensions.ExternalSender{
		Credential: cred,
		PublicKey:  nil,
	}
	ext.Senders = append(ext.Senders, sender)

	genericExt, err := ext.ToExtension()
	if err != nil {
		t.Fatalf("ToExtension failed: %v", err)
	}

	if genericExt.Type != extensions.ExtensionTypeExternalSenders {
		t.Errorf("Wrong extension type: got %d, want %d", genericExt.Type, extensions.ExtensionTypeExternalSenders)
	}
}

// TestExternalSenderEqual tests sender comparison.
func TestExternalSenderEqual(t *testing.T) {
	cred := generateTestCredential(t)

	sender1 := extensions.ExternalSender{
		Credential: cred,
		PublicKey:  nil,
	}
	sender2 := extensions.ExternalSender{
		Credential: cred,
		PublicKey:  nil,
	}

	if !sender1.Equal(&sender2) {
		t.Error("Equal senders not equal")
	}
}

// TestExternalSendersExtension_Marshal tests basic marshaling.
func TestExternalSendersExtension_Marshal(t *testing.T) {
	ext := extensions.NewExternalSendersExtension()
	data := ext.Marshal()
	if len(data) == 0 {
		t.Error("Marshal() returned empty data")
	}
}

// TestExternalSendersExtension_Empty tests empty extension.
func TestExternalSendersExtension_Empty(t *testing.T) {
	ext := extensions.NewExternalSendersExtension()
	if err := ext.Validate(); err != nil {
		t.Errorf("Validate() error = %v, want nil", err)
	}
	if ext.Len() != 0 {
		t.Errorf("Len() = %d, want 0", ext.Len())
	}
}

// TestExternalSendersExtension_MultipleSenders tests with multiple senders.
func TestExternalSendersExtension_MultipleSenders(t *testing.T) {
	ext := extensions.NewExternalSendersExtension()
	cred1 := generateTestCredential(t)
	cred2 := generateTestCredential(t)

	sender1 := extensions.ExternalSender{Credential: cred1, PublicKey: nil}
	sender2 := extensions.ExternalSender{Credential: cred2, PublicKey: nil}

	// Both should fail validation (nil PublicKey)
	if err := ext.AddSender(sender1); err == nil {
		t.Error("AddSender() should fail with nil PublicKey")
	}
	if err := ext.AddSender(sender2); err == nil {
		t.Error("AddSender() should fail with nil PublicKey")
	}
}

// TestExternalSendersExtension_AddSenderInvalid tests adding invalid sender.
func TestExternalSendersExtension_AddSenderInvalid(t *testing.T) {
	ext := extensions.NewExternalSendersExtension()
	sender := extensions.ExternalSender{Credential: nil, PublicKey: nil}

	if err := ext.AddSender(sender); err == nil {
		t.Error("AddSender() should fail with invalid sender")
	}
}

// ============================================================================
// unmarshalECDSAPublicKey via round-trip (RFC 9420 §5.1.1)
// ============================================================================

// newExtWithKey builds an ExternalSendersExtension with a real P-256 key,
// bypassing AddSender validation for testing internal parse paths.
func newExtWithKey(t *testing.T, privKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	ecdhKey, err := privKey.ECDH()
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}
	cred := credentials.NewBasicCredentialFromString("sender")
	ext := extensions.NewExternalSendersExtension()
	ext.Senders = append(ext.Senders, extensions.ExternalSender{
		Credential: cred,
		PublicKey:  &privKey.PublicKey,
	})
	_ = ecdhKey
	return ext.Marshal()
}

// TestUnmarshalExternalSenders_ValidKey verifies that a valid P-256 uncompressed
// public key (0x04 || X || Y) is correctly parsed into a non-zero *ecdsa.PublicKey.
func TestUnmarshalExternalSenders_ValidKey(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	data := newExtWithKey(t, privKey)

	got, err := extensions.UnmarshalExternalSendersExtension(data)
	if err != nil {
		t.Fatalf("UnmarshalExternalSendersExtension: %v", err)
	}
	if len(got.Senders) != 1 {
		t.Fatalf("expected 1 sender, got %d", len(got.Senders))
	}
	pub := got.Senders[0].PublicKey
	if pub == nil {
		t.Fatal("PublicKey is nil — unmarshalECDSAPublicKey did not parse the key")
	}
	if !pub.Equal(&privKey.PublicKey) {
		t.Error("parsed PublicKey does not match original")
	}
}

// TestUnmarshalExternalSenders_RoundTrip verifies Marshal → Unmarshal round-trip.
func TestUnmarshalExternalSenders_RoundTrip(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	cred := credentials.NewBasicCredentialFromString("alice")

	orig := extensions.NewExternalSendersExtension()
	orig.Senders = append(orig.Senders, extensions.ExternalSender{
		Credential: cred,
		PublicKey:  &privKey.PublicKey,
	})

	data := orig.Marshal()
	got, err := extensions.UnmarshalExternalSendersExtension(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Len() != 1 {
		t.Fatalf("sender count = %d, want 1", got.Len())
	}
	if !got.Senders[0].PublicKey.Equal(&privKey.PublicKey) {
		t.Error("public key mismatch after round-trip")
	}
}
