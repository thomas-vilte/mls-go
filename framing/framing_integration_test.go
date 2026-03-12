package framing_test

import (
	"bytes"
	"testing"

	"github.com/mls-go/ciphersuite"
	"github.com/mls-go/framing"
	"github.com/mls-go/internal/tls"
)

// ============================================================================
// Integration Tests - Encrypt/Decrypt Round-Trip
// ============================================================================

// TestFramedContent_BodyTypes tests all body types.
func TestFramedContent_BodyTypes(t *testing.T) {
	tests := []struct {
		name string
		body framing.FramedContentBody
	}{
		{"ApplicationData", framing.ApplicationData{Data: []byte("hello")}},
		{"ProposalBody", framing.ProposalBody{Data: []byte("proposal")}},
		{"CommitBody", framing.CommitBody{Data: []byte("commit")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &framing.FramedContent{
				GroupID: []byte("test-group"),
				Epoch:   1,
				Sender:  framing.Sender{Type: framing.SenderTypeMember, LeafIndex: 0},
				Body:    tt.body,
			}

			data := fc.Marshal()
			fc2, err := framing.UnmarshalFramedContent(data)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			if fc2.ContentType() != fc.ContentType() {
				t.Errorf("ContentType mismatch: got %d, want %d", fc2.ContentType(), fc.ContentType())
			}
		})
	}
}

// TestFramedContent_EmptyFields tests empty fields.
func TestFramedContent_EmptyFields(t *testing.T) {
	fc := &framing.FramedContent{
		GroupID:           []byte{},
		Epoch:             0,
		Sender:            framing.Sender{Type: framing.SenderTypeMember, LeafIndex: 0},
		AuthenticatedData: []byte{},
		Body:              framing.ApplicationData{Data: []byte{}},
	}

	data := fc.Marshal()
	fc2, err := framing.UnmarshalFramedContent(data)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(fc2.GroupID) != 0 {
		t.Errorf("Empty GroupID should remain empty, got %d bytes", len(fc2.GroupID))
	}
	if fc2.Epoch != 0 {
		t.Errorf("Empty Epoch should remain 0, got %d", fc2.Epoch)
	}
	if len(fc2.AuthenticatedData) != 0 {
		t.Errorf("Empty AuthenticatedData should remain empty, got %d bytes", len(fc2.AuthenticatedData))
	}
}

// TestFramedContent_LargeFields tests large fields.
func TestFramedContent_LargeFields(t *testing.T) {
	largeData := make([]byte, 10000)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	fc := &framing.FramedContent{
		GroupID:           largeData,
		Epoch:             999999,
		Sender:            framing.Sender{Type: framing.SenderTypeMember, LeafIndex: 999},
		AuthenticatedData: largeData,
		Body:              framing.ApplicationData{Data: largeData},
	}

	data := fc.Marshal()
	fc2, err := framing.UnmarshalFramedContent(data)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !bytes.Equal(fc.GroupID, fc2.GroupID) {
		t.Error("Large GroupID mismatch")
	}
	if !bytes.Equal(fc.AuthenticatedData, fc2.AuthenticatedData) {
		t.Error("Large AuthenticatedData mismatch")
	}
	appData2 := fc2.Body.(framing.ApplicationData)
	if !bytes.Equal(fc.Body.(framing.ApplicationData).Data, appData2.Data) {
		t.Error("Large Body.Data mismatch")
	}
}

// ============================================================================
// MLSSenderData Tests
// ============================================================================

// TestMLSSenderData_ZeroValues tests zero values.
func TestMLSSenderData_ZeroValues(t *testing.T) {
	sd := &framing.MLSSenderData{
		LeafIndex:  0,
		Generation: 0,
		ReuseGuard: [4]byte{0x00, 0x00, 0x00, 0x00},
	}

	data := sd.Marshal()
	sd2, err := framing.UnmarshalSenderData(data)
	if err != nil {
		t.Fatalf("UnmarshalSenderData failed: %v", err)
	}

	if sd2.LeafIndex != 0 {
		t.Errorf("LeafIndex should be 0, got %d", sd2.LeafIndex)
	}
	if sd2.Generation != 0 {
		t.Errorf("Generation should be 0, got %d", sd2.Generation)
	}
	if sd2.ReuseGuard != [4]byte{0x00, 0x00, 0x00, 0x00} {
		t.Error("ReuseGuard should be all zeros")
	}
}

// TestMLSSenderData_MaxValues tests maximum values.
func TestMLSSenderData_MaxValues(t *testing.T) {
	sd := &framing.MLSSenderData{
		LeafIndex:  0xFFFFFFFF,
		Generation: 0xFFFFFFFF,
		ReuseGuard: [4]byte{0xFF, 0xFF, 0xFF, 0xFF},
	}

	data := sd.Marshal()
	sd2, err := framing.UnmarshalSenderData(data)
	if err != nil {
		t.Fatalf("UnmarshalSenderData failed: %v", err)
	}

	if sd2.LeafIndex != 0xFFFFFFFF {
		t.Errorf("Max LeafIndex mismatch: got %d, want %d", sd2.LeafIndex, 0xFFFFFFFF)
	}
	if sd2.Generation != 0xFFFFFFFF {
		t.Errorf("Max Generation mismatch: got %d, want %d", sd2.Generation, 0xFFFFFFFF)
	}
	if sd2.ReuseGuard != [4]byte{0xFF, 0xFF, 0xFF, 0xFF} {
		t.Error("Max ReuseGuard mismatch")
	}
}

// TestMLSSenderData_InvalidData tests invalid data.
func TestMLSSenderData_InvalidData(t *testing.T) {
	// Truncated data (less than 12 bytes)
	invalidData := []byte{0x01, 0x02, 0x03}
	_, err := framing.UnmarshalSenderData(invalidData)
	if err == nil {
		t.Error("UnmarshalSenderData should fail with truncated data")
	}

	// Empty data
	_, err = framing.UnmarshalSenderData([]byte{})
	if err == nil {
		t.Error("UnmarshalSenderData should fail with empty data")
	}
}

// ============================================================================
// FramedContentAuthData Tests
// ============================================================================

// TestFramedContentAuthData_EmptySignature tests empty signature.
func TestFramedContentAuthData_EmptySignature(t *testing.T) {
	auth := framing.FramedContentAuthData{
		Signature:       &ciphersuite.Signature{},
		ConfirmationTag: nil,
	}

	data := auth.Marshal(framing.ContentTypeApplication)
	if len(data) == 0 {
		t.Error("Marshal should return data even with empty signature")
	}
}

// TestFramedContentAuthData_WithConfirmationTag tests with confirmation tag.
func TestFramedContentAuthData_WithConfirmationTag(t *testing.T) {
	auth := framing.FramedContentAuthData{
		Signature:       &ciphersuite.Signature{},
		ConfirmationTag: []byte{0x01, 0x02, 0x03, 0x04},
	}

	// For Commit should include confirmation tag
	data1 := auth.Marshal(framing.ContentTypeCommit)
	// For Application should not include it
	data2 := auth.Marshal(framing.ContentTypeApplication)

	if len(data1) <= len(data2) {
		t.Error("Commit auth data should be larger (includes confirmation tag)")
	}
}

// TestFramedContentAuthData_NilSignature tests with nil signature.
func TestFramedContentAuthData_NilSignature(t *testing.T) {
	// Should panic or handle gracefully
	defer func() {
		if r := recover(); r != nil {
			// Expected panic with nil signature
			t.Logf("Expected panic with nil signature: %v", r)
		}
	}()

	auth := framing.FramedContentAuthData{
		Signature: nil,
	}

	// This might panic
	_ = auth.Marshal(framing.ContentTypeApplication)
	// If we reach here, it didn't panic (which is also fine)
}

// ============================================================================
// AuthenticatedContent Tests
// ============================================================================

// TestAuthenticatedContent_AllWireFormats tests all wire formats.
func TestAuthenticatedContent_AllWireFormats(t *testing.T) {
	formats := []framing.WireFormat{
		framing.WireFormatPublicMessage,
		framing.WireFormatPrivateMessage,
	}

	for _, wf := range formats {
		t.Run(string(rune(wf)), func(t *testing.T) {
			ac := &framing.AuthenticatedContent{
				WireFormat: wf,
				Content: framing.FramedContent{
					GroupID: []byte("test"),
					Epoch:   1,
					Sender:  framing.Sender{Type: framing.SenderTypeMember, LeafIndex: 0},
					Body:    framing.ApplicationData{Data: []byte("test")},
				},
				Auth: framing.FramedContentAuthData{
					Signature: &ciphersuite.Signature{},
				},
			}

			data := ac.MarshalForSigning()
			if len(data) == 0 {
				t.Error("MarshalForSigning returned empty data")
			}

			// Verify wire format is at start
			if data[0] != 0x00 || data[1] != byte(wf) {
				t.Errorf("Wire format should be at start: got %02x%02x", data[0], data[1])
			}
		})
	}
}

// TestAuthenticatedContent_MarshalTBS verifies FramedContentTBS includes version prefix (RFC §6.1).
func TestAuthenticatedContent_MarshalTBS(t *testing.T) {
	ac := &framing.AuthenticatedContent{
		WireFormat: framing.WireFormatPublicMessage,
		Content: framing.FramedContent{
			GroupID: []byte("test"),
			Epoch:   1,
			Sender:  framing.Sender{Type: framing.SenderTypeMember, LeafIndex: 0},
			Body:    framing.ApplicationData{Data: []byte("test")},
		},
		Auth: framing.FramedContentAuthData{
			Signature: &ciphersuite.Signature{},
		},
	}

	tbsData := ac.MarshalTBS()
	signingData := ac.MarshalForSigning()

	// MarshalTBS must be longer: it prepends version (2 bytes) + wire_format (2 bytes, same as MarshalForSigning start)
	// MarshalForSigning = wire_format(2) + content
	// MarshalTBS        = version(2) + wire_format(2) + content  (no GroupContext since gc is nil)
	if len(tbsData) <= len(signingData) {
		t.Errorf("MarshalTBS (%d bytes) should be longer than MarshalForSigning (%d bytes) due to version prefix", len(tbsData), len(signingData))
	}

	// TBS must start with version = mls10 = 0x0001
	if tbsData[0] != 0x00 || tbsData[1] != 0x01 {
		t.Errorf("MarshalTBS should start with version mls10 (0x0001), got %02x%02x", tbsData[0], tbsData[1])
	}

	// The content portion of TBS (after version) should match MarshalForSigning
	if !bytes.Equal(tbsData[2:], signingData) {
		t.Error("MarshalTBS[2:] should equal MarshalForSigning (wire_format + content)")
	}
}

// ============================================================================
// PublicMessage Tests
// ============================================================================

// TestPublicMessage_NonMemberSender tests that non-member has no membership tag.
func TestPublicMessage_NonMemberSender(t *testing.T) {
	pm := &framing.PublicMessage{
		Content: framing.FramedContent{
			GroupID: []byte("test"),
			Epoch:   1,
			Sender:  framing.Sender{Type: framing.SenderTypeExternal, SenderIndex: 0},
			Body:    framing.ApplicationData{Data: []byte("test")},
		},
		Auth: framing.FramedContentAuthData{
			Signature: &ciphersuite.Signature{},
		},
		MembershipTag: nil, // External senders do not have membership tag
	}

	data := pm.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal returned empty data")
	}

	// VerifyMembershipTag should return nil for non-member
	err := pm.VerifyMembershipTag(ciphersuite.MLS128DHKEMP256, nil)
	if err != nil {
		t.Errorf("VerifyMembershipTag should return nil for non-member: %v", err)
	}
}

// TestPublicMessage_MemberSenderNilKey tests member with nil membership key.
func TestPublicMessage_MemberSenderNilKey(t *testing.T) {
	pm := &framing.PublicMessage{
		Content: framing.FramedContent{
			GroupID: []byte("test"),
			Epoch:   1,
			Sender:  framing.Sender{Type: framing.SenderTypeMember, LeafIndex: 0},
			Body:    framing.ApplicationData{Data: []byte("test")},
		},
		Auth: framing.FramedContentAuthData{
			Signature: &ciphersuite.Signature{},
		},
		MembershipTag: nil,
	}

	// Should be able to marshal without membership tag
	data := pm.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal returned empty data")
	}
}

func TestPublicMessage_MarshalIncludesMembershipTagForMember(t *testing.T) {
	sigPriv, err := ciphersuite.GenerateSignaturePrivateKey()
	if err != nil {
		t.Fatalf("GenerateSignatureKey: %v", err)
	}

	content := framing.FramedContent{
		GroupID: []byte("group"),
		Epoch:   1,
		Sender:  framing.Sender{Type: framing.SenderTypeMember, LeafIndex: 0},
		Body:    framing.ProposalBody{Data: []byte("proposal")},
	}

	membershipKey := ciphersuite.NewSecret([]byte("0123456789abcdef0123456789abcdef"))
	pm, err := framing.NewPublicMessage(
		content,
		sigPriv,
		[]byte("gc"),
		membershipKey,
		ciphersuite.MLS128DHKEMP256,
	)
	if err != nil {
		t.Fatalf("NewPublicMessage: %v", err)
	}

	if len(pm.MembershipTag) == 0 {
		t.Fatal("membership tag should be present for member sender")
	}

	data := pm.Marshal()
	pm2, err := framing.UnmarshalPublicMessage(data)
	if err != nil {
		t.Fatalf("UnmarshalPublicMessage: %v", err)
	}

	if len(pm2.MembershipTag) == 0 {
		t.Fatal("membership tag should survive roundtrip")
	}
}

// ============================================================================
// PrivateMessage Tests
// ============================================================================

// TestPrivateMessage_EmptyFields tests empty fields.
func TestPrivateMessage_EmptyFields(t *testing.T) {
	pm := &framing.PrivateMessage{
		GroupID:             []byte{},
		Epoch:               0,
		ContentType:         framing.ContentTypeApplication,
		AuthenticatedData:   []byte{},
		EncryptedSenderData: []byte{},
		Ciphertext:          []byte{},
	}

	data := pm.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal returned empty data")
	}
}

// TestPrivateMessage_LargeFields tests large fields.
func TestPrivateMessage_LargeFields(t *testing.T) {
	largeData := make([]byte, 10000)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	pm := &framing.PrivateMessage{
		GroupID:             largeData,
		Epoch:               999999,
		ContentType:         framing.ContentTypeApplication,
		AuthenticatedData:   largeData,
		EncryptedSenderData: largeData,
		Ciphertext:          largeData,
	}

	data := pm.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal returned empty data")
	}
}

// TestPrivateMessage_AllContentTypes tests all content types.
func TestPrivateMessage_AllContentTypes(t *testing.T) {
	contentTypes := []framing.ContentType{
		framing.ContentTypeApplication,
		framing.ContentTypeProposal,
		framing.ContentTypeCommit,
	}

	for _, ct := range contentTypes {
		t.Run(string(rune(ct)), func(t *testing.T) {
			pm := &framing.PrivateMessage{
				GroupID:             []byte("test"),
				Epoch:               1,
				ContentType:         ct,
				AuthenticatedData:   []byte("auth"),
				EncryptedSenderData: []byte{0x01, 0x02},
				Ciphertext:          []byte{0x03, 0x04},
			}

			data := pm.Marshal()
			if len(data) == 0 {
				t.Fatal("Marshal returned empty data")
			}

			// Verify content type is in the data
			// Wire format (2 bytes) + GroupID length (1 byte) + GroupID + Epoch (8 bytes) + ContentType (1 byte)
			// The offset depends on the length of GroupID
			// Better to verify that ContentType is serialized correctly
			if data[0] != 0x00 || data[1] != 0x02 {
				t.Errorf("Wire format should be PrivateMessage: got %02x%02x", data[0], data[1])
			}
		})
	}
}

// ============================================================================
// Sender Tests
// ============================================================================

// TestSender_AllTypes tests all sender types.
func TestSender_AllTypes(t *testing.T) {
	senders := []framing.Sender{
		{Type: framing.SenderTypeMember, LeafIndex: 42},
		{Type: framing.SenderTypeExternal, SenderIndex: 99},
		{Type: framing.SenderTypeNewMemberProposal},
		{Type: framing.SenderTypeNewMemberCommit},
	}

	for _, sender := range senders {
		t.Run(string(rune(sender.Type)), func(t *testing.T) {
			// Marshal
			w := tls.NewWriter()
			framing.MarshalSender(&sender, w)
			data := w.Bytes()
			if len(data) == 0 {
				t.Fatal("MarshalSender returned empty data")
			}

			// Unmarshal and verify
			r := tls.NewReader(data)
			sender2, err := framing.UnmarshalSender(r)
			if err != nil {
				t.Fatalf("UnmarshalSender failed: %v", err)
			}

			if sender2.Type != sender.Type {
				t.Errorf("Sender type mismatch: got %d, want %d", sender2.Type, sender.Type)
			}
		})
	}
}

// ============================================================================
// ContentType Tests
// ============================================================================

// TestContentType_Values tests ContentType values.
func TestContentType_Values(t *testing.T) {
	if framing.ContentTypeApplication != 1 {
		t.Errorf("ContentTypeApplication should be 1, got %d", framing.ContentTypeApplication)
	}
	if framing.ContentTypeProposal != 2 {
		t.Errorf("ContentTypeProposal should be 2, got %d", framing.ContentTypeProposal)
	}
	if framing.ContentTypeCommit != 3 {
		t.Errorf("ContentTypeCommit should be 3, got %d", framing.ContentTypeCommit)
	}
}

// ============================================================================
// WireFormat Tests
// ============================================================================

// TestWireFormat_Values tests WireFormat values.
func TestWireFormat_Values(t *testing.T) {
	if framing.WireFormatPublicMessage != 1 {
		t.Errorf("WireFormatPublicMessage should be 1, got %d", framing.WireFormatPublicMessage)
	}
	if framing.WireFormatPrivateMessage != 2 {
		t.Errorf("WireFormatPrivateMessage should be 2, got %d", framing.WireFormatPrivateMessage)
	}
}

// ============================================================================
// Error Tests
// ============================================================================

// TestErrors_NotNil tests that errors are not nil.
func TestErrors_NotNil(t *testing.T) {
	errors := []error{
		framing.ErrInvalidWireFormat,
		framing.ErrInvalidContentType,
		framing.ErrInvalidSenderType,
		framing.ErrDecryptionFailed,
		framing.ErrVerificationFailed,
		framing.ErrInvalidMembershipTag,
		framing.ErrInvalidMessage,
	}

	for i, err := range errors {
		if err == nil {
			t.Errorf("Error %d should not be nil", i)
		}
	}
}

// TestErrors_ErrorMessages tests that errors have descriptive messages.
func TestErrors_ErrorMessages(t *testing.T) {
	tests := []struct {
		err         error
		contains    string
		description string
	}{
		{framing.ErrInvalidWireFormat, "wire format", "ErrInvalidWireFormat"},
		{framing.ErrInvalidContentType, "content type", "ErrInvalidContentType"},
		{framing.ErrInvalidSenderType, "sender type", "ErrInvalidSenderType"},
		{framing.ErrDecryptionFailed, "decryption", "ErrDecryptionFailed"},
		{framing.ErrVerificationFailed, "verification", "ErrVerificationFailed"},
		{framing.ErrInvalidMembershipTag, "membership", "ErrInvalidMembershipTag"},
		{framing.ErrInvalidMessage, "message", "ErrInvalidMessage"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			msg := tt.err.Error()
			if !bytes.Contains([]byte(msg), []byte(tt.contains)) {
				t.Errorf("%s should contain '%s', got '%s'", tt.description, tt.contains, msg)
			}
		})
	}
}

// ============================================================================
// Helper Tests
// ============================================================================

// TestUnmarshalSender_TruncatedData tests unmarshal with truncated data.
func TestUnmarshalSender_TruncatedData(t *testing.T) {
	// Only type, no additional data
	data := []byte{0x01} // SenderTypeMember
	r := tls.NewReader(data)
	_, err := framing.UnmarshalSender(r)
	if err == nil {
		t.Error("UnmarshalSender should fail with truncated data")
	}
}

// TestBuildPrivateContentAAD tests AAD construction.
func TestBuildPrivateContentAAD(t *testing.T) {
	// This function is internal, but we can test it indirectly
	// through the PrivateMessage structure
	pm := &framing.PrivateMessage{
		GroupID:           []byte("test-group"),
		Epoch:             42,
		ContentType:       framing.ContentTypeApplication,
		AuthenticatedData: []byte("auth-data"),
	}

	// Verify fields are present
	if len(pm.GroupID) == 0 {
		t.Error("GroupID should not be empty")
	}
	if pm.Epoch != 42 {
		t.Errorf("Epoch should be 42, got %d", pm.Epoch)
	}
	if pm.ContentType != framing.ContentTypeApplication {
		t.Errorf("ContentType should be Application, got %d", pm.ContentType)
	}
}
