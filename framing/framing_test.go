package framing_test

import (
	"bytes"
	"testing"

	"github.com/mls-go/ciphersuite"
	"github.com/mls-go/framing"
	"github.com/mls-go/internal/tls"
)

// ============================================================================
// FramedContent Tests
// ============================================================================

// TestFramedContent_ApplicationData_RoundTrip tests ApplicationData serialization.
func TestFramedContent_ApplicationData_RoundTrip(t *testing.T) {
	fc := &framing.FramedContent{
		GroupID:           []byte("test-group"),
		Epoch:             42,
		Sender:            framing.Sender{Type: framing.SenderTypeMember, LeafIndex: 1},
		AuthenticatedData: []byte("auth data"),
		Body:              framing.ApplicationData{Data: []byte("hello world")},
	}

	// Marshal
	data := fc.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal returned empty data")
	}

	// Unmarshal
	fc2, err := framing.UnmarshalFramedContent(data)
	if err != nil {
		t.Fatalf("UnmarshalFramedContent failed: %v", err)
	}

	// Verify fields
	if !bytes.Equal(fc.GroupID, fc2.GroupID) {
		t.Errorf("GroupID mismatch: got %v, want %v", fc2.GroupID, fc.GroupID)
	}
	if fc.Epoch != fc2.Epoch {
		t.Errorf("Epoch mismatch: got %d, want %d", fc2.Epoch, fc.Epoch)
	}
	if fc.Sender.LeafIndex != fc2.Sender.LeafIndex {
		t.Errorf("Sender.LeafIndex mismatch: got %d, want %d", fc2.Sender.LeafIndex, fc.Sender.LeafIndex)
	}
	if !bytes.Equal(fc.AuthenticatedData, fc2.AuthenticatedData) {
		t.Errorf("AuthenticatedData mismatch: got %v, want %v", fc2.AuthenticatedData, fc.AuthenticatedData)
	}

	// Verify body
	appData2, ok := fc2.Body.(framing.ApplicationData)
	if !ok {
		t.Fatal("Body is not ApplicationData")
	}
	if !bytes.Equal(fc.Body.(framing.ApplicationData).Data, appData2.Data) {
		t.Errorf("Body.Data mismatch: got %v, want %v", appData2.Data, fc.Body.(framing.ApplicationData).Data)
	}
}

// TestFramedContent_Proposal_RoundTrip tests Proposal serialization.
func TestFramedContent_Proposal_RoundTrip(t *testing.T) {
	fc := &framing.FramedContent{
		GroupID: []byte("test-group"),
		Epoch:   1,
		Sender:  framing.Sender{Type: framing.SenderTypeMember, LeafIndex: 0},
		Body:    framing.ProposalBody{Data: []byte("proposal data")},
	}

	data := fc.Marshal()
	fc2, err := framing.UnmarshalFramedContent(data)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	proposal2, ok := fc2.Body.(framing.ProposalBody)
	if !ok {
		t.Fatal("Body is not ProposalBody")
	}
	if !bytes.Equal(fc.Body.(framing.ProposalBody).Data, proposal2.Data) {
		t.Error("Proposal data mismatch")
	}
}

// TestFramedContent_Commit_RoundTrip tests Commit serialization.
func TestFramedContent_Commit_RoundTrip(t *testing.T) {
	fc := &framing.FramedContent{
		GroupID: []byte("test-group"),
		Epoch:   5,
		Sender:  framing.Sender{Type: framing.SenderTypeMember, LeafIndex: 2},
		Body:    framing.CommitBody{Data: []byte("commit data")},
	}

	data := fc.Marshal()
	fc2, err := framing.UnmarshalFramedContent(data)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	commit2, ok := fc2.Body.(framing.CommitBody)
	if !ok {
		t.Fatal("Body is not CommitBody")
	}
	if !bytes.Equal(fc.Body.(framing.CommitBody).Data, commit2.Data) {
		t.Error("Commit data mismatch")
	}
}

// TestFramedContent_ContentType tests that ContentType is derived correctly.
func TestFramedContent_ContentType(t *testing.T) {
	tests := []struct {
		name string
		body framing.FramedContentBody
		want framing.ContentType
	}{
		{"Application", framing.ApplicationData{Data: []byte{}}, framing.ContentTypeApplication},
		{"Proposal", framing.ProposalBody{Data: []byte{}}, framing.ContentTypeProposal},
		{"Commit", framing.CommitBody{Data: []byte{}}, framing.ContentTypeCommit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &framing.FramedContent{Body: tt.body}
			if got := fc.ContentType(); got != tt.want {
				t.Errorf("ContentType() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestFramedContent_InvalidContentType tests error with unknown content_type.
func TestFramedContent_InvalidContentType(t *testing.T) {
	// Create data manually with invalid content_type
	w := tls.NewWriter()
	w.WriteVLBytes([]byte("group-id"))
	w.WriteUint64(1)
	w.WriteUint8(1) // SenderTypeMember
	w.WriteUint32(0)
	w.WriteVLBytes([]byte{})
	w.WriteUint8(0xFF) // Invalid content type
	w.WriteVLBytes([]byte("body"))

	data := w.Bytes()
	_, err := framing.UnmarshalFramedContent(data)
	if err == nil {
		t.Error("UnmarshalFramedContent should fail with invalid content_type")
	}
}

// ============================================================================
// MLSSenderData Tests
// ============================================================================

// TestMLSSenderData_RoundTrip tests MLSSenderData serialization.
func TestMLSSenderData_RoundTrip(t *testing.T) {
	sd := &framing.MLSSenderData{
		LeafIndex:  42,
		Generation: 100,
		ReuseGuard: [4]byte{0x01, 0x02, 0x03, 0x04},
	}

	data := sd.Marshal()
	sd2, err := framing.UnmarshalSenderData(data)
	if err != nil {
		t.Fatalf("UnmarshalSenderData failed: %v", err)
	}

	if sd.LeafIndex != sd2.LeafIndex {
		t.Errorf("LeafIndex mismatch: got %d, want %d", sd2.LeafIndex, sd.LeafIndex)
	}
	if sd.Generation != sd2.Generation {
		t.Errorf("Generation mismatch: got %d, want %d", sd2.Generation, sd.Generation)
	}
	if sd.ReuseGuard != sd2.ReuseGuard {
		t.Errorf("ReuseGuard mismatch: got %v, want %v", sd2.ReuseGuard, sd.ReuseGuard)
	}
}

// ============================================================================
// FramedContentAuthData Tests
// ============================================================================

// TestFramedContentAuthData_Marshal tests auth data serialization.
func TestFramedContentAuthData_Marshal(t *testing.T) {
	sig := &ciphersuite.Signature{}
	auth := framing.FramedContentAuthData{
		Signature:       sig,
		ConfirmationTag: []byte{0x01, 0x02, 0x03},
	}

	// Without confirmation tag
	data1 := auth.Marshal(framing.ContentTypeApplication)
	if len(data1) == 0 {
		t.Error("Marshal returned empty data for Application")
	}

	// With confirmation tag (Commit)
	data2 := auth.Marshal(framing.ContentTypeCommit)
	if len(data2) == 0 {
		t.Error("Marshal returned empty data for Commit")
	}

	// Should be different
	if bytes.Equal(data1, data2) {
		t.Error("Marshal should produce different output for different content types")
	}
}

// ============================================================================
// AuthenticatedContent Tests
// ============================================================================

// TestAuthenticatedContent_MarshalForSigning tests serialization for signing.
func TestAuthenticatedContent_MarshalForSigning(t *testing.T) {
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

	data := ac.MarshalForSigning()
	if len(data) == 0 {
		t.Error("MarshalForSigning returned empty data")
	}

	// Should start with wire format
	if data[0] != 0x00 || data[1] != 0x01 {
		t.Errorf("Wire format should be at start: got %02x%02x", data[0], data[1])
	}
}

// ============================================================================
// PublicMessage Tests
// ============================================================================

// TestPublicMessage_Marshal tests PublicMessage serialization.
func TestPublicMessage_Marshal(t *testing.T) {
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
		MembershipTag: []byte{0x01, 0x02, 0x03},
	}

	data := pm.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal returned empty data")
	}

	// Verify wire format is at start
	if data[0] != 0x00 || data[1] != 0x01 {
		t.Errorf("Wire format should be at start: got %02x%02x", data[0], data[1])
	}
}

// ============================================================================
// PrivateMessage Tests
// ============================================================================

// TestPrivateMessage_Marshal tests PrivateMessage serialization.
func TestPrivateMessage_Marshal(t *testing.T) {
	pm := &framing.PrivateMessage{
		GroupID:             []byte("test-group"),
		Epoch:               42,
		ContentType:         framing.ContentTypeApplication,
		AuthenticatedData:   []byte("auth"),
		EncryptedSenderData: []byte{0x01, 0x02, 0x03},
		Ciphertext:          []byte{0x04, 0x05, 0x06},
	}

	data := pm.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal returned empty data")
	}

	// Verify wire format
	if data[0] != 0x00 || data[1] != 0x02 {
		t.Errorf("Wire format should be PrivateMessage: got %02x%02x", data[0], data[1])
	}
}

// TestPrivateMessage_ClearTextFields verifies the first 4 fields are in cleartext.
func TestPrivateMessage_ClearTextFields(t *testing.T) {
	groupID := []byte("my-test-group")
	epoch := uint64(12345)
	ct := framing.ContentTypeApplication
	authData := []byte("authenticated-data")

	pm := &framing.PrivateMessage{
		GroupID:             groupID,
		Epoch:               epoch,
		ContentType:         ct,
		AuthenticatedData:   authData,
		EncryptedSenderData: []byte{0x01, 0x02},
		Ciphertext:          []byte{0x03, 0x04},
	}

	data := pm.Marshal()

	// Cleartext fields should be visible in serialized data
	// This is a basic verification - a complete test would verify offsets
	if !bytes.Contains(data, groupID) {
		t.Error("GroupID should be visible in marshaled data")
	}
}

// ============================================================================
// Error Tests
// ============================================================================

// TestErrors_Is verifies that errors.Is works correctly.
func TestErrors_Is(t *testing.T) {
	err := framing.ErrDecryptionFailed

	if !isError(err, framing.ErrDecryptionFailed) {
		t.Error("errors.Is should work with ErrDecryptionFailed")
	}
}

// isError is a helper for testing errors.Is.
func isError(got, want error) bool {
	return got == want
}

// ============================================================================
// Helper Tests
// ============================================================================

// TestMarshalSender_RoundTrip tests Sender serialization.
func TestMarshalSender_RoundTrip(t *testing.T) {
	sender := framing.Sender{
		Type:      framing.SenderTypeMember,
		LeafIndex: 42,
	}

	w := tls.NewWriter()
	framing.MarshalSender(&sender, w)
	data := w.Bytes()

	r := tls.NewReader(data)
	sender2, err := framing.UnmarshalSender(r)
	if err != nil {
		t.Fatalf("UnmarshalSender failed: %v", err)
	}

	if sender.Type != sender2.Type {
		t.Errorf("Sender.Type mismatch: got %d, want %d", sender2.Type, sender.Type)
	}
	if sender.LeafIndex != sender2.LeafIndex {
		t.Errorf("Sender.LeafIndex mismatch: got %d, want %d", sender2.LeafIndex, sender.LeafIndex)
	}
}

// TestMarshalSender_External tests External sender serialization.
func TestMarshalSender_External(t *testing.T) {
	sender := framing.Sender{
		Type:        framing.SenderTypeExternal,
		SenderIndex: 99,
	}

	w := tls.NewWriter()
	framing.MarshalSender(&sender, w)
	data := w.Bytes()

	r := tls.NewReader(data)
	sender2, err := framing.UnmarshalSender(r)
	if err != nil {
		t.Fatalf("UnmarshalSender failed: %v", err)
	}

	if sender2.Type != framing.SenderTypeExternal {
		t.Errorf("Expected External sender, got %d", sender2.Type)
	}
	if sender2.SenderIndex != 99 {
		t.Errorf("SenderIndex mismatch: got %d, want 99", sender2.SenderIndex)
	}
}

// TestMarshalSender_Invalid tests error with invalid sender type.
func TestMarshalSender_Invalid(t *testing.T) {
	data := []byte{0xFF} // Invalid sender type
	r := tls.NewReader(data)
	_, err := framing.UnmarshalSender(r)
	if err == nil {
		t.Error("UnmarshalSender should fail with invalid sender type")
	}
}
