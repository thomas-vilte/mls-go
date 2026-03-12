package framing_test

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
)

// ============================================================================
// MLSMessage Tests
// ============================================================================

// TestMLSMessage_PublicMessage_RoundTrip tests Marshal/Unmarshal of MLSMessage with PublicMessage.
func TestMLSMessage_PublicMessage_RoundTrip(t *testing.T) {
	pm := &framing.PublicMessage{
		Content: framing.FramedContent{
			GroupID: []byte("test-group"),
			Epoch:   42,
			Sender:  framing.Sender{Type: framing.SenderTypeMember, LeafIndex: 3},
			Body:    framing.ApplicationData{Data: []byte("hello")},
		},
		Auth: framing.FramedContentAuthData{
			Signature: &ciphersuite.Signature{},
		},
		MembershipTag: []byte{0xAA, 0xBB},
	}

	msg := framing.NewMLSMessagePublic(pm)
	data := msg.Marshal()

	if len(data) == 0 {
		t.Fatal("Marshal returned empty data")
	}

	// Must start with version = mls10 = 0x0001
	if data[0] != 0x00 || data[1] != 0x01 {
		t.Errorf("Version should be mls10 (0x0001), got %02x%02x", data[0], data[1])
	}

	// Must follow with wire_format = PublicMessage = 0x0001
	if data[2] != 0x00 || data[3] != 0x01 {
		t.Errorf("WireFormat should be PublicMessage (0x0001), got %02x%02x", data[2], data[3])
	}

	// Round-trip
	msg2, err := framing.UnmarshalMLSMessage(data)
	if err != nil {
		t.Fatalf("UnmarshalMLSMessage failed: %v", err)
	}
	if msg2.PublicMessage == nil {
		t.Fatal("Expected PublicMessage, got nil")
	}
	if msg2.WireFormat() != framing.WireFormatPublicMessage {
		t.Errorf("WireFormat mismatch: got %d, want %d", msg2.WireFormat(), framing.WireFormatPublicMessage)
	}
}

// TestMLSMessage_PrivateMessage_RoundTrip tests Marshal/Unmarshal with PrivateMessage.
func TestMLSMessage_PrivateMessage_RoundTrip(t *testing.T) {
	pm := &framing.PrivateMessage{
		GroupID:             []byte("test-group"),
		Epoch:               7,
		ContentType:         framing.ContentTypeApplication,
		AuthenticatedData:   []byte("auth"),
		EncryptedSenderData: []byte{0x01, 0x02, 0x03},
		Ciphertext:          []byte{0x04, 0x05, 0x06},
	}

	msg := framing.NewMLSMessagePrivate(pm)
	data := msg.Marshal()

	if len(data) == 0 {
		t.Fatal("Marshal returned empty data")
	}

	// First two bytes should be the version (mls10 = 0x0001)
	if data[0] != 0x00 || data[1] != 0x01 {
		t.Errorf("Version should be mls10 (0x0001), got %02x%02x", data[0], data[1])
	}

	// wire_format = PrivateMessage = 0x0002
	if data[2] != 0x00 || data[3] != 0x02 {
		t.Errorf("WireFormat should be PrivateMessage (0x0002), got %02x%02x", data[2], data[3])
	}

	// Round-trip
	msg2, err := framing.UnmarshalMLSMessage(data)
	if err != nil {
		t.Fatalf("UnmarshalMLSMessage failed: %v", err)
	}
	if msg2.PrivateMessage == nil {
		t.Fatal("Expected PrivateMessage, got nil")
	}
	if msg2.WireFormat() != framing.WireFormatPrivateMessage {
		t.Errorf("WireFormat mismatch: got %d", msg2.WireFormat())
	}
}

// TestMLSMessage_OpaquePayloads tests Welcome/GroupInfo/KeyPackage as opaque payloads.
func TestMLSMessage_OpaquePayloads(t *testing.T) {
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	cases := []struct {
		name string
		msg  *framing.MLSMessage
		wf   framing.WireFormat
	}{
		{"Welcome", &framing.MLSMessage{Welcome: payload}, framing.WireFormatWelcome},
		{"GroupInfo", &framing.MLSMessage{GroupInfo: payload}, framing.WireFormatGroupInfo},
		{"KeyPackage", &framing.MLSMessage{KeyPackage: payload}, framing.WireFormatKeyPackage},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.msg.WireFormat() != tc.wf {
				t.Errorf("WireFormat() = %d, want %d", tc.msg.WireFormat(), tc.wf)
			}

			data := tc.msg.Marshal()
			msg2, err := framing.UnmarshalMLSMessage(data)
			if err != nil {
				t.Fatalf("UnmarshalMLSMessage failed: %v", err)
			}
			if msg2.WireFormat() != tc.wf {
				t.Errorf("After round-trip WireFormat = %d, want %d", msg2.WireFormat(), tc.wf)
			}
		})
	}
}

// TestMLSMessage_InvalidVersion verifies that an invalid version returns an error.
func TestMLSMessage_InvalidVersion(t *testing.T) {
	// version = 0x0002 (invalid), wire_format = 0x0001
	data := []byte{0x00, 0x02, 0x00, 0x01}
	_, err := framing.UnmarshalMLSMessage(data)
	if err == nil {
		t.Error("Should fail with invalid version")
	}
}

// TestMLSMessage_InvalidWireFormat verifies that an unknown wire_format returns an error.
func TestMLSMessage_InvalidWireFormat(t *testing.T) {
	// version = 0x0001, wire_format = 0x00FF (invalid)
	data := []byte{0x00, 0x01, 0x00, 0xFF}
	_, err := framing.UnmarshalMLSMessage(data)
	if err == nil {
		t.Error("Should fail with unknown wire format")
	}
}

// TestMLSMessage_WireFormat_Empty verifies WireFormat() on empty message.
func TestMLSMessage_WireFormat_Empty(t *testing.T) {
	msg := &framing.MLSMessage{}
	if msg.WireFormat() != 0 {
		t.Errorf("Empty MLSMessage WireFormat should be 0, got %d", msg.WireFormat())
	}
}

// ============================================================================
// Transcript Hash Tests
// ============================================================================

// TestConfirmedTranscriptHashInput_NonCommit verifies that it fails if not a commit.
func TestConfirmedTranscriptHashInput_NonCommit(t *testing.T) {
	ac := &framing.AuthenticatedContent{
		WireFormat: framing.WireFormatPublicMessage,
		Content: framing.FramedContent{
			GroupID: []byte("g"),
			Epoch:   1,
			Sender:  framing.Sender{Type: framing.SenderTypeMember},
			Body:    framing.ApplicationData{Data: []byte("x")}, // NOT a commit
		},
		Auth: framing.FramedContentAuthData{Signature: &ciphersuite.Signature{}},
	}

	_, err := framing.NewConfirmedTranscriptHashInput(ac)
	if err == nil {
		t.Error("NewConfirmedTranscriptHashInput should fail for non-commit content")
	}
}

// TestConfirmedTranscriptHashInput_Compute tests hash computation.
func TestConfirmedTranscriptHashInput_Compute(t *testing.T) {
	ac := &framing.AuthenticatedContent{
		WireFormat: framing.WireFormatPublicMessage,
		Content: framing.FramedContent{
			GroupID: []byte("group"),
			Epoch:   1,
			Sender:  framing.Sender{Type: framing.SenderTypeMember},
			Body:    framing.CommitBody{Data: []byte("commit-data")},
		},
		Auth: framing.FramedContentAuthData{
			Signature:       &ciphersuite.Signature{},
			ConfirmationTag: []byte{0x01, 0x02, 0x03},
		},
	}

	input, err := framing.NewConfirmedTranscriptHashInput(ac)
	if err != nil {
		t.Fatalf("NewConfirmedTranscriptHashInput failed: %v", err)
	}

	interimHash := make([]byte, 32) // Previous hash (epoch 0 = zeros)
	hash, err := input.Compute(ciphersuite.MLS128DHKEMP256, interimHash)
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	if len(hash) != 32 {
		t.Errorf("Hash should be 32 bytes (SHA-256), got %d", len(hash))
	}

	// Same input produces same hash (deterministic)
	hash2, _ := input.Compute(ciphersuite.MLS128DHKEMP256, interimHash)
	if !bytes.Equal(hash, hash2) {
		t.Error("Same input should produce same hash")
	}

	// Different interimHash produces different result
	interimHash2 := make([]byte, 32)
	interimHash2[0] = 0xFF
	hash3, _ := input.Compute(ciphersuite.MLS128DHKEMP256, interimHash2)
	if bytes.Equal(hash, hash3) {
		t.Error("Different interimHash should produce different hash")
	}
}

// TestInterimTranscriptHashInput_Compute tests interim hash computation.
func TestInterimTranscriptHashInput_Compute(t *testing.T) {
	input := &framing.InterimTranscriptHashInput{
		ConfirmationTag: []byte{0xAA, 0xBB, 0xCC},
	}

	confirmedHash := make([]byte, 32)
	hash := input.Compute(ciphersuite.MLS128DHKEMP256, confirmedHash)

	if len(hash) != 32 {
		t.Errorf("Hash should be 32 bytes (SHA-256), got %d", len(hash))
	}

	// Deterministic
	hash2 := input.Compute(ciphersuite.MLS128DHKEMP256, confirmedHash)
	if !bytes.Equal(hash, hash2) {
		t.Error("Same input should produce same hash")
	}

	// Different confirmedHash produces different result
	confirmedHash2 := make([]byte, 32)
	confirmedHash2[0] = 0x01
	hash3 := input.Compute(ciphersuite.MLS128DHKEMP256, confirmedHash2)
	if bytes.Equal(hash, hash3) {
		t.Error("Different confirmedHash should produce different hash")
	}
}

// TestTranscriptHash_Chain tests the complete confirmed→interim chain.
func TestTranscriptHash_Chain(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256

	// Epoch 0: Initial hashes = "" (empty)
	interim0 := []byte{}

	// Epoch 1: A commit arrives
	ac := &framing.AuthenticatedContent{
		WireFormat: framing.WireFormatPublicMessage,
		Content: framing.FramedContent{
			GroupID: []byte("group"),
			Epoch:   1,
			Sender:  framing.Sender{Type: framing.SenderTypeMember},
			Body:    framing.CommitBody{Data: []byte("commit-1")},
		},
		Auth: framing.FramedContentAuthData{
			Signature:       &ciphersuite.Signature{},
			ConfirmationTag: []byte{0x01, 0x02},
		},
	}

	confirmedInput, err := framing.NewConfirmedTranscriptHashInput(ac)
	if err != nil {
		t.Fatalf("NewConfirmedTranscriptHashInput: %v", err)
	}
	confirmed1, err := confirmedInput.Compute(cs, interim0)
	if err != nil {
		t.Fatalf("Compute confirmed: %v", err)
	}

	interimInput := &framing.InterimTranscriptHashInput{
		ConfirmationTag: ac.Auth.ConfirmationTag,
	}
	interim1 := interimInput.Compute(cs, confirmed1)

	// Both hashes should be 32 bytes and different from each other
	if len(confirmed1) != 32 || len(interim1) != 32 {
		t.Errorf("Hashes should be 32 bytes: confirmed=%d, interim=%d", len(confirmed1), len(interim1))
	}
	if bytes.Equal(confirmed1, interim1) {
		t.Error("confirmed and interim hash should be different")
	}
}

// ============================================================================
// Configurable Padding in Encrypt Tests
// ============================================================================

// TestEncryptParams_PaddingSize verifies that EncryptParams accepts PaddingSize.
func TestEncryptParams_PaddingSize(t *testing.T) {
	// Only verify that the field exists and can be set without compile issues.
	// Real encrypt/decrypt test requires a complete SecretTree.
	p := framing.EncryptParams{
		PaddingSize: 16,
		CipherSuite: ciphersuite.MLS128DHKEMP256,
	}
	if p.PaddingSize != 16 {
		t.Errorf("PaddingSize should be 16, got %d", p.PaddingSize)
	}
}
