// Package framing - Tests para RFC 9420 §6
package framing

import (
	"bytes"
	"testing"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/internal/tls"
)

// ============================================================================
// FramedContentBody Tests - RFC 9420 §6.1
// ============================================================================

func TestFramedContentBody_Marshal(t *testing.T) {
	tests := []struct {
		name string
		body FramedContentBody
	}{
		{"Application", ApplicationData{Data: []byte("Hello, MLS!")}},
		{"Proposal", ProposalBody{Data: []byte{0x01, 0x02, 0x03}}},
		{"Commit", CommitBody{Data: []byte{0x04, 0x05, 0x06}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := tls.NewWriter()
			tt.body.marshal(w)
			if len(w.Bytes()) == 0 {
				t.Fatal("marshal returned empty data")
			}
		})
	}
}

func TestReadFramedContentBody_Application(t *testing.T) {
	appData := []byte("Test application data")
	w := tls.NewWriter()
	w.WriteVLBytes(appData)

	r := tls.NewReader(w.Bytes())
	body, err := readFramedContentBody(r, ContentTypeApplication, false, false)
	if err != nil {
		t.Fatalf("readFramedContentBody(Application) failed: %v", err)
	}

	app, ok := body.(ApplicationData)
	if !ok {
		t.Fatal("Expected ApplicationData")
	}
	if !bytes.Equal(app.Data, appData) {
		t.Error("Data mismatch")
	}
}

func TestReadFramedContentBody_InvalidType(t *testing.T) {
	r := tls.NewReader([]byte{0x99})
	_, err := readFramedContentBody(r, 0x99, false, false)
	if err == nil {
		t.Fatal("Expected error for invalid content type")
	}
}

// ============================================================================
// FramedContent Tests - RFC 9420 §6.1
// ============================================================================

func makeTestFC(body FramedContentBody) FramedContent {
	return FramedContent{
		GroupID:           []byte("test-group"),
		Epoch:             42,
		Sender:            Sender{Type: SenderTypeMember, LeafIndex: 3},
		AuthenticatedData: []byte("extra"),
		Body:              body,
	}
}

func TestFramedContent_Marshal_Roundtrip(t *testing.T) {
	fc := makeTestFC(ApplicationData{Data: []byte("payload")})
	data := fc.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal() returned empty")
	}
	got, err := UnmarshalFramedContent(data)
	if err != nil {
		t.Fatalf("UnmarshalFramedContent() failed: %v", err)
	}
	if !bytes.Equal(got.GroupID, fc.GroupID) {
		t.Error("GroupID mismatch")
	}
	if got.Epoch != fc.Epoch {
		t.Errorf("Epoch = %d, want %d", got.Epoch, fc.Epoch)
	}
	if got.Sender.LeafIndex != fc.Sender.LeafIndex {
		t.Error("Sender.LeafIndex mismatch")
	}
	app, ok := got.ApplicationData()
	if !ok {
		t.Fatal("ApplicationData() accessor returned false")
	}
	if !bytes.Equal(app, []byte("payload")) {
		t.Error("application payload mismatch")
	}
}

func TestFramedContent_ApplicationData_NotApp(t *testing.T) {
	fc := makeTestFC(ProposalBody{Data: []byte{0x01}})
	_, ok := fc.ApplicationData()
	if ok {
		t.Error("ApplicationData() should return false for Proposal body")
	}
}

// ============================================================================
// AuthenticatedContent Tests - RFC 9420 §6.1
// ============================================================================

func makeTestAC(body FramedContentBody) AuthenticatedContent {
	return AuthenticatedContent{
		WireFormat: WireFormatPublicMessage,
		Content:    makeTestFC(body),
		Auth: FramedContentAuthData{
			Signature: ciphersuite.NewSignature([]byte{0xDE, 0xAD, 0xBE, 0xEF}),
		},
	}
}

func TestAuthenticatedContent_Marshal_NonEmpty(t *testing.T) {
	ac := makeTestAC(ApplicationData{Data: []byte("msg")})
	data := ac.Marshal()
	if len(data) == 0 {
		t.Fatal("AuthenticatedContent.Marshal() returned empty")
	}
}

func TestAuthenticatedContent_Marshal_Deterministic(t *testing.T) {
	ac := makeTestAC(ApplicationData{Data: []byte("msg")})
	if !bytes.Equal(ac.Marshal(), ac.Marshal()) {
		t.Error("Marshal() is not deterministic")
	}
}

func TestAuthenticatedContent_MarshalTBS_IncludesGroupContext(t *testing.T) {
	ac := makeTestAC(ApplicationData{Data: []byte("msg")})
	ac.GroupContext = []byte("gc-bytes")

	tbs := (&ac).MarshalTBS()
	ac2 := makeTestAC(ApplicationData{Data: []byte("msg")})
	tbsWithout := (&ac2).MarshalTBS()

	// With GroupContext for SenderTypeMember, TBS must be larger
	if len(tbs) <= len(tbsWithout) {
		t.Error("TBS with GroupContext should be larger than without")
	}
}

func TestUnmarshalAuthenticatedContent_Roundtrip_Application(t *testing.T) {
	ac := makeTestAC(ApplicationData{Data: []byte("roundtrip")})
	data := ac.Marshal()

	got, err := UnmarshalAuthenticatedContent(data)
	if err != nil {
		t.Fatalf("UnmarshalAuthenticatedContent() failed: %v", err)
	}
	if got.WireFormat != ac.WireFormat {
		t.Errorf("WireFormat = %d, want %d", got.WireFormat, ac.WireFormat)
	}
	if !bytes.Equal(got.Content.GroupID, ac.Content.GroupID) {
		t.Error("GroupID mismatch after unmarshal")
	}
	app, ok := got.Content.ApplicationData()
	if !ok || !bytes.Equal(app, []byte("roundtrip")) {
		t.Error("application data mismatch after unmarshal")
	}
}

func TestUnmarshalAuthenticatedContent_Roundtrip_CommitWithTag(t *testing.T) {
	ac := AuthenticatedContent{
		WireFormat: WireFormatPublicMessage,
		Content:    makeTestFC(CommitBody{Data: []byte{0x01, 0x02, 0x03}}),
		Auth: FramedContentAuthData{
			Signature:       ciphersuite.NewSignature([]byte{0xAA, 0xBB}),
			ConfirmationTag: []byte{0xCC, 0xDD},
		},
	}
	data := ac.Marshal()

	got, err := UnmarshalAuthenticatedContent(data)
	if err != nil {
		t.Fatalf("UnmarshalAuthenticatedContent(commit) failed: %v", err)
	}
	if got.Auth.ConfirmationTag == nil {
		t.Error("ConfirmationTag lost after unmarshal")
	}
}

func TestUnmarshalAuthenticatedContent_Truncated(t *testing.T) {
	_, err := UnmarshalAuthenticatedContent([]byte{0x00, 0x01})
	if err == nil {
		t.Fatal("expected error for truncated data")
	}
}

// ============================================================================
// PrivateMessageContent Tests - RFC 9420 §6.3
// ============================================================================

func TestMarshalPrivateMessageContent_NopadAndAligned(t *testing.T) {
	body := ApplicationData{Data: []byte("Test")}
	auth := FramedContentAuthData{
		Signature: ciphersuite.NewSignature([]byte{0x01, 0x02, 0x03}),
	}

	unpadded := marshalPrivateMessageContent(body, auth, 0)
	if len(unpadded) == 0 {
		t.Fatal("marshalPrivateMessageContent returned empty")
	}

	for _, align := range []int{4, 8, 16, 32} {
		data := marshalPrivateMessageContent(body, auth, align)
		if len(data)%align != 0 {
			t.Errorf("align=%d: length %d not aligned", align, len(data))
		}
		// padding bytes must be zero
		for i := len(unpadded); i < len(data); i++ {
			if data[i] != 0x00 {
				t.Errorf("align=%d: non-zero padding at byte %d", align, i)
			}
		}
	}
}

func TestUnmarshalPrivateMessageContent_Application(t *testing.T) {
	body := ApplicationData{Data: []byte("Test")}
	auth := FramedContentAuthData{
		Signature: ciphersuite.NewSignature([]byte{0x01, 0x02, 0x03}),
	}
	w := tls.NewWriter()
	body.marshal(w)
	w.WriteRaw(auth.Marshal(ContentTypeApplication))

	got, err := unmarshalPrivateMessageContent(w.Bytes(), ContentTypeApplication)
	if err != nil {
		t.Fatalf("unmarshalPrivateMessageContent failed: %v", err)
	}
	app, ok := got.Body.(ApplicationData)
	if !ok || !bytes.Equal(app.Data, body.Data) {
		t.Error("body data mismatch")
	}
}

func TestUnmarshalPrivateMessageContent_CommitConfirmationTag(t *testing.T) {
	body := ApplicationData{Data: []byte("commit")}
	auth := FramedContentAuthData{
		Signature:       ciphersuite.NewSignature([]byte{0x01, 0x02}),
		ConfirmationTag: []byte{0x03, 0x04},
	}
	w := tls.NewWriter()
	body.marshal(w)
	w.WriteRaw(auth.Marshal(ContentTypeCommit))

	got, err := unmarshalPrivateMessageContent(w.Bytes(), ContentTypeCommit)
	if err != nil {
		t.Fatalf("unmarshalPrivateMessageContent(commit) failed: %v", err)
	}
	if got.Auth.ConfirmationTag == nil {
		t.Error("Expected ConfirmationTag for Commit")
	}
}

func TestUnmarshalPrivateMessageContent_NonZeroPaddingRejected(t *testing.T) {
	body := ApplicationData{Data: []byte("Test")}
	auth := FramedContentAuthData{Signature: ciphersuite.NewSignature([]byte{0x01, 0x02})}
	w := tls.NewWriter()
	body.marshal(w)
	w.WriteRaw(auth.Marshal(ContentTypeApplication))
	w.WriteUint8(0xFF) // non-zero padding byte — must be rejected

	_, err := unmarshalPrivateMessageContent(w.Bytes(), ContentTypeApplication)
	if err == nil {
		t.Fatal("Expected error for non-zero padding byte")
	}
}

func TestUnmarshalPrivateMessageContent_Truncated(t *testing.T) {
	_, err := unmarshalPrivateMessageContent([]byte{0x00}, ContentTypeApplication)
	if err == nil {
		t.Fatal("Expected error for truncated data")
	}
}

// ============================================================================
// FramedContentAuthData Tests - RFC 9420 §6.1
// ============================================================================

func TestFramedContentAuthData_Marshal_WithAndWithoutConfirmation(t *testing.T) {
	sig := ciphersuite.NewSignature([]byte{0xAA, 0xBB})

	// Non-commit: no confirmation tag regardless of field
	authNonCommit := FramedContentAuthData{Signature: sig, ConfirmationTag: []byte{0xFF}}
	dataNonCommit := authNonCommit.Marshal(ContentTypeApplication)

	// Commit without confirmation tag set: no tag appended
	authCommitNoTag := FramedContentAuthData{Signature: sig}
	dataCommitNoTag := authCommitNoTag.Marshal(ContentTypeCommit)

	// Commit with confirmation tag: tag appended
	authCommitTag := FramedContentAuthData{Signature: sig, ConfirmationTag: []byte{0x01, 0x02}}
	dataCommitTag := authCommitTag.Marshal(ContentTypeCommit)

	if bytes.Equal(dataNonCommit, dataCommitNoTag) {
		// Both should have same bytes since neither appends the tag
		// (same signature bytes — this is expected)
	}
	if len(dataCommitTag) <= len(dataCommitNoTag) {
		t.Error("Commit with tag should produce more bytes than without")
	}
	_ = dataNonCommit
}

// ============================================================================
// validAuthTail Tests - covers all branches of the scanner
// ============================================================================

func TestValidAuthTail_Proposal_SigOnly(t *testing.T) {
	w := tls.NewWriter()
	w.WriteVLBytes([]byte{0x01, 0x02}) // signature
	if !validAuthTail(w.Bytes(), ContentTypeProposal, false) {
		t.Error("Proposal with sig only should be valid")
	}
}

func TestValidAuthTail_Proposal_WithMembershipTag(t *testing.T) {
	w := tls.NewWriter()
	w.WriteVLBytes([]byte{0x01, 0x02}) // signature
	w.WriteVLBytes([]byte{0x03, 0x04}) // membership_tag
	if !validAuthTail(w.Bytes(), ContentTypeProposal, true) {
		t.Error("Proposal with sig+membership_tag should be valid")
	}
}

func TestValidAuthTail_Proposal_MissingMembershipTag(t *testing.T) {
	w := tls.NewWriter()
	w.WriteVLBytes([]byte{0x01, 0x02}) // only signature, but membership tag expected
	if validAuthTail(w.Bytes(), ContentTypeProposal, true) {
		t.Error("Proposal missing membership_tag should be invalid")
	}
}

func TestValidAuthTail_Empty_IsInvalid(t *testing.T) {
	if validAuthTail([]byte{}, ContentTypeProposal, false) {
		t.Error("Empty tail should be invalid")
	}
}

func TestValidAuthTail_Commit_WithConfirmationTag(t *testing.T) {
	// tryWithConfirmation path: sig + confirmation_tag
	w := tls.NewWriter()
	w.WriteVLBytes([]byte{0x01, 0x02}) // signature
	w.WriteVLBytes([]byte{0x03, 0x04}) // confirmation_tag
	if !validAuthTail(w.Bytes(), ContentTypeCommit, false) {
		t.Error("Commit with sig+confirmation should be valid")
	}
}

func TestValidAuthTail_Commit_SigOnly(t *testing.T) {
	// tryWithoutConfirmation path: sig only (no confirmation tag)
	// This is valid for some wire encodings where confirmation_tag is absent
	w := tls.NewWriter()
	w.WriteVLBytes([]byte{0x01, 0x02}) // signature only
	if !validAuthTail(w.Bytes(), ContentTypeCommit, false) {
		t.Error("Commit with sig only should be valid via tryWithoutConfirmation")
	}
}

func TestValidAuthTail_Commit_WithConfirmationAndMembershipTag(t *testing.T) {
	// Full PublicMessage commit: sig + confirmation_tag + membership_tag
	w := tls.NewWriter()
	w.WriteVLBytes([]byte{0x01, 0x02}) // signature
	w.WriteVLBytes([]byte{0x03, 0x04}) // confirmation_tag
	w.WriteVLBytes([]byte{0x05, 0x06}) // membership_tag
	if !validAuthTail(w.Bytes(), ContentTypeCommit, true) {
		t.Error("Commit with sig+confirmation+membership should be valid")
	}
}

// ============================================================================
// Sender Tests - RFC 9420 §6.1
// ============================================================================

func TestUnmarshalSender_Member(t *testing.T) {
	w := tls.NewWriter()
	w.WriteUint8(uint8(SenderTypeMember))
	w.WriteUint32(7)

	r := tls.NewReader(w.Bytes())
	s, err := UnmarshalSender(r)
	if err != nil {
		t.Fatalf("UnmarshalSender(member) failed: %v", err)
	}
	if s.Type != SenderTypeMember || s.LeafIndex != 7 {
		t.Errorf("got {%v, %d}, want {Member, 7}", s.Type, s.LeafIndex)
	}
}

func TestUnmarshalSender_External(t *testing.T) {
	w := tls.NewWriter()
	w.WriteUint8(uint8(SenderTypeExternal))
	w.WriteUint32(2)

	r := tls.NewReader(w.Bytes())
	s, err := UnmarshalSender(r)
	if err != nil {
		t.Fatalf("UnmarshalSender(external) failed: %v", err)
	}
	if s.Type != SenderTypeExternal || s.SenderIndex != 2 {
		t.Errorf("got {%v, %d}, want {External, 2}", s.Type, s.SenderIndex)
	}
}

func TestUnmarshalSender_NewMemberProposal(t *testing.T) {
	w := tls.NewWriter()
	w.WriteUint8(uint8(SenderTypeNewMemberProposal))

	r := tls.NewReader(w.Bytes())
	s, err := UnmarshalSender(r)
	if err != nil {
		t.Fatalf("UnmarshalSender(new_member_proposal) failed: %v", err)
	}
	if s.Type != SenderTypeNewMemberProposal {
		t.Errorf("got %v, want NewMemberProposal", s.Type)
	}
}

func TestUnmarshalSender_InvalidType(t *testing.T) {
	w := tls.NewWriter()
	w.WriteUint8(0xFF)
	r := tls.NewReader(w.Bytes())
	if _, err := UnmarshalSender(r); err == nil {
		t.Fatal("expected error for invalid sender type")
	}
}

// ============================================================================
// Edge Cases
// ============================================================================

func TestEmptyApplicationData(t *testing.T) {
	body := ApplicationData{Data: []byte{}}
	w := tls.NewWriter()
	body.marshal(w)
	if len(w.Bytes()) == 0 {
		t.Error("Empty ApplicationData should still produce VL-prefix bytes")
	}
}

func TestLargeApplicationData_Roundtrip(t *testing.T) {
	data := make([]byte, 10000)
	for i := range data {
		data[i] = byte(i % 256)
	}
	w := tls.NewWriter()
	ApplicationData{Data: data}.marshal(w)
	r := tls.NewReader(w.Bytes())
	got, err := readFramedContentBody(r, ContentTypeApplication, false, false)
	if err != nil {
		t.Fatalf("readFramedContentBody(large) failed: %v", err)
	}
	app := got.(ApplicationData)
	if !bytes.Equal(app.Data, data) {
		t.Error("large data roundtrip mismatch")
	}
}
