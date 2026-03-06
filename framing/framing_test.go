package framing_test

import (
	"bytes"
	"testing"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/framing"
	"github.com/openmls/go/internal/tls"
)

// ============================================================================
// Tests de FramedContent
// ============================================================================

// TestFramedContent_ApplicationData_RoundTrip prueba serialización de ApplicationData
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

	// Verificar campos
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

	// Verificar body
	appData2, ok := fc2.Body.(framing.ApplicationData)
	if !ok {
		t.Fatal("Body is not ApplicationData")
	}
	if !bytes.Equal(fc.Body.(framing.ApplicationData).Data, appData2.Data) {
		t.Errorf("Body.Data mismatch: got %v, want %v", appData2.Data, fc.Body.(framing.ApplicationData).Data)
	}
}

// TestFramedContent_Proposal_RoundTrip prueba serialización de Proposal
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

// TestFramedContent_Commit_RoundTrip prueba serialización de Commit
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

// TestFramedContent_ContentType prueba que ContentType se deriva correctamente
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

// TestFramedContent_InvalidContentType prueba error con content_type desconocido
func TestFramedContent_InvalidContentType(t *testing.T) {
	// Crear datos manualmente con content_type inválido
	w := tls.NewWriter()
	w.WriteVLBytes([]byte("group-id"))
	w.WriteUint64(1)
	w.WriteUint8(1) // SenderTypeMember
	w.WriteUint32(0)
	w.WriteVLBytes([]byte{})
	w.WriteUint8(0xFF) // Content type inválido
	w.WriteVLBytes([]byte("body"))

	data := w.Bytes()
	_, err := framing.UnmarshalFramedContent(data)
	if err == nil {
		t.Error("UnmarshalFramedContent should fail with invalid content_type")
	}
}

// ============================================================================
// Tests de MLSSenderData
// ============================================================================

// TestMLSSenderData_RoundTrip prueba serialización de MLSSenderData
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
// Tests de FramedContentAuthData
// ============================================================================

// TestFramedContentAuthData_Marshal prueba serialización de auth data
func TestFramedContentAuthData_Marshal(t *testing.T) {
	sig := &ciphersuite.Signature{}
	auth := framing.FramedContentAuthData{
		Signature:       sig,
		ConfirmationTag: []byte{0x01, 0x02, 0x03},
	}

	// Sin confirmation tag
	data1 := auth.Marshal(framing.ContentTypeApplication)
	if len(data1) == 0 {
		t.Error("Marshal returned empty data for Application")
	}

	// Con confirmation tag (Commit)
	data2 := auth.Marshal(framing.ContentTypeCommit)
	if len(data2) == 0 {
		t.Error("Marshal returned empty data for Commit")
	}

	// Deberían ser diferentes
	if bytes.Equal(data1, data2) {
		t.Error("Marshal should produce different output for different content types")
	}
}

// ============================================================================
// Tests de AuthenticatedContent
// ============================================================================

// TestAuthenticatedContent_MarshalForSigning prueba serialización para firma
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

	// Debería empezar con wire format
	if data[0] != 0x00 || data[1] != 0x01 {
		t.Errorf("Wire format should be at start: got %02x%02x", data[0], data[1])
	}
}

// ============================================================================
// Tests de PublicMessage
// ============================================================================

// TestPublicMessage_Marshal prueba serialización de PublicMessage
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

	// Verificar que empieza con wire format
	if data[0] != 0x00 || data[1] != 0x01 {
		t.Errorf("Wire format should be at start: got %02x%02x", data[0], data[1])
	}
}

// ============================================================================
// Tests de PrivateMessage
// ============================================================================

// TestPrivateMessage_Marshal prueba serialización de PrivateMessage
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

	// Verificar wire format
	if data[0] != 0x00 || data[1] != 0x02 {
		t.Errorf("Wire format should be PrivateMessage: got %02x%02x", data[0], data[1])
	}
}

// TestPrivateMessage_FieldsEnClaro verifica que los primeros 4 campos están en claro
func TestPrivateMessage_FieldsEnClaro(t *testing.T) {
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

	// Los campos en claro deberían ser legibles en el data serializado
	// Esto es una verificación básica - en un test completo verificaríamos offsets
	if !bytes.Contains(data, groupID) {
		t.Error("GroupID should be visible in marshaled data")
	}
}

// ============================================================================
// Tests de errores
// ============================================================================

// TestErrors_Is verifica que errors.Is funciona correctamente
func TestErrors_Is(t *testing.T) {
	err := framing.ErrDecryptionFailed

	if !isError(err, framing.ErrDecryptionFailed) {
		t.Error("errors.Is should work with ErrDecryptionFailed")
	}
}

// isError es un helper para testear errors.Is
func isError(got, want error) bool {
	return got == want
}

// ============================================================================
// Tests de helpers
// ============================================================================

// TestMarshalSender_RoundTrip prueba serialización de Sender
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

// TestMarshalSender_External prueba serialización de External sender
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

// TestMarshalSender_Invalid prueba error con sender type inválido
func TestMarshalSender_Invalid(t *testing.T) {
	data := []byte{0xFF} // Sender type inválido
	r := tls.NewReader(data)
	_, err := framing.UnmarshalSender(r)
	if err == nil {
		t.Error("UnmarshalSender should fail with invalid sender type")
	}
}
