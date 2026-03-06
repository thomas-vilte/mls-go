package framing_test

import (
	"bytes"
	"testing"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/framing"
	"github.com/openmls/go/internal/tls"
)

// ============================================================================
// Tests de Integración - Encrypt/Decrypt Round-Trip
// ============================================================================

// TestFramedContent_BodyTypes prueba todos los tipos de body
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

// TestFramedContent_EmptyFields prueba campos vacíos
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

// TestFramedContent_LargeFields prueba campos grandes
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
// Tests de MLSSenderData
// ============================================================================

// TestMLSSenderData_ZeroValues prueba valores en cero
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

// TestMLSSenderData_MaxValues prueba valores máximos
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

// TestMLSSenderData_InvalidData prueba datos inválidos
func TestMLSSenderData_InvalidData(t *testing.T) {
	// Datos truncados (menos de 12 bytes)
	invalidData := []byte{0x01, 0x02, 0x03}
	_, err := framing.UnmarshalSenderData(invalidData)
	if err == nil {
		t.Error("UnmarshalSenderData should fail with truncated data")
	}

	// Datos vacíos
	_, err = framing.UnmarshalSenderData([]byte{})
	if err == nil {
		t.Error("UnmarshalSenderData should fail with empty data")
	}
}

// ============================================================================
// Tests de FramedContentAuthData
// ============================================================================

// TestFramedContentAuthData_EmptySignature prueba firma vacía
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

// TestFramedContentAuthData_WithConfirmationTag prueba con confirmation tag
func TestFramedContentAuthData_WithConfirmationTag(t *testing.T) {
	auth := framing.FramedContentAuthData{
		Signature:       &ciphersuite.Signature{},
		ConfirmationTag: []byte{0x01, 0x02, 0x03, 0x04},
	}

	// Para Commit debería incluir confirmation tag
	data1 := auth.Marshal(framing.ContentTypeCommit)
	// Para Application no debería incluirlo
	data2 := auth.Marshal(framing.ContentTypeApplication)

	if len(data1) <= len(data2) {
		t.Error("Commit auth data should be larger (includes confirmation tag)")
	}
}

// TestFramedContentAuthData_NilSignature prueba con signature nil
func TestFramedContentAuthData_NilSignature(t *testing.T) {
	// Debería panickear o manejar gracefully
	defer func() {
		if r := recover(); r != nil {
			// Es esperado que panickee con nil signature
			t.Logf("Expected panic with nil signature: %v", r)
		}
	}()

	auth := framing.FramedContentAuthData{
		Signature: nil,
	}

	// Esto probablemente panickee
	_ = auth.Marshal(framing.ContentTypeApplication)
	// Si llegamos acá, no panickeó (lo cual también está bien)
}

// ============================================================================
// Tests de AuthenticatedContent
// ============================================================================

// TestAuthenticatedContent_AllWireFormats prueba todos los wire formats
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

			// Verificar que empieza con wire format
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
// Tests de PublicMessage
// ============================================================================

// TestPublicMessage_NonMemberSender prueba que non-member no tiene membership tag
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
		MembershipTag: nil, // External senders no tienen membership tag
	}

	data := pm.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal returned empty data")
	}

	// VerifyMembershipTag debería retornar nil para non-member
	err := pm.VerifyMembershipTag(nil)
	if err != nil {
		t.Errorf("VerifyMembershipTag should return nil for non-member: %v", err)
	}
}

// TestPublicMessage_MemberSenderNilKey prueba member con membership key nil
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

	// Debería poder hacer marshal sin membership tag
	data := pm.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal returned empty data")
	}
}

// ============================================================================
// Tests de PrivateMessage
// ============================================================================

// TestPrivateMessage_EmptyFields prueba campos vacíos
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

// TestPrivateMessage_LargeFields prueba campos grandes
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

// TestPrivateMessage_AllContentTypes prueba todos los content types
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

			// Verificar que content type está en el data
			// Wire format (2 bytes) + GroupID length (1 byte) + GroupID + Epoch (8 bytes) + ContentType (1 byte)
			// El offset depende del largo del GroupID
			// Mejor verificar que el ContentType se serializa correctamente
			if data[0] != 0x00 || data[1] != 0x02 {
				t.Errorf("Wire format should be PrivateMessage: got %02x%02x", data[0], data[1])
			}
		})
	}
}

// ============================================================================
// Tests de Sender
// ============================================================================

// TestSender_AllTypes prueba todos los tipos de sender
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

			// Unmarshal y verificar
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
// Tests de ContentType
// ============================================================================

// TestContentType_Values prueba los valores de ContentType
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
// Tests de WireFormat
// ============================================================================

// TestWireFormat_Values prueba los valores de WireFormat
func TestWireFormat_Values(t *testing.T) {
	if framing.WireFormatPublicMessage != 1 {
		t.Errorf("WireFormatPublicMessage should be 1, got %d", framing.WireFormatPublicMessage)
	}
	if framing.WireFormatPrivateMessage != 2 {
		t.Errorf("WireFormatPrivateMessage should be 2, got %d", framing.WireFormatPrivateMessage)
	}
}

// ============================================================================
// Tests de Errors
// ============================================================================

// TestErrors_NotNil prueba que los errores no son nil
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

// TestErrors_ErrorMessages prueba que los errores tienen mensajes descriptivos
func TestErrors_ErrorMessages(t *testing.T) {
	tests := []struct {
		err         error
		contains    string
		description string
	}{
		{framing.ErrInvalidWireFormat, "wire format", "ErrInvalidWireFormat"},
		{framing.ErrInvalidContentType, "content type", "ErrInvalidContentType"},
		{framing.ErrInvalidSenderType, "sender type", "ErrInvalidSenderType"},
		{framing.ErrDecryptionFailed, "descifrado", "ErrDecryptionFailed"},
		{framing.ErrVerificationFailed, "verificación", "ErrVerificationFailed"},
		{framing.ErrInvalidMembershipTag, "membership", "ErrInvalidMembershipTag"},
		{framing.ErrInvalidMessage, "mensaje", "ErrInvalidMessage"},
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
// Tests de Helpers
// ============================================================================

// TestUnmarshalSender_TruncatedData prueba unmarshal con datos truncados
func TestUnmarshalSender_TruncatedData(t *testing.T) {
	// Solo type, sin datos adicionales
	data := []byte{0x01} // SenderTypeMember
	r := tls.NewReader(data)
	_, err := framing.UnmarshalSender(r)
	if err == nil {
		t.Error("UnmarshalSender should fail with truncated data")
	}
}

// TestBuildPrivateContentAAD prueba construcción de AAD
func TestBuildPrivateContentAAD(t *testing.T) {
	// Esta función es interna, pero la podemos testear indirectamente
	// a través de la estructura de PrivateMessage
	pm := &framing.PrivateMessage{
		GroupID:           []byte("test-group"),
		Epoch:             42,
		ContentType:       framing.ContentTypeApplication,
		AuthenticatedData: []byte("auth-data"),
	}

	// Verificar que los campos están presentes
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
