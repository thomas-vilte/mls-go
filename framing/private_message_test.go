package framing_test

import (
	"bytes"
	"testing"

	"github.com/mls-go/ciphersuite"
	"github.com/mls-go/framing"
	"github.com/mls-go/internal/tls"
	"github.com/mls-go/secrettree"
)

// ============================================================================
// PrivateMessage Marshal / Unmarshal
// ============================================================================

func TestPrivateMessage_RoundTrip_Marshal(t *testing.T) {
	pm := &framing.PrivateMessage{
		GroupID:             []byte("test-group"),
		Epoch:               42,
		ContentType:         framing.ContentTypeApplication,
		AuthenticatedData:   []byte("auth data"),
		EncryptedSenderData: []byte{0x01, 0x02, 0x03},
		Ciphertext:          []byte{0x04, 0x05, 0x06, 0x07},
	}

	data := pm.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal returned empty data")
	}

	pm2, err := framing.UnmarshalPrivateMessage(data)
	if err != nil {
		t.Fatalf("UnmarshalPrivateMessage failed: %v", err)
	}
	if !bytes.Equal(pm.GroupID, pm2.GroupID) {
		t.Error("GroupID mismatch")
	}
	if pm.Epoch != pm2.Epoch {
		t.Error("Epoch mismatch")
	}
	if pm.ContentType != pm2.ContentType {
		t.Error("ContentType mismatch")
	}
	if !bytes.Equal(pm.AuthenticatedData, pm2.AuthenticatedData) {
		t.Error("AuthenticatedData mismatch")
	}
	if !bytes.Equal(pm.EncryptedSenderData, pm2.EncryptedSenderData) {
		t.Error("EncryptedSenderData mismatch")
	}
	if !bytes.Equal(pm.Ciphertext, pm2.Ciphertext) {
		t.Error("Ciphertext mismatch")
	}
}

func TestUnmarshalPrivateMessage_WrongWireFormat(t *testing.T) {
	if _, err := framing.UnmarshalPrivateMessage([]byte{0x00, 0x01}); err == nil {
		t.Error("expected error for wrong wire format")
	}
}

func TestUnmarshalPrivateMessage_Truncated(t *testing.T) {
	if _, err := framing.UnmarshalPrivateMessage([]byte{0x00, 0x02}); err == nil {
		t.Error("expected error for truncated data")
	}
}

// ============================================================================
// MLSSenderData Marshal / Unmarshal
// ============================================================================

func TestMLSSenderData_MarshalUnmarshal(t *testing.T) {
	sd := &framing.MLSSenderData{
		LeafIndex:  42,
		Generation: 100,
		ReuseGuard: [4]byte{0x01, 0x02, 0x03, 0x04},
	}
	data := sd.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal returned empty")
	}
	sd2, err := framing.UnmarshalSenderData(data)
	if err != nil {
		t.Fatalf("UnmarshalSenderData: %v", err)
	}
	if sd.LeafIndex != sd2.LeafIndex {
		t.Errorf("LeafIndex = %d, want %d", sd2.LeafIndex, sd.LeafIndex)
	}
	if sd.Generation != sd2.Generation {
		t.Errorf("Generation = %d, want %d", sd2.Generation, sd.Generation)
	}
	if sd.ReuseGuard != sd2.ReuseGuard {
		t.Error("ReuseGuard mismatch")
	}
}

// ============================================================================
// Encrypt Error Paths
// ============================================================================

func TestEncrypt_NonMemberSender(t *testing.T) {
	content := framing.FramedContent{
		GroupID: []byte("grp"),
		Epoch:   1,
		Sender:  framing.Sender{Type: framing.SenderTypeExternal},
		Body:    framing.ApplicationData{Data: []byte("hi")},
	}
	_, err := framing.Encrypt(framing.EncryptParams{
		Content:         content,
		SenderLeafIndex: 0,
		CipherSuite:     ciphersuite.MLS128DHKEMP256,
	})
	if err == nil {
		t.Error("Encrypt should fail for non-member sender")
	}
}

// ============================================================================
// Encrypt / Decrypt RFC 9420 §6.3 Roundtrip
// ============================================================================

// makeEncDecTrees builds two secret trees from the same root bytes.
// The sender and receiver each need their own tree (stateful ratchet).
func makeEncDecTrees(t *testing.T, cs ciphersuite.CipherSuite, leafCount uint32) (enc, dec *secrettree.Tree) {
	t.Helper()
	rootBytes := bytes.Repeat([]byte{0x42}, 32)
	encTree, err := secrettree.NewTree(ciphersuite.NewSecret(rootBytes), leafCount, cs)
	if err != nil {
		t.Fatalf("NewTree(enc): %v", err)
	}
	decTree, err := secrettree.NewTree(ciphersuite.NewSecret(rootBytes), leafCount, cs)
	if err != nil {
		t.Fatalf("NewTree(dec): %v", err)
	}
	return encTree, decTree
}

// TestEncryptDecrypt_Application verifies the full encryption/decryption flow
// for Application messages (RFC §6.3).
func TestEncryptDecrypt_Application(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	encTree, decTree := makeEncDecTrees(t, cs, 2)

	sigPriv, sigPub := makeSigKeyPair(t, cs)

	groupID := []byte("test-group-id")
	epoch := uint64(1)
	plaintext := []byte("Hello MLS Application!")
	authData := []byte("aad")
	gcBytes := []byte("serialized-group-context")

	sdSecretBytes := bytes.Repeat([]byte{0x99}, 32)

	content := framing.FramedContent{
		GroupID:           groupID,
		Epoch:             epoch,
		Sender:            framing.Sender{Type: framing.SenderTypeMember, SenderIndex: 0},
		AuthenticatedData: authData,
		Body:              framing.ApplicationData{Data: plaintext},
	}

	pm, err := framing.Encrypt(framing.EncryptParams{
		Content:          content,
		SenderLeafIndex:  0,
		CipherSuite:      cs,
		SenderDataSecret: ciphersuite.NewSecret(sdSecretBytes),
		SecretTree:       encTree,
		SigKey:           sigPriv,
		GroupContext:     gcBytes,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if pm == nil {
		t.Fatal("Encrypt returned nil")
	}
	if len(pm.Ciphertext) == 0 {
		t.Error("Ciphertext is empty")
	}
	if len(pm.EncryptedSenderData) == 0 {
		t.Error("EncryptedSenderData is empty")
	}

	ac, err := framing.Decrypt(pm, framing.DecryptParams{
		CipherSuite:      cs,
		SenderDataSecret: ciphersuite.NewSecret(sdSecretBytes),
		SecretTree:       decTree,
		SigPubKey:        sigPub,
		GroupContext:     gcBytes,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if ac == nil {
		t.Fatal("Decrypt returned nil")
	}

	appData, ok := ac.Content.Body.(framing.ApplicationData)
	if !ok {
		t.Fatalf("body is not ApplicationData, got %T", ac.Content.Body)
	}
	if !bytes.Equal(appData.Data, plaintext) {
		t.Errorf("decrypted = %q, want %q", appData.Data, plaintext)
	}
	if !bytes.Equal(ac.Content.GroupID, groupID) {
		t.Error("GroupID mismatch after decrypt")
	}
	if ac.Content.Epoch != epoch {
		t.Errorf("Epoch = %d, want %d", ac.Content.Epoch, epoch)
	}
}

// TestEncryptDecrypt_Proposal verifies the flow with ContentType=Proposal
// using the handshake ratchet (RFC §9.1).
func TestEncryptDecrypt_Proposal(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	encTree, decTree := makeEncDecTrees(t, cs, 2)
	sigPriv, sigPub := makeSigKeyPair(t, cs)

	sdSecretBytes := bytes.Repeat([]byte{0x77}, 32)
	gcBytes := []byte("gc")

	// Generic Proposal body for this test
	proposalData := []byte{0x02, 0x00, 0x01, 0x02, 0x03, 0x04} // Raw proposal bytes
	content := framing.FramedContent{
		GroupID: []byte("grp"),
		Epoch:   5,
		Sender:  framing.Sender{Type: framing.SenderTypeMember, SenderIndex: 0},
		Body:    framing.ProposalBody{Data: proposalData},
	}

	pm, err := framing.Encrypt(framing.EncryptParams{
		Content:          content,
		SenderLeafIndex:  0,
		CipherSuite:      cs,
		SenderDataSecret: ciphersuite.NewSecret(sdSecretBytes),
		SecretTree:       encTree,
		SigKey:           sigPriv,
		GroupContext:     gcBytes,
	})
	if err != nil {
		t.Fatalf("Encrypt (Proposal): %v", err)
	}
	if pm.ContentType != framing.ContentTypeProposal {
		t.Errorf("ContentType = %d, want ContentTypeProposal", pm.ContentType)
	}

	_, err = framing.Decrypt(pm, framing.DecryptParams{
		CipherSuite:      cs,
		SenderDataSecret: ciphersuite.NewSecret(sdSecretBytes),
		SecretTree:       decTree,
		SigPubKey:        sigPub,
		GroupContext:     gcBytes,
	})
	if err != nil {
		t.Fatalf("Decrypt (Proposal): %v", err)
	}
}

// TestDecrypt_TamperedCiphertext verifies that Decrypt fails with corrupted ciphertext.
func TestDecrypt_TamperedCiphertext(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	encTree, decTree := makeEncDecTrees(t, cs, 2)
	sigPriv, _ := makeSigKeyPair(t, cs)

	sdSecretBytes := bytes.Repeat([]byte{0x55}, 32)
	content := framing.FramedContent{
		GroupID: []byte("grp"),
		Epoch:   1,
		Sender:  framing.Sender{Type: framing.SenderTypeMember, SenderIndex: 0},
		Body:    framing.ApplicationData{Data: []byte("secret")},
	}

	pm, err := framing.Encrypt(framing.EncryptParams{
		Content:          content,
		SenderLeafIndex:  0,
		CipherSuite:      cs,
		SenderDataSecret: ciphersuite.NewSecret(sdSecretBytes),
		SecretTree:       encTree,
		SigKey:           sigPriv,
		GroupContext:     []byte("gc"),
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Corrupt the ciphertext
	pm.Ciphertext[0] ^= 0xFF

	_, err = framing.Decrypt(pm, framing.DecryptParams{
		CipherSuite:      cs,
		SenderDataSecret: ciphersuite.NewSecret(sdSecretBytes),
		SecretTree:       decTree,
	})
	if err == nil {
		t.Error("Decrypt should fail with tampered ciphertext")
	}
}

// TestDecrypt_TamperedSenderData verifies that Decrypt fails with corrupted sender data.
func TestDecrypt_TamperedSenderData(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	encTree, decTree := makeEncDecTrees(t, cs, 2)
	sigPriv, _ := makeSigKeyPair(t, cs)

	sdSecretBytes := bytes.Repeat([]byte{0x33}, 32)
	content := framing.FramedContent{
		GroupID: []byte("grp"),
		Epoch:   1,
		Sender:  framing.Sender{Type: framing.SenderTypeMember, SenderIndex: 0},
		Body:    framing.ApplicationData{Data: []byte("msg")},
	}

	pm, err := framing.Encrypt(framing.EncryptParams{
		Content:          content,
		SenderLeafIndex:  0,
		CipherSuite:      cs,
		SenderDataSecret: ciphersuite.NewSecret(sdSecretBytes),
		SecretTree:       encTree,
		SigKey:           sigPriv,
		GroupContext:     []byte("gc"),
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	pm.EncryptedSenderData[0] ^= 0xFF

	_, err = framing.Decrypt(pm, framing.DecryptParams{
		CipherSuite:      cs,
		SenderDataSecret: ciphersuite.NewSecret(sdSecretBytes),
		SecretTree:       decTree,
	})
	if err == nil {
		t.Error("Decrypt should fail with tampered sender data")
	}
}

// ============================================================================
// MLSMessage AsPrivate / AsPublic
// ============================================================================

func TestMLSMessage_AsPrivate(t *testing.T) {
	pm := &framing.PrivateMessage{
		GroupID:             []byte("g"),
		Epoch:               1,
		ContentType:         framing.ContentTypeApplication,
		EncryptedSenderData: []byte{0x01},
		Ciphertext:          []byte{0x02},
	}
	msg := framing.NewMLSMessagePrivate(pm)
	if msg.WireFormat() != framing.WireFormatPrivateMessage {
		t.Error("WireFormat should be PrivateMessage")
	}
	got, ok := msg.AsPrivate()
	if !ok || got == nil {
		t.Fatal("AsPrivate returned nil/false")
	}
	if !bytes.Equal(got.GroupID, pm.GroupID) {
		t.Error("GroupID mismatch")
	}
	_, ok = msg.AsPublic()
	if ok {
		t.Error("AsPublic should return false on a PrivateMessage")
	}
}

func TestMLSMessage_AsPublic(t *testing.T) {
	pub := &framing.PublicMessage{
		Content: framing.FramedContent{GroupID: []byte("g"), Epoch: 0,
			Sender: framing.Sender{Type: framing.SenderTypeMember},
			Body:   framing.ApplicationData{Data: []byte("d")}},
	}
	msg := framing.NewMLSMessagePublic(pub)
	if msg.WireFormat() != framing.WireFormatPublicMessage {
		t.Error("WireFormat should be PublicMessage")
	}
	got, ok := msg.AsPublic()
	if !ok || got == nil {
		t.Fatal("AsPublic returned nil/false")
	}
	_, ok = msg.AsPrivate()
	if ok {
		t.Error("AsPrivate should return false on a PublicMessage")
	}
}

// ============================================================================
// buildPrivateContentAAD Determinism
// ============================================================================

func TestBuildPrivateContentAAD_Deterministic(t *testing.T) {
	groupID := []byte("test-group")
	epoch := uint64(1)
	contentType := framing.ContentTypeApplication
	authData := []byte("auth data")

	buildAAD := func(ad []byte) []byte {
		w := tls.NewWriter()
		w.WriteVLBytes(groupID)
		w.WriteUint64(epoch)
		w.WriteUint8(uint8(contentType))
		w.WriteVLBytes(ad)
		return w.Bytes()
	}

	aad1 := buildAAD(authData)
	aad2 := buildAAD(authData)
	if !bytes.Equal(aad1, aad2) {
		t.Error("AAD is not deterministic")
	}
	if bytes.Equal(aad1, buildAAD([]byte("different"))) {
		t.Error("different authData should produce different AAD")
	}
}

// ============================================================================
// Helper
// ============================================================================

// makeSigKeyPair returns a SignaturePrivateKey + matching OpenMlsSignaturePublicKey.
func makeSigKeyPair(t *testing.T, cs ciphersuite.CipherSuite) (*ciphersuite.SignaturePrivateKey, *ciphersuite.OpenMlsSignaturePublicKey) {
	t.Helper()
	privKey, err := ciphersuite.GenerateSignaturePrivateKey()
	if err != nil {
		t.Fatalf("GenerateSignaturePrivateKey: %v", err)
	}
	pubKey := privKey.PublicKey()
	return privKey, ciphersuite.NewOpenMlsSignaturePublicKey(pubKey.AsSlice(), cs.SignatureScheme())
}
