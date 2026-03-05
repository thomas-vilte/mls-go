package framing

import (
	"testing"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/group"
	"github.com/openmls/go/schedule"
)

func TestSenderTypes(t *testing.T) {
	// Test member sender
	leafIndex := group.NewLeafNodeIndex(0)
	memberSender := NewMemberSender(leafIndex)

	if memberSender == nil {
		t.Fatal("NewMemberSender returned nil")
	}
	if memberSender.Type != SenderTypeMember {
		t.Errorf("Sender type should be Member, got %d", memberSender.Type)
	}
	if memberSender.LeafIndex != leafIndex {
		t.Errorf("LeafIndex mismatch")
	}

	// Test external sender
	extSender := NewExternalSender(42)
	if extSender == nil {
		t.Fatal("NewExternalSender returned nil")
	}
	if extSender.Type != SenderTypeExternal {
		t.Errorf("Sender type should be External, got %d", extSender.Type)
	}
	if extSender.SenderIndex != 42 {
		t.Errorf("SenderIndex mismatch")
	}

	// Test new member senders
	newMemberProposalSender := NewNewMemberProposalSender()
	if newMemberProposalSender == nil {
		t.Fatal("NewNewMemberProposalSender returned nil")
	}
	if newMemberProposalSender.Type != SenderTypeNewMemberProposal {
		t.Errorf("Sender type should be NewMemberProposal, got %d", newMemberProposalSender.Type)
	}

	newMemberCommitSender := NewNewMemberCommitSender()
	if newMemberCommitSender == nil {
		t.Fatal("NewNewMemberCommitSender returned nil")
	}
	if newMemberCommitSender.Type != SenderTypeNewMemberCommit {
		t.Errorf("Sender type should be NewMemberCommit, got %d", newMemberCommitSender.Type)
	}
}

func TestSenderMethods(t *testing.T) {
	// Test member sender methods
	memberSender := NewMemberSender(group.NewLeafNodeIndex(0))
	if !memberSender.IsMember() {
		t.Error("IsMember should return true for member sender")
	}
	if memberSender.IsExternal() {
		t.Error("IsExternal should return false for member sender")
	}
	if memberSender.IsNewMember() {
		t.Error("IsNewMember should return false for member sender")
	}

	// Test external sender methods
	extSender := NewExternalSender(42)
	if extSender.IsMember() {
		t.Error("IsMember should return false for external sender")
	}
	if !extSender.IsExternal() {
		t.Error("IsExternal should return true for external sender")
	}
	if extSender.IsNewMember() {
		t.Error("IsNewMember should return false for external sender")
	}

	// Test new member sender methods
	newMemberSender := NewNewMemberProposalSender()
	if newMemberSender.IsMember() {
		t.Error("IsMember should return false for new member sender")
	}
	if newMemberSender.IsExternal() {
		t.Error("IsExternal should return false for new member sender")
	}
	if !newMemberSender.IsNewMember() {
		t.Error("IsNewMember should return true for new member sender")
	}
}

func TestWireFormats(t *testing.T) {
	// Verify wire format constants
	if WireFormatPublicMessage != 0x0001 {
		t.Errorf("WireFormatPublicMessage should be 0x0001, got 0x%04x", WireFormatPublicMessage)
	}
	if WireFormatPrivateMessage != 0x0002 {
		t.Errorf("WireFormatPrivateMessage should be 0x0002, got 0x%04x", WireFormatPrivateMessage)
	}
	if WireFormatWelcome != 0x0003 {
		t.Errorf("WireFormatWelcome should be 0x0003, got 0x%04x", WireFormatWelcome)
	}
	if WireFormatGroupInfo != 0x0004 {
		t.Errorf("WireFormatGroupInfo should be 0x0004, got 0x%04x", WireFormatGroupInfo)
	}
	if WireFormatKeyPackage != 0x0005 {
		t.Errorf("WireFormatKeyPackage should be 0x0005, got 0x%04x", WireFormatKeyPackage)
	}
}

func TestContentTypes(t *testing.T) {
	// Verify content type constants
	if ContentTypeApplication != 0x01 {
		t.Errorf("ContentTypeApplication should be 0x01, got 0x%02x", ContentTypeApplication)
	}
	if ContentTypeProposal != 0x02 {
		t.Errorf("ContentTypeProposal should be 0x02, got 0x%02x", ContentTypeProposal)
	}
	if ContentTypeCommit != 0x03 {
		t.Errorf("ContentTypeCommit should be 0x03, got 0x%02x", ContentTypeCommit)
	}
}

func TestPublicMessageMarshal(t *testing.T) {
	sender := NewMemberSender(group.NewLeafNodeIndex(0))
	content := []byte("test content")
	signature := []byte("test signature")

	pm := NewPublicMessage(sender, ContentTypeApplication, content, signature)

	data := pm.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshaled PublicMessage is empty")
	}

	// Unmarshal
	pm2, err := UnmarshalPublicMessage(data)
	if err != nil {
		t.Fatalf("UnmarshalPublicMessage failed: %v", err)
	}

	if pm2.WireFormat != WireFormatPublicMessage {
		t.Errorf("WireFormat mismatch")
	}
	if pm2.Sender.Type != sender.Type {
		t.Errorf("Sender type mismatch")
	}
}

func TestPrivateMessageMarshal(t *testing.T) {
	pm := NewPrivateMessage(
		[]byte("encrypted sender data"),
		[]byte("encrypted content"),
	)

	data := pm.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshaled PrivateMessage is empty")
	}

	// Unmarshal
	pm2, err := UnmarshalPrivateMessage(data)
	if err != nil {
		t.Fatalf("UnmarshalPrivateMessage failed: %v", err)
	}

	if pm2.WireFormat != WireFormatPrivateMessage {
		t.Errorf("WireFormat mismatch")
	}
}

func TestEncryptionDecryption(t *testing.T) {
	// Create encryption secret
	encryptionSecret, err := ciphersuite.NewSecretRandom(ciphersuite.SHA256.Size())
	if err != nil {
		t.Fatalf("NewSecretRandom failed: %v", err)
	}

	// Create epoch secrets (simplified)
	epochSecrets := &schedule.EpochSecrets{}

	// Encrypt content
	content := []byte("Hello, MLS!")
	pm, err := Encrypt(content, encryptionSecret, epochSecrets)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if pm == nil {
		t.Fatal("Encrypted message is nil")
	}
	if len(pm.EncryptedContent) == 0 {
		t.Error("Encrypted content is empty")
	}

	// Decrypt content
	plaintext, err := Decrypt(pm, encryptionSecret, 0)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(plaintext) != string(content) {
		t.Errorf("Decrypted content mismatch: got %s, want %s", plaintext, content)
	}
}

func TestFramedContent(t *testing.T) {
	fc := &FramedContent{
		ContentType:          ContentTypeApplication,
		AuthenticatedContent: []byte("test content"),
	}

	data := fc.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshaled FramedContent is empty")
	}
}

func TestMLSMessage(t *testing.T) {
	// Create public message
	sender := NewMemberSender(group.NewLeafNodeIndex(0))
	pm := NewPublicMessage(sender, ContentTypeApplication, []byte("content"), []byte("sig"))

	// Create MLS message
	mlsMsg := NewPublicMLSMessage(pm)
	if mlsMsg == nil {
		t.Fatal("NewPublicMLSMessage returned nil")
	}
	if mlsMsg.Version != 1 {
		t.Errorf("Version should be 1, got %d", mlsMsg.Version)
	}
	if mlsMsg.Body.PublicMessage == nil {
		t.Error("PublicMessage should not be nil")
	}

	// Create private message
	privMsg := NewPrivateMessage([]byte("enc sender"), []byte("enc content"))
	mlsMsg2 := NewPrivateMLSMessage(privMsg)
	if mlsMsg2 == nil {
		t.Fatal("NewPrivateMLSMessage returned nil")
	}
	if mlsMsg2.Body.PrivateMessage == nil {
		t.Error("PrivateMessage should not be nil")
	}
}
