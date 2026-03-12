package messages_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/mls-go/messages"
)

// ============================================================================
// Welcome
// ============================================================================

func TestWelcomeMarshalUnmarshal(t *testing.T) {
	welcome := messages.NewWelcome(
		0x0002,
		[]messages.EncryptedGroupSecrets{
			{
				KeyPackageHash: bytes.Repeat([]byte{0x01}, 32),
				EncryptedKey:   []byte{0x02, 0x03, 0x04},
				Ciphertext:     []byte{0x05, 0x06, 0x07},
			},
		},
		[]byte{0x08, 0x09, 0x0A},
	)

	data, err := welcome.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("Marshal returned empty")
	}

	got, err := messages.UnmarshalWelcome(data)
	if err != nil {
		t.Fatalf("UnmarshalWelcome: %v", err)
	}
	if got.CipherSuite != welcome.CipherSuite {
		t.Errorf("CipherSuite = 0x%04x, want 0x%04x", got.CipherSuite, welcome.CipherSuite)
	}
	if len(got.Secrets) != 1 {
		t.Fatalf("Secrets count = %d, want 1", len(got.Secrets))
	}
	if !bytes.Equal(got.Secrets[0].KeyPackageHash, welcome.Secrets[0].KeyPackageHash) {
		t.Error("KeyPackageHash mismatch")
	}
	if !bytes.Equal(got.EncryptedGroupInfo, welcome.EncryptedGroupInfo) {
		t.Error("EncryptedGroupInfo mismatch")
	}
}

func TestWelcomeFindSecret(t *testing.T) {
	target := []byte{0x42, 0x42, 0x42, 0x42}
	welcome := messages.NewWelcome(
		0x0002,
		[]messages.EncryptedGroupSecrets{
			{KeyPackageHash: []byte{0x01}, EncryptedKey: []byte{0x02}, Ciphertext: []byte{0x03}},
			{KeyPackageHash: target, EncryptedKey: []byte{0x06}, Ciphertext: []byte{0x07}},
		},
		[]byte{0x08},
	)
	found := welcome.FindSecret(target)
	if found == nil {
		t.Fatal("FindSecret returned nil for known hash")
	}
	if !bytes.Equal(found.EncryptedKey, []byte{0x06}) {
		t.Error("found wrong secret entry")
	}
	if welcome.FindSecret([]byte{0xFF, 0xFF}) != nil {
		t.Error("FindSecret should return nil for unknown hash")
	}
}

// ============================================================================
// GroupInfo
// ============================================================================

func TestGroupInfoMarshalUnmarshal(t *testing.T) {
	gc := &messages.GroupContext{
		ProtocolVersion:         1,
		CipherSuite:             0x0002,
		GroupID:                 []byte{0x00, 0x01, 0x02, 0x03},
		Epoch:                   5,
		TreeHash:                bytes.Repeat([]byte{0xAA}, 32),
		ConfirmedTranscriptHash: bytes.Repeat([]byte{0xBB}, 32),
		Extensions:              []messages.Extension{},
	}
	gi := &messages.GroupInfo{
		GroupContext:    gc,
		Extensions:      []messages.Extension{},
		ConfirmationTag: bytes.Repeat([]byte{0xCC}, 32),
		Signer:          0,
		Signature:       []byte{0x01, 0x02, 0x03},
	}

	data := gi.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal returned empty")
	}

	got, err := messages.UnmarshalGroupInfo(data)
	if err != nil {
		t.Fatalf("UnmarshalGroupInfo: %v", err)
	}
	if got.GroupContext.Epoch != gc.Epoch {
		t.Errorf("Epoch = %d, want %d", got.GroupContext.Epoch, gc.Epoch)
	}
	if !bytes.Equal(got.ConfirmationTag, gi.ConfirmationTag) {
		t.Error("ConfirmationTag mismatch")
	}
	if !bytes.Equal(got.Signature, gi.Signature) {
		t.Error("Signature mismatch")
	}
	if got.Signer != gi.Signer {
		t.Errorf("Signer = %d, want %d", got.Signer, gi.Signer)
	}
}

// ============================================================================
// GroupContext
// ============================================================================

func TestGroupContextMarshalUnmarshal(t *testing.T) {
	gc := &messages.GroupContext{
		ProtocolVersion:         1,
		CipherSuite:             0x0002,
		GroupID:                 []byte{0xDE, 0xAD, 0xBE, 0xEF},
		Epoch:                   42,
		TreeHash:                bytes.Repeat([]byte{0x11}, 32),
		ConfirmedTranscriptHash: bytes.Repeat([]byte{0x22}, 32),
		Extensions:              []messages.Extension{{Type: 0x0002, Data: []byte{0x33, 0x44}}},
	}
	data := gc.Marshal()
	got, err := messages.UnmarshalGroupContext(data)
	if err != nil {
		t.Fatalf("UnmarshalGroupContext: %v", err)
	}
	if got.Epoch != gc.Epoch {
		t.Errorf("Epoch = %d, want %d", got.Epoch, gc.Epoch)
	}
	if !bytes.Equal(got.GroupID, gc.GroupID) {
		t.Error("GroupID mismatch")
	}
	if len(got.Extensions) != 1 {
		t.Errorf("Extensions count = %d, want 1", len(got.Extensions))
	}
}

// ============================================================================
// EncryptGroupInfo / DecryptGroupInfo — RFC 9420 §11.2.2
// ============================================================================

// TestEncryptDecryptGroupInfo verifies that GroupInfo can be encrypted with the
// welcome_key/nonce pair and decrypted back to the original.
func TestEncryptDecryptGroupInfo(t *testing.T) {
	gc := &messages.GroupContext{
		ProtocolVersion:         1,
		CipherSuite:             0x0002,
		GroupID:                 []byte{0x01, 0x02, 0x03, 0x04},
		Epoch:                   0,
		TreeHash:                bytes.Repeat([]byte{0xAB}, 32),
		ConfirmedTranscriptHash: bytes.Repeat([]byte{0xCD}, 32),
		Extensions:              []messages.Extension{},
	}
	gi := &messages.GroupInfo{
		GroupContext:    gc,
		Extensions:      []messages.Extension{},
		ConfirmationTag: bytes.Repeat([]byte{0xEF}, 32),
		Signer:          0,
		Signature:       []byte{0x11, 0x22, 0x33},
	}

	// welcome_key: 16 bytes (AES-128); welcome_nonce: 12 bytes (GCM)
	welcomeKey := bytes.Repeat([]byte{0x42}, 16)
	welcomeNonce := bytes.Repeat([]byte{0x24}, 12)

	ciphertext, err := messages.EncryptGroupInfo(gi, welcomeKey, welcomeNonce)
	if err != nil {
		t.Fatalf("EncryptGroupInfo: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("EncryptGroupInfo returned empty ciphertext")
	}

	decrypted, err := messages.DecryptGroupInfo(ciphertext, welcomeKey, welcomeNonce)
	if err != nil {
		t.Fatalf("DecryptGroupInfo: %v", err)
	}
	if decrypted.GroupContext.Epoch != gc.Epoch {
		t.Errorf("decrypted Epoch = %d, want %d", decrypted.GroupContext.Epoch, gc.Epoch)
	}
	if !bytes.Equal(decrypted.ConfirmationTag, gi.ConfirmationTag) {
		t.Error("decrypted ConfirmationTag mismatch")
	}
}

func TestDecryptGroupInfo_WrongKey(t *testing.T) {
	gc := &messages.GroupContext{
		ProtocolVersion: 1,
		CipherSuite:     0x0002,
		GroupID:         []byte{0x01},
		Extensions:      []messages.Extension{},
	}
	gi := &messages.GroupInfo{
		GroupContext:    gc,
		Extensions:      []messages.Extension{},
		ConfirmationTag: []byte{0x01},
		Signature:       []byte{0x02},
	}
	key := bytes.Repeat([]byte{0x42}, 16)
	nonce := bytes.Repeat([]byte{0x24}, 12)
	ct, _ := messages.EncryptGroupInfo(gi, key, nonce)

	wrongKey := bytes.Repeat([]byte{0xFF}, 16)
	if _, err := messages.DecryptGroupInfo(ct, wrongKey, nonce); err == nil {
		t.Fatal("DecryptGroupInfo should fail with wrong key")
	}
}

// ============================================================================
// HashKeyPackage — RFC 9420 §10.5
// ============================================================================

func TestHashKeyPackage_DeterministicAndUnique(t *testing.T) {
	data := []byte("some serialized KeyPackage bytes")
	h1 := messages.HashKeyPackage(data)
	h2 := messages.HashKeyPackage(data)
	if !bytes.Equal(h1, h2) {
		t.Error("HashKeyPackage is not deterministic")
	}
	if len(h1) != 32 {
		t.Errorf("hash len = %d, want 32", len(h1))
	}
	if bytes.Equal(h1, messages.HashKeyPackage([]byte("other"))) {
		t.Error("different inputs produced the same hash")
	}
}

// ============================================================================
// ConfirmationTag — RFC 9420 §8.2
// ============================================================================

func TestConfirmationTag_ValidAndInvalid(t *testing.T) {
	confirmKey := bytes.Repeat([]byte{0x42}, 32)
	transcriptHash := bytes.Repeat([]byte{0x43}, 32)

	tag := messages.ComputeConfirmationTag(sha256.New, confirmKey, transcriptHash)
	if len(tag) != 32 {
		t.Errorf("tag len = %d, want 32", len(tag))
	}

	if !messages.VerifyConfirmationTag(sha256.New, confirmKey, transcriptHash, tag) {
		t.Error("VerifyConfirmationTag failed for valid tag")
	}

	// Tampered tag
	bad := make([]byte, len(tag))
	copy(bad, tag)
	bad[0] ^= 0xFF
	if messages.VerifyConfirmationTag(sha256.New, confirmKey, transcriptHash, bad) {
		t.Error("VerifyConfirmationTag should fail for tampered tag")
	}

	// Wrong key
	wrongKey := bytes.Repeat([]byte{0xFF}, 32)
	if messages.VerifyConfirmationTag(sha256.New, wrongKey, transcriptHash, tag) {
		t.Error("VerifyConfirmationTag should fail for wrong key")
	}
}

func TestConfirmationTag_Deterministic(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	hash := bytes.Repeat([]byte{0x02}, 32)
	t1 := messages.ComputeConfirmationTag(sha256.New, key, hash)
	t2 := messages.ComputeConfirmationTag(sha256.New, key, hash)
	if !bytes.Equal(t1, t2) {
		t.Error("ComputeConfirmationTag is not deterministic")
	}
}
