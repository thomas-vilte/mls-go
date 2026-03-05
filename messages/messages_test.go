package messages_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/openmls/go/messages"
)

// TestWelcomeMarshalUnmarshal tests Welcome message serialization.
//
// Based on openmls Rust test: openmls/src/messages/mod.rs
func TestWelcomeMarshalUnmarshal(t *testing.T) {
	// Create a minimal valid Welcome
	welcome := messages.NewWelcome(
		0x0002, // MLS_128_DHKEMP256_AES128GCM_SHA256_P256
		[]messages.EncryptedGroupSecrets{
			{
				KeyPackageHash: bytes.Repeat([]byte{0x01}, 32),
				EncryptedKey:   []byte{0x02, 0x03, 0x04},
				Ciphertext:     []byte{0x05, 0x06, 0x07},
			},
		},
		[]byte{0x08, 0x09, 0x0A},
	)

	// Marshal
	data, err := welcome.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	t.Logf("Serialized Welcome: %d bytes", len(data))
	t.Logf("Hex: %s", hex.EncodeToString(data))

	// Unmarshal
	parsed, err := messages.UnmarshalWelcome(data)
	if err != nil {
		t.Fatalf("UnmarshalWelcome failed: %v", err)
	}

	// Validate
	if parsed.CipherSuite != welcome.CipherSuite {
		t.Errorf("CipherSuite mismatch: got 0x%04x, want 0x%04x", parsed.CipherSuite, welcome.CipherSuite)
	}

	if len(parsed.Secrets) != len(welcome.Secrets) {
		t.Fatalf("Secrets count mismatch: got %d, want %d", len(parsed.Secrets), len(welcome.Secrets))
	}

	if !bytes.Equal(parsed.Secrets[0].KeyPackageHash, welcome.Secrets[0].KeyPackageHash) {
		t.Error("KeyPackageHash mismatch")
	}

	if !bytes.Equal(parsed.EncryptedGroupInfo, welcome.EncryptedGroupInfo) {
		t.Error("EncryptedGroupInfo mismatch")
	}
}

// TestWelcomeFindSecret tests finding secrets by KeyPackage hash.
func TestWelcomeFindSecret(t *testing.T) {
	keyPackageHash := []byte{0x42, 0x42, 0x42, 0x42}
	
	welcome := messages.NewWelcome(
		0x0002,
		[]messages.EncryptedGroupSecrets{
			{
				KeyPackageHash: []byte{0x01, 0x02, 0x03},
				EncryptedKey:   []byte{0x04},
				Ciphertext:     []byte{0x05},
			},
			{
				KeyPackageHash: keyPackageHash,
				EncryptedKey:   []byte{0x06},
				Ciphertext:     []byte{0x07},
			},
		},
		[]byte{0x08},
	)

	// Find existing secret
	secret := welcome.FindSecret(keyPackageHash)
	if secret == nil {
		t.Fatal("FindSecret returned nil for existing hash")
	}

	if !bytes.Equal(secret.EncryptedKey, []byte{0x06}) {
		t.Error("Found wrong secret")
	}

	// Find non-existing secret
	secret = welcome.FindSecret([]byte{0xFF, 0xFF, 0xFF})
	if secret != nil {
		t.Error("FindSecret should return nil for non-existing hash")
	}
}

// TestGroupInfoMarshalUnmarshal tests GroupInfo serialization.
//
// Based on openmls Rust test: openmls/src/messages/group_info.rs
func TestGroupInfoMarshalUnmarshal(t *testing.T) {
	groupContext := &messages.GroupContext{
		ProtocolVersion:         1,
		CipherSuite:             0x0002,
		GroupID:                 []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		Epoch:                   0,
		TreeHash:                bytes.Repeat([]byte{0xAA}, 32),
		ConfirmedTranscriptHash: bytes.Repeat([]byte{0xBB}, 32),
		Extensions:              []messages.Extension{},
	}

	groupInfo := &messages.GroupInfo{
		GroupContext:    groupContext,
		Extensions:      []messages.Extension{},
		ConfirmationTag: bytes.Repeat([]byte{0xCC}, 32),
		Signer:          0,
		Signature:       []byte{0x01, 0x02, 0x03},
	}

	// Marshal
	data := groupInfo.Marshal()
	t.Logf("Serialized GroupInfo: %d bytes", len(data))

	// Unmarshal
	parsed, err := messages.UnmarshalGroupInfo(data)
	if err != nil {
		t.Fatalf("UnmarshalGroupInfo failed: %v", err)
	}

	// Validate
	if parsed.GroupContext.ProtocolVersion != groupContext.ProtocolVersion {
		t.Errorf("ProtocolVersion mismatch: got %d, want %d", parsed.GroupContext.ProtocolVersion, groupContext.ProtocolVersion)
	}

	if parsed.GroupContext.CipherSuite != groupContext.CipherSuite {
		t.Errorf("CipherSuite mismatch")
	}

	if !bytes.Equal(parsed.ConfirmationTag, groupInfo.ConfirmationTag) {
		t.Error("ConfirmationTag mismatch")
	}

	if parsed.Signer != groupInfo.Signer {
		t.Errorf("Signer mismatch: got %d, want %d", parsed.Signer, groupInfo.Signer)
	}

	if !bytes.Equal(parsed.Signature, groupInfo.Signature) {
		t.Error("Signature mismatch")
	}
}

// TestGroupContextMarshalUnmarshal tests GroupContext serialization.
func TestGroupContextMarshalUnmarshal(t *testing.T) {
	groupContext := &messages.GroupContext{
		ProtocolVersion:         1,
		CipherSuite:             0x0002,
		GroupID:                 []byte{0xDE, 0xAD, 0xBE, 0xEF},
		Epoch:                   42,
		TreeHash:                bytes.Repeat([]byte{0x11}, 32),
		ConfirmedTranscriptHash: bytes.Repeat([]byte{0x22}, 32),
		Extensions: []messages.Extension{
			{Type: 0x0002, Data: []byte{0x33, 0x44, 0x55}},
		},
	}

	data := groupContext.Marshal()
	t.Logf("Serialized GroupContext: %d bytes", len(data))

	parsed, err := messages.UnmarshalGroupContext(data)
	if err != nil {
		t.Fatalf("UnmarshalGroupContext failed: %v", err)
	}

	if parsed.ProtocolVersion != groupContext.ProtocolVersion {
		t.Errorf("ProtocolVersion mismatch")
	}

	if parsed.CipherSuite != groupContext.CipherSuite {
		t.Errorf("CipherSuite mismatch")
	}

	if !bytes.Equal(parsed.GroupID, groupContext.GroupID) {
		t.Errorf("GroupID mismatch")
	}

	if parsed.Epoch != groupContext.Epoch {
		t.Errorf("Epoch mismatch: got %d, want %d", parsed.Epoch, groupContext.Epoch)
	}
}

// TestHashKeyPackage tests KeyPackage hashing.
func TestHashKeyPackage(t *testing.T) {
	keyPackage := []byte("test key package data")
	
	hash1 := messages.HashKeyPackage(keyPackage)
	hash2 := messages.HashKeyPackage(keyPackage)
	
	if !bytes.Equal(hash1, hash2) {
		t.Error("HashKeyPackage is not deterministic")
	}

	if len(hash1) != 32 {
		t.Errorf("HashKeyPackage should return 32 bytes (SHA-256), got %d", len(hash1))
	}

	// Different input should give different hash
	hash3 := messages.HashKeyPackage([]byte("different data"))
	if bytes.Equal(hash1, hash3) {
		t.Error("Different inputs produced same hash")
	}
}

// TestConfirmationTag tests confirmation tag computation and verification.
func TestConfirmationTag(t *testing.T) {
	confirmationKey := bytes.Repeat([]byte{0x42}, 32)
	confirmedTranscriptHash := bytes.Repeat([]byte{0x43}, 32)

	tag := messages.ComputeConfirmationTag(sha256.New, confirmationKey, confirmedTranscriptHash)

	if len(tag) != 32 {
		t.Errorf("ConfirmationTag should be 32 bytes (HMAC-SHA256), got %d", len(tag))
	}

	// Verify should succeed with correct tag
	if !messages.VerifyConfirmationTag(sha256.New, confirmationKey, confirmedTranscriptHash, tag) {
		t.Error("VerifyConfirmationTag failed with correct tag")
	}

	// Verify should fail with wrong tag
	wrongTag := make([]byte, 32)
	copy(wrongTag, tag)
	wrongTag[0] ^= 0xFF

	if messages.VerifyConfirmationTag(sha256.New, confirmationKey, confirmedTranscriptHash, wrongTag) {
		t.Error("VerifyConfirmationTag succeeded with wrong tag")
	}
}
