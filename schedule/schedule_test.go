package schedule

import (
	"testing"

	"github.com/openmls/go/ciphersuite"
)

func TestKeyScheduleFlow(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256

	// Create initial key schedule with init_secret = 0
	initSecret := ciphersuite.ZeroSecretCS(cs)
	ks := NewKeySchedule(cs, initSecret)

	// Generate a commit_secret
	commitSecret, err := ciphersuite.NewSecretRandomCS(cs)
	if err != nil {
		t.Fatalf("Failed to create commit_secret: %v", err)
	}
	ks.SetCommitSecret(commitSecret)

	// Compute joiner_secret
	groupContext := []byte("test group context")
	joinerSecret, err := ks.ComputeJoinerSecret(groupContext)
	if err != nil {
		t.Fatalf("Failed to compute joiner_secret: %v", err)
	}
	if joinerSecret == nil || joinerSecret.Len() == 0 {
		t.Error("joiner_secret should not be empty")
	}

	// Compute psk_secret (no PSKs)
	_, err = ks.ComputePskSecret([]Psk{})
	if err != nil {
		t.Fatalf("Failed to compute psk_secret: %v", err)
	}

	// Compute epoch_secret
	epochSecret, err := ks.ComputeEpochSecret(groupContext)
	if err != nil {
		t.Fatalf("Failed to compute epoch_secret: %v", err)
	}
	if epochSecret == nil || epochSecret.Len() == 0 {
		t.Error("epoch_secret should not be empty")
	}

	// Derive all epoch secrets
	secrets, err := ks.DeriveEpochSecrets()
	if err != nil {
		t.Fatalf("Failed to derive epoch secrets: %v", err)
	}

	// Verify all secrets were derived
	if secrets.InitSecret == nil {
		t.Error("init_secret should not be nil")
	}
	if secrets.EncryptionSecret == nil {
		t.Error("encryption_secret should not be nil")
	}
	if secrets.ExporterSecret == nil {
		t.Error("exporter_secret should not be nil")
	}
	if secrets.AuthenticationSecret == nil {
		t.Error("authentication_secret should not be nil")
	}
	if secrets.ExternalSecret == nil {
		t.Error("external_secret should not be nil")
	}
	if secrets.ResumptionSecret == nil {
		t.Error("resumption_secret should not be nil")
	}
	if secrets.ConfirmationKey == nil {
		t.Error("confirmation_key should not be nil")
	}
	if secrets.MembershipKey == nil {
		t.Error("membership_key should not be nil")
	}
}

func TestWelcomeSecretDerivation(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256

	initSecret := ciphersuite.ZeroSecretCS(cs)
	ks := NewKeySchedule(cs, initSecret)

	// Set commit_secret and compute joiner_secret
	commitSecret := ciphersuite.ZeroSecretCS(cs)
	ks.SetCommitSecret(commitSecret)

	_, err := ks.ComputeJoinerSecret([]byte("test group context"))
	if err != nil {
		t.Fatalf("ComputeJoinerSecret failed: %v", err)
	}

	_, err = ks.ComputePskSecret([]Psk{})
	if err != nil {
		t.Fatalf("ComputePskSecret failed: %v", err)
	}

	// Compute welcome_secret
	welcomeSecret, err := ks.ComputeWelcomeSecret()
	if err != nil {
		t.Fatalf("ComputeWelcomeSecret failed: %v", err)
	}
	if welcomeSecret == nil || welcomeSecret.Len() == 0 {
		t.Error("welcome_secret should not be empty")
	}

	// Derive welcome key and nonce
	welcomeKey, welcomeNonce, err := ks.WelcomeKeyNonce()
	if err != nil {
		t.Fatalf("WelcomeKeyNonce failed: %v", err)
	}
	if len(welcomeKey) != 16 {
		t.Errorf("welcome_key should be 16 bytes, got %d", len(welcomeKey))
	}
	if len(welcomeNonce) != 12 {
		t.Errorf("welcome_nonce should be 12 bytes, got %d", len(welcomeNonce))
	}
}

func TestConfirmationTag(t *testing.T) {
	confirmationKey := []byte("test confirmation key 12345678")
	confirmedTranscriptHash := []byte("test transcript hash 12345678")

	tag := ComputeConfirmationTag(confirmationKey, confirmedTranscriptHash)
	if len(tag) != 32 {
		t.Errorf("confirmation_tag should be 32 bytes, got %d", len(tag))
	}

	// Verify tag is deterministic
	tag2 := ComputeConfirmationTag(confirmationKey, confirmedTranscriptHash)
	if string(tag) != string(tag2) {
		t.Error("confirmation_tag should be deterministic")
	}
}

func TestMembershipTag(t *testing.T) {
	membershipKey := []byte("test membership key 123456789")
	authenticatedContent := []byte("test authenticated content")

	tag := ComputeMembershipTag(membershipKey, authenticatedContent)
	if len(tag) == 0 {
		t.Error("membership_tag should not be empty")
	}

	// Verify tag
	if !VerifyMembershipTag(membershipKey, authenticatedContent, tag) {
		t.Error("VerifyMembershipTag should return true for valid tag")
	}

	// Verify with wrong content
	wrongContent := []byte("wrong content")
	if VerifyMembershipTag(membershipKey, wrongContent, tag) {
		t.Error("VerifyMembershipTag should return false for wrong content")
	}
}

func TestTranscriptHashes(t *testing.T) {
	interimTranscriptHash := make([]byte, 32)
	framedContent := []byte("test framed content")
	signature := []byte("test signature")

	confirmedHash := ComputeTranscriptHash(interimTranscriptHash, framedContent, signature)
	if len(confirmedHash) != 32 {
		t.Errorf("confirmed_transcript_hash should be 32 bytes, got %d", len(confirmedHash))
	}

	confirmationTag := []byte("test confirmation tag")
	interimHash := ComputeInterimTranscriptHash(confirmedHash, confirmationTag)
	if len(interimHash) != 32 {
		t.Errorf("interim_transcript_hash should be 32 bytes, got %d", len(interimHash))
	}
}

func TestPSKCombination(t *testing.T) {
	psks := []Psk{
		{PskType: PskTypeExternal, PskId: []byte("psk1"), Psk: []byte("secret1")},
		{PskType: PskTypeExternal, PskId: []byte("psk2"), Psk: []byte("secret2")},
	}

	cs := ciphersuite.MLS128DHKEMP256
	pskInput, err := ComputePskInput(psks, cs)
	if err != nil {
		t.Fatalf("ComputePskInput failed: %v", err)
	}
	if len(pskInput) == 0 {
		t.Error("psk_input should not be empty")
	}

	// Single PSK should return a derived PSK input with hash length.
	singlePsk := []Psk{
		{PskType: PskTypeExternal, PskId: []byte("psk1"), Psk: []byte("secret1")},
	}
	pskInput2, err := ComputePskInput(singlePsk, cs)
	if err != nil {
		t.Fatalf("ComputePskInput failed: %v", err)
	}
	if len(pskInput2) != cs.HashLength() {
		t.Errorf("single PSK input length = %d, want %d", len(pskInput2), cs.HashLength())
	}
	if string(pskInput2) == "secret1" {
		t.Error("single PSK should be derived, not returned directly")
	}
}

func TestExporter(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256

	// Create exporter secret
	exporterSecret, err := ciphersuite.NewSecretRandomCS(cs)
	if err != nil {
		t.Fatalf("Failed to create exporter_secret: %v", err)
	}

	// Export with label
	context := []byte("test context")
	exportedValue, err := Exporter(exporterSecret, ExporterLabelAuthenticationKey, context, 32)
	if err != nil {
		t.Fatalf("Exporter failed: %v", err)
	}
	if len(exportedValue) != 32 {
		t.Errorf("exported value should be 32 bytes, got %d", len(exportedValue))
	}

	// Export with different length should give different result
	exportedValue2, err := Exporter(exporterSecret, ExporterLabelAuthenticationKey, context, 16)
	if err != nil {
		t.Fatalf("Exporter failed: %v", err)
	}
	if len(exportedValue2) != 16 {
		t.Errorf("exported value should be 16 bytes, got %d", len(exportedValue2))
	}
}
