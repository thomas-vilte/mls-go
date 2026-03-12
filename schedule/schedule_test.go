package schedule

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// ============================================================================
// Full key-schedule flow — RFC 9420 §8
// ============================================================================

// TestKeyScheduleFlow exercises the committer path:
//
//	init_secret → (commit_secret) → joiner_secret → (psk_secret) →
//	member_secret → epoch_secret → all epoch secrets
func TestKeyScheduleFlow(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	gc := []byte("test group context")

	ks := NewKeySchedule(cs, ciphersuite.ZeroSecretCS(cs))

	cs1, err := ciphersuite.NewSecretRandomCS(cs)
	if err != nil {
		t.Fatalf("NewSecretRandomCS: %v", err)
	}
	ks.SetCommitSecret(cs1)

	js, err := ks.ComputeJoinerSecret(gc)
	if err != nil {
		t.Fatalf("ComputeJoinerSecret: %v", err)
	}
	if js == nil || js.Len() == 0 {
		t.Error("joiner_secret is empty")
	}

	if _, err = ks.ComputePskSecret([]Psk{}); err != nil {
		t.Fatalf("ComputePskSecret: %v", err)
	}

	es, err := ks.ComputeEpochSecret(gc)
	if err != nil {
		t.Fatalf("ComputeEpochSecret: %v", err)
	}
	if es == nil || es.Len() == 0 {
		t.Error("epoch_secret is empty")
	}

	secrets, err := ks.DeriveEpochSecrets()
	if err != nil {
		t.Fatalf("DeriveEpochSecrets: %v", err)
	}
	if secrets.InitSecret == nil {
		t.Error("init_secret nil")
	}
	if secrets.EncryptionSecret == nil {
		t.Error("encryption_secret nil")
	}
	if secrets.ExporterSecret == nil {
		t.Error("exporter_secret nil")
	}
	if secrets.AuthenticationSecret == nil {
		t.Error("authentication_secret nil")
	}
	if secrets.ExternalSecret == nil {
		t.Error("external_secret nil")
	}
	if secrets.ResumptionSecret == nil {
		t.Error("resumption_secret nil")
	}
	if secrets.ConfirmationKey == nil {
		t.Error("confirmation_key nil")
	}
	if secrets.MembershipKey == nil {
		t.Error("membership_key nil")
	}
}

// ============================================================================
// InitSecret accessor
// ============================================================================

func TestInitSecret(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	init := ciphersuite.ZeroSecretCS(cs)
	ks := NewKeySchedule(cs, init)
	if ks.InitSecret() == nil {
		t.Fatal("InitSecret() returned nil")
	}
	if ks.InitSecret().Len() != cs.HashLength() {
		t.Errorf("InitSecret len = %d, want %d", ks.InitSecret().Len(), cs.HashLength())
	}
}

// ============================================================================
// SetJoinerSecret — Welcome receiver path (RFC 9420 §11.2.2)
// ============================================================================

// TestSetJoinerSecret verifies that a Welcome receiver can inject joiner_secret
// directly (bypassing CommitSecret + ComputeJoinerSecret) and still derive all
// epoch secrets successfully.
//
// Note: HKDFExtract zeroes out Secret values after use (forward secrecy), so
// committer and receiver must each hold independent Secret instances of the
// same material. The two paths are compared by deriving joiner_secret twice
// from identical inputs.
func TestSetJoinerSecret(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	gc := []byte("group context bytes")

	// Helper: run committer path up to epoch secrets, returning the
	// encryption_secret as bytes.  Uses zero init/commit secrets.
	runCommitter := func() []byte {
		ks := NewKeySchedule(cs, ciphersuite.ZeroSecretCS(cs))
		ks.SetCommitSecret(ciphersuite.ZeroSecretCS(cs))
		if _, err := ks.ComputeJoinerSecret(gc); err != nil {
			t.Fatalf("ComputeJoinerSecret: %v", err)
		}
		if _, err := ks.ComputePskSecret([]Psk{}); err != nil {
			t.Fatalf("ComputePskSecret: %v", err)
		}
		if _, err := ks.ComputeEpochSecret(gc); err != nil {
			t.Fatalf("ComputeEpochSecret: %v", err)
		}
		s, err := ks.DeriveEpochSecrets()
		if err != nil {
			t.Fatalf("DeriveEpochSecrets: %v", err)
		}
		return s.EncryptionSecret.AsSlice()
	}

	// Helper: run receiver path — injects a freshly computed joiner_secret.
	runReceiver := func() []byte {
		// Derive joiner_secret from the same inputs used by the committer
		// (zero init_secret + zero commit_secret + gc).
		tmpKS := NewKeySchedule(cs, ciphersuite.ZeroSecretCS(cs))
		tmpKS.SetCommitSecret(ciphersuite.ZeroSecretCS(cs))
		joinerSecret, err := tmpKS.ComputeJoinerSecret(gc)
		if err != nil {
			t.Fatalf("tmpKS ComputeJoinerSecret: %v", err)
		}
		// After ComputeJoinerSecret the joinerSecret is now stored in ks.joinerSecret
		// and the underlying Secret bytes are still valid (only HKDFExtract zeroes).

		// New key schedule for the receiver; use SetJoinerSecret instead of
		// running ComputeJoinerSecret (the Welcome path).
		ksR := NewKeySchedule(cs, ciphersuite.ZeroSecretCS(cs))
		ksR.SetJoinerSecret(joinerSecret)
		if err = ksR.SetPskSecretDirect(ciphersuite.ZeroSecret(cs.HashLength())); err != nil {
			t.Fatalf("SetPskSecretDirect: %v", err)
		}
		if _, err = ksR.ComputeEpochSecret(gc); err != nil {
			t.Fatalf("ComputeEpochSecret: %v", err)
		}
		s, err := ksR.DeriveEpochSecrets()
		if err != nil {
			t.Fatalf("DeriveEpochSecrets: %v", err)
		}
		return s.EncryptionSecret.AsSlice()
	}

	enc1 := runCommitter()
	enc2 := runReceiver()
	if !bytes.Equal(enc1, enc2) {
		t.Error("encryption_secret mismatch between committer and Welcome receiver")
	}
}

// TestSetJoinerSecret_NoComputeJoinerSecretRequired verifies that calling
// SetJoinerSecret is sufficient to skip ComputeJoinerSecret entirely.
func TestSetJoinerSecret_NoComputeJoinerSecretRequired(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	gc := []byte("gc")

	js := ciphersuite.ZeroSecret(cs.HashLength())
	ks := NewKeySchedule(cs, ciphersuite.ZeroSecretCS(cs))
	ks.SetJoinerSecret(js)

	if err := ks.SetPskSecretDirect(ciphersuite.ZeroSecret(cs.HashLength())); err != nil {
		t.Fatalf("SetPskSecretDirect without ComputeJoinerSecret: %v", err)
	}
	if _, err := ks.ComputeEpochSecret(gc); err != nil {
		t.Fatalf("ComputeEpochSecret: %v", err)
	}
	secrets, err := ks.DeriveEpochSecrets()
	if err != nil {
		t.Fatalf("DeriveEpochSecrets: %v", err)
	}
	if secrets.EncryptionSecret == nil {
		t.Error("encryption_secret is nil")
	}
}

// ============================================================================
// SetPskSecretFromInput (interop testing path)
// ============================================================================

// TestSetPskSecretFromInput verifies that injecting a raw psk_secret input
// (test-vector style) produces the same member_secret as ComputePskSecret
// with an equivalent zero psk (when the input is the zero secret).
func TestSetPskSecretFromInput_ZeroEquivalence(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	gc := []byte("gc")

	// Using ComputePskSecret with zero PSK
	ks1 := NewKeySchedule(cs, ciphersuite.ZeroSecretCS(cs))
	ks1.SetCommitSecret(ciphersuite.ZeroSecretCS(cs))
	if _, err := ks1.ComputeJoinerSecret(gc); err != nil {
		t.Fatalf("ComputeJoinerSecret: %v", err)
	}
	if _, err := ks1.ComputePskSecret([]Psk{}); err != nil {
		t.Fatalf("ComputePskSecret: %v", err)
	}
	if _, err := ks1.ComputeEpochSecret(gc); err != nil {
		t.Fatalf("ComputeEpochSecret (ks1): %v", err)
	}
	s1, err := ks1.DeriveEpochSecrets()
	if err != nil {
		t.Fatalf("DeriveEpochSecrets (ks1): %v", err)
	}

	// Using SetPskSecretFromInput with the same zero secret
	ks2 := NewKeySchedule(cs, ciphersuite.ZeroSecretCS(cs))
	ks2.SetCommitSecret(ciphersuite.ZeroSecretCS(cs))
	if _, err := ks2.ComputeJoinerSecret(gc); err != nil {
		t.Fatalf("ComputeJoinerSecret (ks2): %v", err)
	}
	if err := ks2.SetPskSecretFromInput(ciphersuite.ZeroSecret(cs.HashLength())); err != nil {
		t.Fatalf("SetPskSecretFromInput: %v", err)
	}
	if _, err := ks2.ComputeEpochSecret(gc); err != nil {
		t.Fatalf("ComputeEpochSecret (ks2): %v", err)
	}
	s2, err := ks2.DeriveEpochSecrets()
	if err != nil {
		t.Fatalf("DeriveEpochSecrets (ks2): %v", err)
	}

	if !bytes.Equal(s1.EncryptionSecret.AsSlice(), s2.EncryptionSecret.AsSlice()) {
		t.Error("SetPskSecretFromInput(zero) != ComputePskSecret([]) — unexpected divergence")
	}
}

// ============================================================================
// WelcomeSecret derivation — RFC 9420 §8 ("welcome")
// ============================================================================

func TestWelcomeSecretDerivation(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	ks := NewKeySchedule(cs, ciphersuite.ZeroSecretCS(cs))
	ks.SetCommitSecret(ciphersuite.ZeroSecretCS(cs))

	if _, err := ks.ComputeJoinerSecret([]byte("gc")); err != nil {
		t.Fatalf("ComputeJoinerSecret: %v", err)
	}
	if _, err := ks.ComputePskSecret([]Psk{}); err != nil {
		t.Fatalf("ComputePskSecret: %v", err)
	}

	ws, err := ks.ComputeWelcomeSecret()
	if err != nil {
		t.Fatalf("ComputeWelcomeSecret: %v", err)
	}
	if ws == nil || ws.Len() == 0 {
		t.Error("welcome_secret is empty")
	}

	// WelcomeKeyNonce derives (key=16B, nonce=12B) from welcome_secret.
	welcomeKey, welcomeNonce, err := ks.WelcomeKeyNonce()
	if err != nil {
		t.Fatalf("WelcomeKeyNonce: %v", err)
	}
	if len(welcomeKey) != 16 {
		t.Errorf("welcome_key len = %d, want 16", len(welcomeKey))
	}
	if len(welcomeNonce) != 12 {
		t.Errorf("welcome_nonce len = %d, want 12", len(welcomeNonce))
	}
}

// ============================================================================
// ConfirmationTag — RFC 9420 §8.2
// ============================================================================

func TestConfirmationTag(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	key := bytes.Repeat([]byte{0x42}, 32)
	hash := bytes.Repeat([]byte{0x43}, 32)

	tag := ComputeConfirmationTag(cs, key, hash)
	if len(tag) != 32 {
		t.Errorf("tag len = %d, want 32", len(tag))
	}

	// Deterministic
	if !bytes.Equal(tag, ComputeConfirmationTag(cs, key, hash)) {
		t.Error("ComputeConfirmationTag is not deterministic")
	}
}

// ============================================================================
// MembershipTag — RFC 9420 §6.2.2
// ============================================================================

func TestMembershipTag(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	key := bytes.Repeat([]byte{0x01}, 32)
	content := []byte("authenticated content")

	tag := ComputeMembershipTag(cs, key, content)
	if len(tag) == 0 {
		t.Error("membership_tag is empty")
	}
	if !VerifyMembershipTag(cs, key, content, tag) {
		t.Error("VerifyMembershipTag failed for valid tag")
	}
	if VerifyMembershipTag(cs, key, []byte("other"), tag) {
		t.Error("VerifyMembershipTag should fail for wrong content")
	}
}

// ============================================================================
// Transcript hashes — RFC 9420 §8.2
// ============================================================================

func TestTranscriptHashes(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	interimHash := make([]byte, 32)
	framedContent := []byte("test framed content")
	sig := []byte("test signature")

	confirmedHash := ComputeTranscriptHash(cs, interimHash, framedContent, sig)
	if len(confirmedHash) != 32 {
		t.Errorf("confirmed_transcript_hash len = %d, want 32", len(confirmedHash))
	}

	interimHash2 := ComputeInterimTranscriptHash(cs, confirmedHash, []byte("confirm tag"))
	if len(interimHash2) != 32 {
		t.Errorf("interim_transcript_hash len = %d, want 32", len(interimHash2))
	}
}

// ============================================================================
// PSK combination — RFC 9420 §8.4
// ============================================================================

func TestPSKCombination(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	psks := []Psk{
		{PskType: PskTypeExternal, PskID: []byte("psk1"), Psk: []byte("secret1")},
		{PskType: PskTypeExternal, PskID: []byte("psk2"), Psk: []byte("secret2")},
	}

	pskInput, err := ComputePskInput(psks, cs)
	if err != nil {
		t.Fatalf("ComputePskInput: %v", err)
	}
	if len(pskInput) == 0 {
		t.Error("psk_input is empty")
	}

	// Single PSK → hash-length output
	single := []Psk{{PskType: PskTypeExternal, PskID: []byte("psk1"), Psk: []byte("secret1")}}
	singleInput, err := ComputePskInput(single, cs)
	if err != nil {
		t.Fatalf("ComputePskInput (single): %v", err)
	}
	if len(singleInput) != cs.HashLength() {
		t.Errorf("single PSK input len = %d, want %d", len(singleInput), cs.HashLength())
	}
}

// TestComputePskSecret_WithPSKs tests ComputePskSecret with external PSKs
func TestComputePskSecret_WithPSKs(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256

	// Create KeySchedule
	initSecret, _ := ciphersuite.NewSecretRandomCS(cs)
	ks := NewKeySchedule(cs, initSecret)

	// Set commit secret
	commitSecret, _ := ciphersuite.NewSecretRandomCS(cs)
	ks.SetCommitSecret(commitSecret)

	// Compute joiner secret
	groupContext := []byte("test group context")
	_, err := ks.ComputeJoinerSecret(groupContext)
	if err != nil {
		t.Fatalf("ComputeJoinerSecret: %v", err)
	}

	// PSKs externas
	psks := []Psk{
		{PskType: PskTypeExternal, PskID: []byte("psk1"), Psk: []byte("secret1")},
		{PskType: PskTypeExternal, PskID: []byte("psk2"), Psk: []byte("secret2")},
	}

	// ComputePskSecret con PSKs
	pskSecret, err := ks.ComputePskSecret(psks)
	if err != nil {
		t.Fatalf("ComputePskSecret: %v", err)
	}

	if pskSecret == nil {
		t.Fatal("ComputePskSecret should return non-nil secret")
	}

	// Verify that the result differs from the case without PSKs
	ks2 := NewKeySchedule(cs, initSecret)
	ks2.SetCommitSecret(commitSecret)
	if _, err := ks2.ComputeJoinerSecret(groupContext); err != nil {
		t.Fatalf("ComputeJoinerSecret failed: %v", err)
	}

	zeroPskSecret, err := ks2.ComputePskSecret([]Psk{})
	if err != nil {
		t.Fatalf("ComputePskSecret failed: %v", err)
	}

	if bytes.Equal(pskSecret.AsSlice(), zeroPskSecret.AsSlice()) {
		t.Error("PskSecret with PSKs should differ from zero PSK case")
	}
}

// TestPskInput_ResumptionType tests PSK with Resumption type
func TestPskInput_ResumptionType(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256

	// PSK de resumption
	psks := []Psk{
		{
			PskType:    PskTypeResumption,
			PskID:      []byte("resumption-psk-id"),
			Psk:        []byte("resumption-secret"),
			Usage:      0x01, // ResumptionPskUsageReinit
			PskGroupID: []byte("test-group"),
			PskEpoch:   5,
		},
	}

	pskInput, err := ComputePskInput(psks, cs)
	if err != nil {
		t.Fatalf("ComputePskInput with Resumption PSK: %v", err)
	}

	if len(pskInput) != cs.HashLength() {
		t.Errorf("Resumption PSK input len = %d, want %d", len(pskInput), cs.HashLength())
	}
}

// TestPskMarshal_Roundtrip tests PSK marshal/unmarshal roundtrip
// Nota: PskID no es exportado, testeamos ComputePskInput que lo usa internamente
func TestPskMarshal_Roundtrip(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256

	// PSK externa
	psks := []Psk{
		{
			PskType: PskTypeExternal,
			PskID:   []byte("external-psk-id"),
			Psk:     []byte("external-secret"),
		},
	}

	pskInput, err := ComputePskInput(psks, cs)
	if err != nil {
		t.Fatalf("ComputePskInput: %v", err)
	}

	if len(pskInput) != cs.HashLength() {
		t.Errorf("PSK input len = %d, want %d", len(pskInput), cs.HashLength())
	}

	// PSK de resumption
	psksResumption := []Psk{
		{
			PskType:    PskTypeResumption,
			PskID:      []byte("resumption-id"),
			Psk:        []byte("resumption-secret"),
			Usage:      0x01,
			PskGroupID: []byte("group-123"),
			PskEpoch:   10,
		},
	}

	pskInput2, err := ComputePskInput(psksResumption, cs)
	if err != nil {
		t.Fatalf("ComputePskInput (resumption): %v", err)
	}

	if len(pskInput2) != cs.HashLength() {
		t.Errorf("Resumption PSK input len = %d, want %d", len(pskInput2), cs.HashLength())
	}
}

// ============================================================================
// Exporter — RFC 9420 §8.5
// ============================================================================

func TestExporter_LengthAndLabel(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	exporterSecret, err := ciphersuite.NewSecretRandomCS(cs)
	if err != nil {
		t.Fatalf("NewSecretRandomCS: %v", err)
	}

	ctx := []byte("test context")

	// Requested length is honoured.
	for _, length := range []int{16, 32, 64} {
		out, err := Exporter(exporterSecret, cs, ExporterLabelAuthenticationKey, ctx, length)
		if err != nil {
			t.Fatalf("Exporter(len=%d): %v", length, err)
		}
		if len(out) != length {
			t.Errorf("Exporter len = %d, want %d", len(out), length)
		}
	}

	// Different labels produce different outputs.
	out1, _ := Exporter(exporterSecret, cs, "label-A", ctx, 32)
	out2, _ := Exporter(exporterSecret, cs, "label-B", ctx, 32)
	if bytes.Equal(out1, out2) {
		t.Error("different labels produced the same exported value")
	}

	// Different contexts produce different outputs.
	out3, _ := Exporter(exporterSecret, cs, "label-A", []byte("ctx-X"), 32)
	if bytes.Equal(out1, out3) {
		t.Error("different contexts produced the same exported value")
	}
}

// ============================================================================
// DeriveAuthenticationKey — RFC 9420 §8.5
// ============================================================================

func TestDeriveAuthenticationKey(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	ks := NewKeySchedule(cs, ciphersuite.ZeroSecretCS(cs))
	ks.SetCommitSecret(ciphersuite.ZeroSecretCS(cs))
	gc := []byte("gc")
	if _, err := ks.ComputeJoinerSecret(gc); err != nil {
		t.Fatalf("ComputeJoinerSecret: %v", err)
	}
	if _, err := ks.ComputePskSecret([]Psk{}); err != nil {
		t.Fatalf("ComputePskSecret: %v", err)
	}
	if _, err := ks.ComputeEpochSecret(gc); err != nil {
		t.Fatalf("ComputeEpochSecret: %v", err)
	}
	secrets, err := ks.DeriveEpochSecrets()
	if err != nil {
		t.Fatalf("DeriveEpochSecrets: %v", err)
	}

	authKey, err := DeriveAuthenticationKey(secrets.AuthenticationSecret)
	if err != nil {
		t.Fatalf("DeriveAuthenticationKey: %v", err)
	}
	if len(authKey) == 0 {
		t.Error("authentication key is empty")
	}
	// Deterministic
	authKey2, _ := DeriveAuthenticationKey(secrets.AuthenticationSecret)
	if !bytes.Equal(authKey, authKey2) {
		t.Error("DeriveAuthenticationKey is not deterministic")
	}
}
