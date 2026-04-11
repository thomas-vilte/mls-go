package group

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/schedule"
)

type keyScheduleEpochVector struct {
	CommitSecret     string `json:"commit_secret"`
	ConfirmationKey  string `json:"confirmation_key"`
	EncryptionSecret string `json:"encryption_secret"`
	ExporterSecret   string `json:"exporter_secret"`
	ExternalSecret   string `json:"external_secret"`
	GroupContext     string `json:"group_context"`
	InitSecret       string `json:"init_secret"`
	JoinerSecret     string `json:"joiner_secret"`
	MembershipKey    string `json:"membership_key"`
	PskSecret        string `json:"psk_secret"`
	ResumptionPsk    string `json:"resumption_psk"`
	SenderDataSecret string `json:"sender_data_secret"`
	WelcomeSecret    string `json:"welcome_secret"`
}

type keyScheduleVector struct {
	CipherSuite       uint16                   `json:"cipher_suite"`
	InitialInitSecret string                   `json:"initial_init_secret"`
	Epochs            []keyScheduleEpochVector `json:"epochs"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

func TestKeyScheduleVectors(t *testing.T) {
	// Test vectors oficiales de MLSWG:
	// https://github.com/mlswg/mls-implementations/blob/main/test-vectors/key-schedule.json
	//
	// psk_secret is an INPUT to the key schedule, not an output.
	// Used to incorporate external or resumption PSKs.

	data, err := os.ReadFile("../testdata/mls-interop-testvectors/test-vectors/key-schedule.json")
	if err != nil {
		if os.IsNotExist(err) {
			t.Skip("key-schedule interop vectors not available")
		}
		t.Fatalf("read vector file: %v", err)
	}

	var vectors []keyScheduleVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("unmarshal vectors: %v", err)
	}

	for _, v := range vectors {
		currentInitSecret := mustHex(t, v.InitialInitSecret)
		for i, epoch := range v.Epochs {
			name := fmt.Sprintf("cs-%d-epoch-%d", v.CipherSuite, i)
			t.Run(name, func(t *testing.T) {
				cs := ciphersuite.CipherSuite(v.CipherSuite)

				// Skip unsupported cipher suites (CS4-7 are placeholders)
				if !cs.IsSupported() {
					t.Skipf("cipher suite %d not implemented", v.CipherSuite)
				}

				initSecret := ciphersuite.NewSecret(currentInitSecret)
				commitSecret := ciphersuite.NewSecret(mustHex(t, epoch.CommitSecret))
				groupContext := mustHex(t, epoch.GroupContext)

				// psk_secret is an INPUT from the test vector
				pskSecretInput := mustHex(t, epoch.PskSecret)

				ks := schedule.NewKeySchedule(cs, initSecret)
				ks.SetCommitSecret(commitSecret)

				joinerSecret, err := ks.ComputeJoinerSecret(groupContext)
				if err != nil {
					t.Fatalf("ComputeJoinerSecret: %v", err)
				}
				if !bytes.Equal(joinerSecret.AsSlice(), mustHex(t, epoch.JoinerSecret)) {
					t.Fatalf("joiner_secret sametch")
				}

				// Use the psk_secret from test vector as direct input
				// Use the input directly instead of computing with ComputePskSecret(nil)
				err = ks.SetPskSecretFromInput(ciphersuite.NewSecret(pskSecretInput))
				if err != nil {
					t.Fatalf("SetPskSecretFromInput: %v", err)
				}

				if _, err := ks.ComputeEpochSecret(groupContext); err != nil {
					t.Fatalf("ComputeEpochSecret: %v", err)
				}

				welcomeSecret, err := ks.ComputeWelcomeSecret()
				if err != nil {
					t.Fatalf("ComputeWelcomeSecret: %v", err)
				}
				if !bytes.Equal(welcomeSecret.AsSlice(), mustHex(t, epoch.WelcomeSecret)) {
					t.Fatalf("welcome_secret sametch")
				}

				derived, err := ks.DeriveEpochSecrets()
				if err != nil {
					t.Fatalf("DeriveEpochSecrets: %v", err)
				}

				if !bytes.Equal(derived.SenderDataSecret.AsSlice(), mustHex(t, epoch.SenderDataSecret)) {
					t.Fatalf("sender_data_secret sametch")
				}
				if !bytes.Equal(derived.EncryptionSecret.AsSlice(), mustHex(t, epoch.EncryptionSecret)) {
					t.Fatalf("encryption_secret sametch")
				}
				if !bytes.Equal(derived.ExporterSecret.AsSlice(), mustHex(t, epoch.ExporterSecret)) {
					t.Fatalf("exporter_secret sametch")
				}
				if !bytes.Equal(derived.ConfirmationKey.AsSlice(), mustHex(t, epoch.ConfirmationKey)) {
					t.Fatalf("confirmation_key sametch")
				}
				if !bytes.Equal(derived.MembershipKey.AsSlice(), mustHex(t, epoch.MembershipKey)) {
					t.Fatalf("membership_key sametch")
				}
				if !bytes.Equal(derived.ExternalSecret.AsSlice(), mustHex(t, epoch.ExternalSecret)) {
					t.Fatalf("external_secret sametch")
				}
				if !bytes.Equal(derived.ResumptionSecret.AsSlice(), mustHex(t, epoch.ResumptionPsk)) {
					t.Fatalf("resumption_psk sametch")
				}
				if !bytes.Equal(derived.InitSecret.AsSlice(), mustHex(t, epoch.InitSecret)) {
					t.Fatalf("init_secret sametch")
				}

				currentInitSecret = derived.InitSecret.AsSlice()
			})
		}
	}
}
