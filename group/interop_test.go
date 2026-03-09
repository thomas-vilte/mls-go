package group

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/schedule"
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
	if os.Getenv("MLS_RUN_INTEROP_VECTORS") == "" {
		t.Skip("set MLS_RUN_INTEROP_VECTORS=1 to run official interop vectors")
	}

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
				initSecret := ciphersuite.NewSecret(currentInitSecret)
				commitSecret := ciphersuite.NewSecret(mustHex(t, epoch.CommitSecret))
				groupContext := mustHex(t, epoch.GroupContext)

				ks := schedule.NewKeySchedule(cs, initSecret)
				ks.SetCommitSecret(commitSecret)

				joinerSecret, err := ks.ComputeJoinerSecret(groupContext)
				if err != nil {
					t.Fatalf("ComputeJoinerSecret: %v", err)
				}
				if !bytes.Equal(joinerSecret.AsSlice(), mustHex(t, epoch.JoinerSecret)) {
					t.Fatalf("joiner_secret mismatch")
				}

				memberSecret, err := ks.ComputePskSecret(nil)
				if err != nil {
					t.Fatalf("ComputePskSecret: %v", err)
				}
				if !bytes.Equal(memberSecret.AsSlice(), mustHex(t, epoch.PskSecret)) {
					t.Fatalf("psk_secret mismatch")
				}

				if _, err := ks.ComputeEpochSecret(groupContext); err != nil {
					t.Fatalf("ComputeEpochSecret: %v", err)
				}

				welcomeSecret, err := ks.ComputeWelcomeSecret()
				if err != nil {
					t.Fatalf("ComputeWelcomeSecret: %v", err)
				}
				if !bytes.Equal(welcomeSecret.AsSlice(), mustHex(t, epoch.WelcomeSecret)) {
					t.Fatalf("welcome_secret mismatch")
				}

				derived, err := ks.DeriveEpochSecrets()
				if err != nil {
					t.Fatalf("DeriveEpochSecrets: %v", err)
				}

				if !bytes.Equal(derived.SenderDataSecret.AsSlice(), mustHex(t, epoch.SenderDataSecret)) {
					t.Fatalf("sender_data_secret mismatch")
				}
				if !bytes.Equal(derived.EncryptionSecret.AsSlice(), mustHex(t, epoch.EncryptionSecret)) {
					t.Fatalf("encryption_secret mismatch")
				}
				if !bytes.Equal(derived.ExporterSecret.AsSlice(), mustHex(t, epoch.ExporterSecret)) {
					t.Fatalf("exporter_secret mismatch")
				}
				if !bytes.Equal(derived.ConfirmationKey.AsSlice(), mustHex(t, epoch.ConfirmationKey)) {
					t.Fatalf("confirmation_key mismatch")
				}
				if !bytes.Equal(derived.MembershipKey.AsSlice(), mustHex(t, epoch.MembershipKey)) {
					t.Fatalf("membership_key mismatch")
				}
				if !bytes.Equal(derived.ExternalSecret.AsSlice(), mustHex(t, epoch.ExternalSecret)) {
					t.Fatalf("external_secret mismatch")
				}
				if !bytes.Equal(derived.ResumptionSecret.AsSlice(), mustHex(t, epoch.ResumptionPsk)) {
					t.Fatalf("resumption_psk mismatch")
				}
				if !bytes.Equal(derived.InitSecret.AsSlice(), mustHex(t, epoch.InitSecret)) {
					t.Fatalf("init_secret mismatch")
				}

				currentInitSecret = derived.InitSecret.AsSlice()
			})
		}
	}
}
