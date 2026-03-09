package schedule

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/openmls/go/ciphersuite"
)

// keyScheduleEpoch mirrors one epoch entry from the key-schedule test vector JSON.
type keyScheduleEpoch struct {
	CommitSecret       string `json:"commit_secret"`
	JoinerSecret       string `json:"joiner_secret"`
	PskSecret          string `json:"psk_secret"`
	GroupContext       string `json:"group_context"`
	WelcomeSecret      string `json:"welcome_secret"`
	EncryptionSecret   string `json:"encryption_secret"`
	SenderDataSecret   string `json:"sender_data_secret"`
	ExporterSecret     string `json:"exporter_secret"`
	EpochAuthenticator string `json:"epoch_authenticator"`
	ExternalSecret     string `json:"external_secret"`
	ConfirmationKey    string `json:"confirmation_key"`
	MembershipKey      string `json:"membership_key"`
	ResumptionPsk      string `json:"resumption_psk"`
	InitSecret         string `json:"init_secret"`
}

type keyScheduleVector struct {
	CipherSuite       uint16             `json:"cipher_suite"`
	GroupID           string             `json:"group_id"`
	InitialInitSecret string             `json:"initial_init_secret"`
	Epochs            []keyScheduleEpoch `json:"epochs"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

func TestKeyScheduleInteropVectors(t *testing.T) {
	data, err := os.ReadFile("../testdata/mls-interop-testvectors/test-vectors/key-schedule.json")
	if err != nil {
		t.Skipf("key-schedule.json not found: %v", err)
	}

	var vectors []keyScheduleVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse key-schedule.json: %v", err)
	}

	for _, vec := range vectors {
		cs := ciphersuite.CipherSuite(vec.CipherSuite)
		if !cs.IsSupported() {
			t.Logf("skipping unsupported cipher suite %d", vec.CipherSuite)
			continue
		}

		t.Run(cs.String(), func(t *testing.T) {
			// First epoch starts with the provided initial_init_secret.
			initSecret := ciphersuite.NewSecret(mustHex(t, vec.InitialInitSecret))

			for i, epoch := range vec.Epochs {
				commitSecretBytes := mustHex(t, epoch.CommitSecret)
				expectedJoiner := mustHex(t, epoch.JoinerSecret)
				expectedPskSecretInput := mustHex(t, epoch.PskSecret)
				groupContextBytes := mustHex(t, epoch.GroupContext)
				expectedWelcome := mustHex(t, epoch.WelcomeSecret)
				expectedEncryption := mustHex(t, epoch.EncryptionSecret)
				expectedSenderData := mustHex(t, epoch.SenderDataSecret)
				expectedExporter := mustHex(t, epoch.ExporterSecret)
				expectedEpochAuth := mustHex(t, epoch.EpochAuthenticator)
				expectedExternal := mustHex(t, epoch.ExternalSecret)
				expectedConfirmKey := mustHex(t, epoch.ConfirmationKey)
				expectedMembership := mustHex(t, epoch.MembershipKey)
				expectedResumption := mustHex(t, epoch.ResumptionPsk)
				expectedInitSecret := mustHex(t, epoch.InitSecret)

				ks := NewKeySchedule(cs, initSecret)
				ks.SetCommitSecret(ciphersuite.NewSecret(commitSecretBytes))

				// joiner_secret = ExpandWithLabel(Extract(init_secret, commit_secret), "joiner", GroupContext, Nh)
				joinerSecret, err := ks.ComputeJoinerSecret(groupContextBytes)
				if err != nil {
					t.Fatalf("epoch %d: ComputeJoinerSecret: %v", i, err)
				}
				if got := joinerSecret.AsSlice(); !bytesEqual(got, expectedJoiner) {
					t.Errorf("epoch %d: joiner_secret\n  got  %x\n  want %x", i, got, expectedJoiner)
				}

				// Inject psk_secret from vector directly.
				if err := ks.SetPskSecretDirect(ciphersuite.NewSecret(expectedPskSecretInput)); err != nil {
					t.Fatalf("epoch %d: SetPskSecretDirect: %v", i, err)
				}

				// welcome_secret
				welcomeSecret, err := ks.ComputeWelcomeSecret()
				if err != nil {
					t.Fatalf("epoch %d: ComputeWelcomeSecret: %v", i, err)
				}
				if got := welcomeSecret.AsSlice(); !bytesEqual(got, expectedWelcome) {
					t.Errorf("epoch %d: welcome_secret\n  got  %x\n  want %x", i, got, expectedWelcome)
				}

				// epoch_secret = ExpandWithLabel(member_secret, "epoch", GroupContext, Nh)
				if _, err := ks.ComputeEpochSecret(groupContextBytes); err != nil {
					t.Fatalf("epoch %d: ComputeEpochSecret: %v", i, err)
				}

				// Derive all epoch secrets.
				secrets, err := ks.DeriveEpochSecrets()
				if err != nil {
					t.Fatalf("epoch %d: DeriveEpochSecrets: %v", i, err)
				}

				check := func(name string, got *ciphersuite.Secret, want []byte) {
					t.Helper()
					if got == nil {
						t.Errorf("epoch %d: %s is nil", i, name)
						return
					}
					if !bytesEqual(got.AsSlice(), want) {
						t.Errorf("epoch %d: %s\n  got  %x\n  want %x", i, name, got.AsSlice(), want)
					}
				}

				check("sender_data_secret", secrets.SenderDataSecret, expectedSenderData)
				check("encryption_secret", secrets.EncryptionSecret, expectedEncryption)
				check("exporter_secret", secrets.ExporterSecret, expectedExporter)
				check("epoch_authenticator", secrets.AuthenticationSecret, expectedEpochAuth)
				check("external_secret", secrets.ExternalSecret, expectedExternal)
				check("confirmation_key", secrets.ConfirmationKey, expectedConfirmKey)
				check("membership_key", secrets.MembershipKey, expectedMembership)
				check("resumption_psk", secrets.ResumptionSecret, expectedResumption)
				check("init_secret", secrets.InitSecret, expectedInitSecret)

				// The output init_secret feeds into the next epoch.
				initSecret = secrets.InitSecret.Clone()
			}
		})
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
