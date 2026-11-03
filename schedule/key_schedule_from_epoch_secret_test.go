package schedule

import (
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// TestNewKeyScheduleFromEpochSecret checks that a schedule seeded with a fresh
// epoch_secret derives the nine epoch secrets of RFC 9420 §8, Table 4, with the
// hash of the cipher suite (SHA-256 and SHA-512 suites).
func TestNewKeyScheduleFromEpochSecret(t *testing.T) {
	suites := []ciphersuite.CipherSuite{
		ciphersuite.MLS128DHKEMX25519,
		ciphersuite.MLS128DHKEMP256,
		ciphersuite.MLS256DHKEMP521AES256GCM,
	}
	for _, cs := range suites {
		epochSecret, err := ciphersuite.NewSecretRandomCS(cs)
		if err != nil {
			t.Fatalf("NewSecretRandomCS(%v): %v", cs, err)
		}

		got, err := NewKeyScheduleFromEpochSecret(cs, epochSecret).DeriveEpochSecrets()
		if err != nil {
			t.Fatalf("DeriveEpochSecrets(%v): %v", cs, err)
		}

		checks := []struct {
			label  string
			secret *ciphersuite.Secret
		}{
			{"sender data", got.SenderDataSecret},
			{"encryption", got.EncryptionSecret},
			{"exporter", got.ExporterSecret},
			{"authentication", got.AuthenticationSecret},
			{"confirm", got.ConfirmationKey},
			{"membership", got.MembershipKey},
			{"external", got.ExternalSecret},
			{"resumption", got.ResumptionSecret},
			{"init", got.InitSecret},
		}
		for _, c := range checks {
			want, err := epochSecret.DeriveSecret(cs, c.label)
			if err != nil {
				t.Fatalf("DeriveSecret(%q) for %v: %v", c.label, cs, err)
			}
			if !c.secret.Equal(want) {
				t.Errorf("%v: secret for label %q is not DeriveSecret(epoch_secret, %q)", cs, c.label, c.label)
			}
			if c.secret.Len() != cs.HashLength() {
				t.Errorf("%v: secret for label %q has length %d, want %d", cs, c.label, c.secret.Len(), cs.HashLength())
			}
		}
	}
}
