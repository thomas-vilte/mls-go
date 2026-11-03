package group

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// Tests for the epoch secrets that a joiner derives from a Welcome.

// joinTestMember is a member with its key package, private keys and signing key.
type joinTestMember struct {
	name string
	kp   *keypackages.KeyPackage
	priv *keypackages.KeyPackagePrivateKeys
	sig  *ciphersuite.SignaturePrivateKey
}

func newJoinTestMember(t *testing.T, name string) joinTestMember {
	t.Helper()
	cred, _, err := credentials.GenerateCredentialWithKey([]byte(name))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(%s): %v", name, err)
	}
	kp, priv, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage(%s): %v", name, err)
	}
	return joinTestMember{name: name, kp: kp, priv: priv, sig: ciphersuite.NewSignaturePrivateKey(priv.SignatureKey)}
}

// createJoinTestGroup creates a one-member group for u (epoch 0).
func createJoinTestGroup(t *testing.T, u joinTestMember) *Group {
	t.Helper()
	gid, err := NewGroupIDRandom()
	if err != nil {
		t.Fatalf("NewGroupIDRandom: %v", err)
	}
	g, err := NewGroup(gid, ciphersuite.MLS128DHKEMP256, u.kp, u.priv)
	if err != nil {
		t.Fatalf("NewGroup(%s): %v", u.name, err)
	}
	return g
}

// joinThroughWelcome commits the pending proposals of committer, merges the commit, and joins each user in
// joiners through one Welcome. The joiners derive their state from the Welcome alone.
func joinThroughWelcome(t *testing.T, committer *Group, by joinTestMember, joiners ...joinTestMember) []*Group {
	t.Helper()
	staged, err := committer.Commit(by.sig, by.sig.PublicKey(), nil)
	if err != nil {
		t.Fatalf("Commit by %s: %v", by.name, err)
	}
	joinerSecret := staged.JoinerSecret()
	if err := committer.MergeCommit(staged); err != nil {
		t.Fatalf("MergeCommit by %s: %v", by.name, err)
	}
	kps := make([]*keypackages.KeyPackage, len(joiners))
	for i, j := range joiners {
		kps[i] = j.kp
	}
	welcome, err := committer.CreateWelcomeWithOpts(kps, by.sig, WithJoinerSecret(joinerSecret), WithStagedCommit(staged))
	if err != nil {
		t.Fatalf("CreateWelcome by %s: %v", by.name, err)
	}
	out := make([]*Group, len(joiners))
	for i, j := range joiners {
		out[i], err = JoinFromWelcome(welcome, j.kp, j.priv, nil)
		if err != nil {
			t.Fatalf("JoinFromWelcome(%s): %v", j.name, err)
		}
	}
	return out
}

// assertSameExport checks that two groups derive the same exporter output.
func assertSameExport(t *testing.T, a, b *Group) {
	t.Helper()
	ea, err := a.Export("join-test", []byte("ctx"), 32)
	if err != nil {
		t.Fatalf("Export(a): %v", err)
	}
	eb, err := b.Export("join-test", []byte("ctx"), 32)
	if err != nil {
		t.Fatalf("Export(b): %v", err)
	}
	if !bytes.Equal(ea, eb) {
		t.Fatalf("exporter differs between members: %x vs %x", ea, eb)
	}
}

// assertSameEpochSecrets fails unless every epoch secret of a equals the one of b. setupTwoMemberGroup uses
// it instead of copying the committer's secrets into the joiner, because the copy hid any difference.
func assertSameEpochSecrets(t *testing.T, a, b *Group) {
	t.Helper()
	x, y := a.epochSecrets, b.epochSecrets
	checks := []struct {
		name string
		p, q *ciphersuite.Secret
	}{
		{"init", x.InitSecret, y.InitSecret},
		{"sender_data", x.SenderDataSecret, y.SenderDataSecret},
		{"encryption", x.EncryptionSecret, y.EncryptionSecret},
		{"exporter", x.ExporterSecret, y.ExporterSecret},
		{"external", x.ExternalSecret, y.ExternalSecret},
		{"confirmation", x.ConfirmationKey, y.ConfirmationKey},
		{"membership", x.MembershipKey, y.MembershipKey},
		{"authentication", x.AuthenticationSecret, y.AuthenticationSecret},
		{"resumption", x.ResumptionSecret, y.ResumptionSecret},
	}
	for _, c := range checks {
		if c.p == nil || c.q == nil {
			t.Errorf("%s secret is missing on one of the members", c.name)
			continue
		}
		if !bytes.Equal(c.p.AsSlice(), c.q.AsSlice()) {
			t.Errorf("joiner derives a different %s secret than the committer", c.name)
		}
	}
}

// TestJoinerDerivesCommitterEpochSecrets checks that bob, who joins through a Welcome, has the same epoch
// secrets as alice. This is the check that setupTwoMemberGroup now makes instead of copying the secrets.
func TestJoinerDerivesCommitterEpochSecrets(t *testing.T) {
	alice := newJoinTestMember(t, "Alice")
	bob := newJoinTestMember(t, "Bob")
	ag := createJoinTestGroup(t, alice)
	if _, err := ag.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	bg := joinThroughWelcome(t, ag, alice, bob)[0]
	assertSameEpochSecrets(t, ag, bg)
	assertSameExport(t, ag, bg)
}
