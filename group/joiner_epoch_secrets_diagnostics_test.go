//go:build diagnostics

package group

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// diagnosticMember is a member with its key package, private keys and signing key.
type diagnosticMember struct {
	name string
	kp   *keypackages.KeyPackage
	priv *keypackages.KeyPackagePrivateKeys
	sig  *ciphersuite.SignaturePrivateKey
}

func newDiagnosticMember(t *testing.T, name string) diagnosticMember {
	t.Helper()
	cred, _, err := credentials.GenerateCredentialWithKey([]byte(name))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(%s): %v", name, err)
	}
	kp, priv, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage(%s): %v", name, err)
	}
	return diagnosticMember{name: name, kp: kp, priv: priv, sig: ciphersuite.NewSignaturePrivateKey(priv.SignatureKey)}
}

// createDiagnosticGroup creates a one-member group for u (epoch 0).
func createDiagnosticGroup(t *testing.T, u diagnosticMember) *Group {
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

// commitAndJoin commits the pending proposals of committer, merges the commit, and joins each
// user in joiners through one Welcome. The joiners use JoinFromWelcome directly; no epoch secrets are
// copied from the committer.
func commitAndJoin(t *testing.T, committer *Group, by diagnosticMember, joiners ...diagnosticMember) []*Group {
	t.Helper()
	staged, err := committer.Commit(by.sig, by.sig.PublicKey(), nil)
	if err != nil {
		t.Fatalf("Commit by %s: %v", by.name, err)
	}
	joiner := staged.JoinerSecret()
	if err := committer.MergeCommit(staged); err != nil {
		t.Fatalf("MergeCommit by %s: %v", by.name, err)
	}
	if len(joiners) == 0 {
		return nil
	}
	kps := make([]*keypackages.KeyPackage, len(joiners))
	for i, j := range joiners {
		kps[i] = j.kp
	}
	w, err := committer.CreateWelcomeWithOpts(kps, by.sig, WithJoinerSecret(joiner), WithStagedCommit(staged))
	if err != nil {
		t.Fatalf("CreateWelcome by %s: %v", by.name, err)
	}
	out := make([]*Group, len(joiners))
	for i, j := range joiners {
		out[i], err = JoinFromWelcome(w, j.kp, j.priv, nil)
		if err != nil {
			t.Fatalf("JoinFromWelcome(%s): %v", j.name, err)
		}
	}
	return out
}

// exchangeMessages sends one application message each way between a and b and checks the plaintext.
func exchangeMessages(t *testing.T, a *Group, aUser diagnosticMember, b *Group, bUser diagnosticMember) {
	t.Helper()
	for _, dir := range []struct {
		from     *Group
		fromUser diagnosticMember
		to       *Group
	}{{a, aUser, b}, {b, bUser, a}} {
		text := []byte("diagnostics " + dir.fromUser.name)
		pm, err := dir.from.SendMessage(text, dir.fromUser.sig)
		if err != nil {
			t.Fatalf("SendMessage(%s): %v", dir.fromUser.name, err)
		}
		got, err := dir.to.ReceiveMessage(pm, dir.from.ownLeafIndex)
		if err != nil {
			t.Fatalf("ReceiveMessage from %s: %v", dir.fromUser.name, err)
		}
		if !bytes.Equal(got, text) {
			t.Fatalf("plaintext from %s = %q, want %q", dir.fromUser.name, got, text)
		}
	}
}

// assertDiagnosticExportEqual checks that two groups derive the same exporter output.
func assertDiagnosticExportEqual(t *testing.T, a, b *Group) {
	t.Helper()
	ea, err := a.Export("diagnostics", []byte("ctx"), 32)
	if err != nil {
		t.Fatalf("Export(a): %v", err)
	}
	eb, err := b.Export("diagnostics", []byte("ctx"), 32)
	if err != nil {
		t.Fatalf("Export(b): %v", err)
	}
	if !bytes.Equal(ea, eb) {
		t.Fatalf("exporter differs between members: %x vs %x", ea, eb)
	}
}

// TestJoinerEpochSecretsMatchCommitterWithoutCopy checks that a joiner who joins through a Welcome derives the
// same epoch secrets as the committer, with no copy of the committer's secrets into the joiner. A copy would
// hide any difference between both derivations.
func TestJoinerEpochSecretsMatchCommitterWithoutCopy(t *testing.T) {
	alice := newDiagnosticMember(t, "Alice")
	bob := newDiagnosticMember(t, "Bob")
	ag := createDiagnosticGroup(t, alice)
	if _, err := ag.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	bg := commitAndJoin(t, ag, alice, bob)[0]

	a, b := ag.epochSecrets, bg.epochSecrets
	checks := []struct {
		name string
		x, y *ciphersuite.Secret
	}{
		{"init", a.InitSecret, b.InitSecret},
		{"sender_data", a.SenderDataSecret, b.SenderDataSecret},
		{"encryption", a.EncryptionSecret, b.EncryptionSecret},
		{"exporter", a.ExporterSecret, b.ExporterSecret},
		{"external", a.ExternalSecret, b.ExternalSecret},
		{"confirmation", a.ConfirmationKey, b.ConfirmationKey},
		{"membership", a.MembershipKey, b.MembershipKey},
		{"authentication", a.AuthenticationSecret, b.AuthenticationSecret},
		{"resumption", a.ResumptionSecret, b.ResumptionSecret},
	}
	for _, c := range checks {
		if !bytes.Equal(c.x.AsSlice(), c.y.AsSlice()) {
			t.Errorf("joiner derives a different %s secret than the committer", c.name)
		}
	}
	assertDiagnosticExportEqual(t, ag, bg)
	exchangeMessages(t, ag, alice, bg, bob)
}

// TestEpochZeroGroupSurvivesStateRoundTrip checks that the epoch 0 group created by NewGroup keeps its key
// schedule when it is serialized and restored: a commit and a Welcome from the restored group still work.
func TestEpochZeroGroupSurvivesStateRoundTrip(t *testing.T) {
	alice := newDiagnosticMember(t, "Alice")
	bob := newDiagnosticMember(t, "Bob")
	ag := createDiagnosticGroup(t, alice)

	state, err := ag.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState at epoch 0: %v", err)
	}
	restored, err := UnmarshalGroupState(state)
	if err != nil {
		t.Fatalf("UnmarshalGroupState at epoch 0: %v", err)
	}
	if err := restored.ValidateRestoredState(); err != nil {
		t.Fatalf("ValidateRestoredState at epoch 0: %v", err)
	}
	assertDiagnosticExportEqual(t, ag, restored)

	if _, err := restored.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember on restored group: %v", err)
	}
	bg := commitAndJoin(t, restored, alice, bob)[0]
	assertDiagnosticExportEqual(t, restored, bg)
	exchangeMessages(t, restored, alice, bg, bob)
}
