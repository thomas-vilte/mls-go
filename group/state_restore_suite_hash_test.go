package group

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// restoreSuites lists the cipher suites that the restore tests run with. CS5 hashes with SHA-512, the others
// with SHA-256, which is the default hash of ciphersuite.NewSecret.
var restoreSuites = []struct {
	name string
	cs   ciphersuite.CipherSuite
}{
	{"CS1", ciphersuite.MLS128DHKEMX25519},
	{"CS2", ciphersuite.MLS128DHKEMP256},
	{"CS3", ciphersuite.MLS128DHKEMX25519ChaCha20},
	{"CS5", ciphersuite.MLS256DHKEMP521AES256GCM},
}

// restoreMember holds the keys of a test member for one cipher suite.
type restoreMember struct {
	kp      *keypackages.KeyPackage
	priv    *keypackages.KeyPackagePrivateKeys
	sigPriv *ciphersuite.SignaturePrivateKey
}

func newRestoreMember(t *testing.T, name string, cs ciphersuite.CipherSuite) *restoreMember {
	t.Helper()
	cred, sigPriv, err := credentials.GenerateCredentialWithKeyForCS([]byte(name), cs)
	if err != nil {
		t.Fatalf("GenerateCredentialWithKeyForCS(%s): %v", name, err)
	}
	kp, priv, err := keypackages.Generate(cred, cs)
	if err != nil {
		t.Fatalf("keypackages.Generate(%s): %v", name, err)
	}
	return &restoreMember{kp: kp, priv: priv, sigPriv: sigPriv}
}

func newRestoreGroup(t *testing.T, m *restoreMember, cs ciphersuite.CipherSuite) *Group {
	t.Helper()
	gid, err := NewGroupIDRandom()
	if err != nil {
		t.Fatalf("NewGroupIDRandom: %v", err)
	}
	g, err := NewGroup(gid, cs, m.kp, m.priv)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	return g
}

// TestRestoredStateKeepsExporterOutput checks that Export returns the same bytes before and after the group state
// is saved and loaded. The exporter_secret is restored with the hash of the cipher suite; restoring it with the
// SHA-256 default derived different output for CS5.
func TestRestoredStateKeepsExporterOutput(t *testing.T) {
	for _, tc := range restoreSuites {
		t.Run(tc.name, func(t *testing.T) {
			g := newRestoreGroup(t, newRestoreMember(t, "alice", tc.cs), tc.cs)
			ctx := []byte("restore context")

			before, err := g.Export("restore label", ctx, 32)
			if err != nil {
				t.Fatalf("Export (original): %v", err)
			}
			state, err := g.MarshalState()
			if err != nil {
				t.Fatalf("MarshalState: %v", err)
			}
			restored, err := UnmarshalGroupState(state)
			if err != nil {
				t.Fatalf("UnmarshalGroupState: %v", err)
			}
			after, err := restored.Export("restore label", ctx, 32)
			if err != nil {
				t.Fatalf("Export (restored): %v", err)
			}
			if !bytes.Equal(before, after) {
				t.Errorf("Export differs after restore (cs=%v)", tc.cs)
			}
		})
	}
}

// TestRestoredMemberKeepsSendingToOthers checks that a member whose state was saved and loaded can keep sending
// messages that the other member decrypts. Alice sends, her state is restored, and she sends again.
func TestRestoredMemberKeepsSendingToOthers(t *testing.T) {
	for _, tc := range restoreSuites {
		t.Run(tc.name, func(t *testing.T) {
			alice := newRestoreMember(t, "alice", tc.cs)
			bob := newRestoreMember(t, "bob", tc.cs)
			aliceGroup := newRestoreGroup(t, alice, tc.cs)
			if _, err := aliceGroup.AddMember(bob.kp); err != nil {
				t.Fatalf("AddMember(bob): %v", err)
			}
			sc, err := aliceGroup.Commit(alice.sigPriv, alice.sigPriv.PublicKey(), nil)
			if err != nil {
				t.Fatalf("Commit: %v", err)
			}
			joinerSecret := sc.JoinerSecret()
			if err := aliceGroup.MergeCommit(sc); err != nil {
				t.Fatalf("MergeCommit: %v", err)
			}
			welcome, err := aliceGroup.CreateWelcomeWithOpts([]*keypackages.KeyPackage{bob.kp}, alice.sigPriv,
				WithJoinerSecret(joinerSecret), WithStagedCommit(sc))
			if err != nil {
				t.Fatalf("CreateWelcomeWithOpts: %v", err)
			}
			bobGroup, err := JoinFromWelcome(welcome, bob.kp, bob.priv, nil)
			if err != nil {
				t.Fatalf("JoinFromWelcome: %v", err)
			}

			// Control: the message sent before the restore is decrypted.
			first := []byte("before the restore")
			pm, err := aliceGroup.SendMessage(first, alice.sigPriv)
			if err != nil {
				t.Fatalf("SendMessage (before restore): %v", err)
			}
			if got, err := bobGroup.ReceiveMessage(pm, aliceGroup.ownLeafIndex); err != nil || !bytes.Equal(got, first) {
				t.Fatalf("bob receiving the message sent before the restore = %q, %v", got, err)
			}

			state, err := aliceGroup.MarshalState()
			if err != nil {
				t.Fatalf("MarshalState: %v", err)
			}
			restoredAlice, err := UnmarshalGroupState(state)
			if err != nil {
				t.Fatalf("UnmarshalGroupState: %v", err)
			}
			second := []byte("after the restore")
			pm, err = restoredAlice.SendMessage(second, alice.sigPriv)
			if err != nil {
				t.Fatalf("SendMessage (restored): %v", err)
			}
			if got, err := bobGroup.ReceiveMessage(pm, restoredAlice.ownLeafIndex); err != nil || !bytes.Equal(got, second) {
				t.Errorf("bob receiving the message sent by the restored member = %q, %v; want %q", got, err, second)
			}
		})
	}
}

// TestUnmarshalGroupStateRejectsUnsupportedSuite checks that restoring a state with a cipher suite that is not
// implemented fails with ErrUnsupportedSuite. The epoch secrets used to fall back to SHA-256 without an error.
func TestUnmarshalGroupStateRejectsUnsupportedSuite(t *testing.T) {
	const unsupported = ciphersuite.MLS256DHKEMX448AES256GCM

	data, err := json.Marshal(StateData{CipherSuite: uint16(unsupported)})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if _, err := UnmarshalGroupState(data); !errors.Is(err, ciphersuite.ErrUnsupportedSuite) {
		t.Errorf("UnmarshalGroupState(cs=%v): err = %v, want ErrUnsupportedSuite", unsupported, err)
	}
}
