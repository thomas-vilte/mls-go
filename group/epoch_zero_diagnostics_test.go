//go:build diagnostics

package group

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// TestEpochZeroSecretsDifferFromPublicRebuild checks that none of the secrets rebuilt from the public
// GroupContext matches the epoch 0 secrets of the group. The rebuild uses the former derivation (zero
// init_secret and commit_secret, no PSK). The helpers are the ones of group_creation_epoch_secret_test.go.
func TestEpochZeroSecretsDifferFromPublicRebuild(t *testing.T) {
	alice := newDiagnosticMember(t, "Alice")
	ag := createDiagnosticGroup(t, alice)
	cs := ag.cipherSuite
	rebuilt := rebuildEpochFromPublicValues(t, cs, ciphersuite.ZeroSecretCS(cs), ag.groupContext.Marshal())
	if equal, _ := compareEpochSecrets(ag.epochSecrets, rebuilt); len(equal) > 0 {
		t.Errorf("epoch 0 secrets reproducible from public data (zero init, zero commit): %v", equal)
	}
}

// TestIndependentCreatorsGetDifferentEpochZeroSecrets checks that two groups created from the same key
// package and the same group ID get different epoch 0 encryption secrets, because epoch_secret is random, and
// that the group keeps in its key schedule the init_secret that seeds epoch 1.
func TestIndependentCreatorsGetDifferentEpochZeroSecrets(t *testing.T) {
	alice := newDiagnosticMember(t, "Alice")
	gid, err := NewGroupIDRandom()
	if err != nil {
		t.Fatalf("NewGroupIDRandom: %v", err)
	}
	g1, err := NewGroup(gid, ciphersuite.MLS128DHKEMP256, alice.kp, alice.priv)
	if err != nil {
		t.Fatalf("NewGroup #1: %v", err)
	}
	g2, err := NewGroup(gid, ciphersuite.MLS128DHKEMP256, alice.kp, alice.priv)
	if err != nil {
		t.Fatalf("NewGroup #2: %v", err)
	}
	if bytes.Equal(g1.epochSecrets.EncryptionSecret.AsSlice(), g2.epochSecrets.EncryptionSecret.AsSlice()) {
		t.Error("two creators derive the same epoch 0 encryption_secret from the same inputs")
	}
	if g1.keySchedule == nil || g1.keySchedule.InitSecret() == nil {
		t.Fatal("group has no key schedule init_secret")
	}
	if !bytes.Equal(g1.keySchedule.InitSecret().AsSlice(), g1.epochSecrets.InitSecret.AsSlice()) {
		t.Error("key schedule init_secret differs from epochSecrets.InitSecret")
	}
}
