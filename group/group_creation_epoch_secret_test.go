package group

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/schedule"
)

// epochZeroSuites covers the signature schemes and hash functions that NewGroup
// supports (SHA-256 and SHA-512 key schedules).
var epochZeroSuites = []struct {
	name string
	cs   ciphersuite.CipherSuite
}{
	{"CS1", ciphersuite.MLS128DHKEMX25519},
	{"CS2", ciphersuite.MLS128DHKEMP256},
	{"CS3", ciphersuite.MLS128DHKEMX25519ChaCha20},
	{"CS5", ciphersuite.MLS256DHKEMP521AES256GCM},
}

// newEpochZeroMember creates a KeyPackage, its private keys and the signature key for a
// member called name, for the cipher suite cs.
func newEpochZeroMember(t *testing.T, name string, cs ciphersuite.CipherSuite) (*keypackages.KeyPackage, *keypackages.KeyPackagePrivateKeys, *ciphersuite.SignaturePrivateKey) {
	t.Helper()
	cred, sigPriv, err := credentials.GenerateCredentialWithKeyForCS([]byte(name), cs)
	if err != nil {
		t.Fatalf("GenerateCredentialWithKeyForCS(%s, %v): %v", name, cs, err)
	}
	kp, priv, err := keypackages.Generate(cred, cs)
	if err != nil {
		t.Fatalf("keypackages.Generate(%s, %v): %v", name, cs, err)
	}
	return kp, priv, sigPriv
}

// rebuildEpochFromPublicValues runs the RFC 9420 §8 derivation with only public or
// attacker-known inputs: the init_secret of the previous epoch, a zero
// commit_secret, no PSK and the GroupContext of the epoch. Before epoch 0 used a random epoch_secret,
// NewGroup used exactly these inputs for epoch 0 (init_secret = 0^Nh).
func rebuildEpochFromPublicValues(t *testing.T, cs ciphersuite.CipherSuite, initSecret *ciphersuite.Secret, groupContext []byte) *schedule.EpochSecrets {
	t.Helper()
	ks := schedule.NewKeySchedule(cs, initSecret)
	ks.SetCommitSecret(ciphersuite.ZeroSecretCS(cs))
	if _, err := ks.ComputeJoinerSecret(groupContext); err != nil {
		t.Fatalf("ComputeJoinerSecret: %v", err)
	}
	if _, err := ks.ComputePskSecret(nil); err != nil {
		t.Fatalf("ComputePskSecret: %v", err)
	}
	if _, err := ks.ComputeEpochSecret(groupContext); err != nil {
		t.Fatalf("ComputeEpochSecret: %v", err)
	}
	es, err := ks.DeriveEpochSecrets()
	if err != nil {
		t.Fatalf("DeriveEpochSecrets: %v", err)
	}
	return es
}

// compareEpochSecrets splits the nine epoch secrets of a and b into the names of
// the ones that are equal and the ones that differ.
func compareEpochSecrets(a, b *schedule.EpochSecrets) (equal, differ []string) {
	pairs := []struct {
		name string
		x, y *ciphersuite.Secret
	}{
		{"sender_data_secret", a.SenderDataSecret, b.SenderDataSecret},
		{"encryption_secret", a.EncryptionSecret, b.EncryptionSecret},
		{"exporter_secret", a.ExporterSecret, b.ExporterSecret},
		{"authentication_secret", a.AuthenticationSecret, b.AuthenticationSecret},
		{"confirmation_key", a.ConfirmationKey, b.ConfirmationKey},
		{"membership_key", a.MembershipKey, b.MembershipKey},
		{"external_secret", a.ExternalSecret, b.ExternalSecret},
		{"resumption_secret", a.ResumptionSecret, b.ResumptionSecret},
		{"init_secret", a.InitSecret, b.InitSecret},
	}
	for _, p := range pairs {
		if p.x.Equal(p.y) {
			equal = append(equal, p.name)
		} else {
			differ = append(differ, p.name)
		}
	}
	return equal, differ
}

// TestNewGroupEpochZeroSecretsAreNotPublic checks that the epoch 0 secrets of a new group cannot be rebuilt
// from public data. NewGroup used to derive epoch 0 from a zero init_secret and commit_secret and no PSK, so
// anyone who knows the GroupContext could compute the secrets. RFC 9420 §11 requires the creator's
// epoch_secret to be "a fresh random value of size KDF.Nh".
func TestNewGroupEpochZeroSecretsAreNotPublic(t *testing.T) {
	for _, tc := range epochZeroSuites {
		t.Run(tc.name, func(t *testing.T) {
			kp, priv, _ := newEpochZeroMember(t, "alice", tc.cs)
			groupID, err := NewGroupIDRandom()
			if err != nil {
				t.Fatalf("NewGroupIDRandom: %v", err)
			}

			g1, err := NewGroup(groupID, tc.cs, kp, priv)
			if err != nil {
				t.Fatalf("NewGroup #1: %v", err)
			}
			g2, err := NewGroup(groupID, tc.cs, kp, priv)
			if err != nil {
				t.Fatalf("NewGroup #2: %v", err)
			}

			// Same public inputs: the two epoch 0 secret sets must still differ.
			if equal, _ := compareEpochSecrets(g1.EpochSecrets(), g2.EpochSecrets()); len(equal) > 0 {
				t.Fatalf("two groups created from the same inputs share epoch 0 secrets: %v", equal)
			}

			// No epoch 0 secret may match the rebuild from zeros over the public GroupContext.
			fromZeros := rebuildEpochFromPublicValues(t, tc.cs, ciphersuite.ZeroSecretCS(tc.cs), g1.groupContext.Marshal())
			if equal, _ := compareEpochSecrets(g1.EpochSecrets(), fromZeros); len(equal) > 0 {
				t.Fatalf("epoch 0 secrets reconstructible from zeros: %v", equal)
			}
		})
	}
}

// TestEpochOneSecretsAreNotPublic checks the epoch after the first Add. That Commit has no UpdatePath because
// the group has one member, so its commit_secret is zero by RFC 9420 §12.4.2. Its epoch 1 secrets still depend
// on the epoch 0 init_secret, so they must not be rebuildable from public data either.
func TestEpochOneSecretsAreNotPublic(t *testing.T) {
	for _, tc := range epochZeroSuites {
		t.Run(tc.name, func(t *testing.T) {
			aliceKP, alicePriv, aliceSig := newEpochZeroMember(t, "alice", tc.cs)
			bobKP, _, _ := newEpochZeroMember(t, "bob", tc.cs)
			groupID, err := NewGroupIDRandom()
			if err != nil {
				t.Fatalf("NewGroupIDRandom: %v", err)
			}

			g, err := NewGroup(groupID, tc.cs, aliceKP, alicePriv)
			if err != nil {
				t.Fatalf("NewGroup: %v", err)
			}
			fromZeros0 := rebuildEpochFromPublicValues(t, tc.cs, ciphersuite.ZeroSecretCS(tc.cs), g.groupContext.Marshal())

			if _, err := g.AddMember(bobKP); err != nil {
				t.Fatalf("AddMember: %v", err)
			}
			sc, err := g.Commit(aliceSig, aliceSig.PublicKey(), nil)
			if err != nil {
				t.Fatalf("Commit: %v", err)
			}
			if err := g.MergeCommit(sc); err != nil {
				t.Fatalf("MergeCommit: %v", err)
			}
			if g.epoch.AsUint64() != 1 {
				t.Fatalf("epoch = %d, want 1", g.epoch.AsUint64())
			}

			// An observer knows the epoch 0 init_secret (rebuilt from zeros) and the epoch 1 GroupContext.
			fromZeros1 := rebuildEpochFromPublicValues(t, tc.cs, fromZeros0.InitSecret, g.groupContext.Marshal())
			if equal, _ := compareEpochSecrets(g.EpochSecrets(), fromZeros1); len(equal) > 0 {
				t.Fatalf("epoch 1 secrets reconstructible from public data: %v", equal)
			}
		})
	}
}

// TestJoinFlowAfterRandomEpochZero checks that Add, Commit, Welcome and Join still work with a random epoch 0
// secret, and that the joiner derives the same epoch 1 secrets as the committer without any manual alignment.
func TestJoinFlowAfterRandomEpochZero(t *testing.T) {
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")
	groupID, err := NewGroupIDRandom()
	if err != nil {
		t.Fatalf("NewGroupIDRandom: %v", err)
	}

	aliceGroup, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, alice.kp, alice.priv)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	if _, err := aliceGroup.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	sc, err := aliceGroup.Commit(alice.sigPriv, alice.sigPub, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	joinerSecret := sc.JoinerSecret()
	if err := aliceGroup.MergeCommit(sc); err != nil {
		t.Fatalf("MergeCommit: %v", err)
	}
	welcome, err := aliceGroup.CreateWelcomeWithOpts(
		[]*keypackages.KeyPackage{bob.kp},
		alice.sigPriv,
		WithJoinerSecret(joinerSecret),
		WithStagedCommit(sc),
	)
	if err != nil {
		t.Fatalf("CreateWelcome: %v", err)
	}
	bobGroup, err := JoinFromWelcome(welcome, bob.kp, bob.priv, nil)
	if err != nil {
		t.Fatalf("JoinFromWelcome: %v", err)
	}

	if _, differ := compareEpochSecrets(aliceGroup.EpochSecrets(), bobGroup.EpochSecrets()); len(differ) > 0 {
		t.Fatalf("joiner epoch 1 secrets differ from the committer's: %v", differ)
	}

	msg := []byte("hello bob after epoch 0")
	pm, err := aliceGroup.SendMessage(msg, alice.sigPriv)
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	got, err := bobGroup.ReceiveMessage(pm, aliceGroup.ownLeafIndex)
	if err != nil {
		t.Fatalf("ReceiveMessage: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, msg)
	}
}

// TestExternalJoinAtEpochZero checks that an external joiner can still commit to a GroupInfo for epoch 0.
// RFC 9420 §11 lets the creator publish it right after NewGroup. Its external_pub comes from the epoch 0
// external_secret, which is now random, and both sides must end in the same epoch.
func TestExternalJoinAtEpochZero(t *testing.T) {
	alice := newTestUser(t, "alice")
	charlie := newTestUser(t, "charlie")
	groupID, err := NewGroupIDRandom()
	if err != nil {
		t.Fatalf("NewGroupIDRandom: %v", err)
	}

	aliceGroup, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, alice.kp, alice.priv)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	groupInfo, err := aliceGroup.GetGroupInfo(alice.sigPriv)
	if err != nil {
		t.Fatalf("GetGroupInfo(epoch 0): %v", err)
	}
	charlieGroup, sc, err := ExternalCommit(
		groupInfo,
		aliceGroup.cipherSuite,
		charlie.sigPriv,
		charlie.sigPub,
		nil,
		charlie.kp.LeafNode.Credential,
	)
	if err != nil {
		t.Fatalf("ExternalCommit(epoch 0 GroupInfo): %v", err)
	}
	if err := aliceGroup.MergeCommit(sc); err != nil {
		t.Fatalf("MergeCommit(external): %v", err)
	}
	if aliceGroup.epoch.AsUint64() != 1 || charlieGroup.epoch.AsUint64() != 1 {
		t.Fatalf("epochs alice=%d charlie=%d, want 1 and 1", aliceGroup.epoch.AsUint64(), charlieGroup.epoch.AsUint64())
	}

	msg := []byte("hello charlie")
	pm, err := aliceGroup.SendMessage(msg, alice.sigPriv)
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	got, err := charlieGroup.ReceiveMessage(pm, aliceGroup.ownLeafIndex)
	if err != nil {
		t.Fatalf("ReceiveMessage(charlie): %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, msg)
	}
}
