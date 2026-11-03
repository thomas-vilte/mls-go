package group

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/schedule"
)

// TestNewGroupFromReInit_Epoch0NotReproducibleFromPSK checks RFC 9420 §11: the
// creator's epoch_secret is "a fresh random value of size KDF.Nh". The epoch 0
// of a successor group must not be a pure function of the reinit psk_secret and
// the GroupContext. Rebuilding epoch 0 with init_secret = 0, commit_secret = 0
// and the stored psk_secret must not reproduce the group's epoch secrets.
func TestNewGroupFromReInit_Epoch0NotReproducibleFromPSK(t *testing.T) {
	reInit := makeReInitProposal([]byte("gid-epoch0-entropy"))
	kp, priv := makeSingleKP(t)
	resumption := ciphersuite.NewSecret(bytes.Repeat([]byte{0x5A}, 32))

	g, err := NewGroupFromReInit(reInit, resumption, []byte("old-group-id"), 3, kp, priv)
	if err != nil {
		t.Fatalf("NewGroupFromReInit: %v", err)
	}

	rawPsk := g.keySchedule.GetRawPskSecret()
	if rawPsk == nil {
		t.Fatal("reinit psk_secret is not stored in the key schedule")
	}

	cs := reInit.CipherSuite
	gcBytes := g.groupContext.Marshal()
	zeroSeed := schedule.NewKeySchedule(cs, ciphersuite.ZeroSecretCS(cs))
	zeroSeed.SetCommitSecret(ciphersuite.ZeroSecretCS(cs))
	if _, err := zeroSeed.ComputeJoinerSecret(gcBytes); err != nil {
		t.Fatalf("ComputeJoinerSecret: %v", err)
	}
	if err := zeroSeed.SetPskSecretDirect(rawPsk); err != nil {
		t.Fatalf("SetPskSecretDirect: %v", err)
	}
	if _, err := zeroSeed.ComputeEpochSecret(gcBytes); err != nil {
		t.Fatalf("ComputeEpochSecret: %v", err)
	}
	rebuilt, err := zeroSeed.DeriveEpochSecrets()
	if err != nil {
		t.Fatalf("DeriveEpochSecrets: %v", err)
	}

	if bytes.Equal(rebuilt.EncryptionSecret.AsSlice(), g.epochSecrets.EncryptionSecret.AsSlice()) {
		t.Fatal("epoch 0 equals the zero-seeded derivation from the reinit PSK alone; RFC 9420 §11 requires a fresh random epoch_secret")
	}
}

// TestNewGroupFromReInit_SamePSKDistinctEpochSecrets checks that two successor groups created from the same
// reinit PSK do not share epoch secrets. The psk_nonce is sampled fresh on every call.
func TestNewGroupFromReInit_SamePSKDistinctEpochSecrets(t *testing.T) {
	reInit := makeReInitProposal([]byte("gid-same-psk"))
	psk := ciphersuite.NewSecret(bytes.Repeat([]byte{0x77}, 32))
	kp1, priv1 := makeSingleKP(t)
	kp2, priv2 := makeSingleKP(t)

	g1, err := NewGroupFromReInit(reInit, psk, []byte("old-group-id"), 1, kp1, priv1)
	if err != nil {
		t.Fatalf("g1: %v", err)
	}
	g2, err := NewGroupFromReInit(reInit, psk, []byte("old-group-id"), 1, kp2, priv2)
	if err != nil {
		t.Fatalf("g2: %v", err)
	}

	if bytes.Equal(g1.epochSecrets.EncryptionSecret.AsSlice(), g2.epochSecrets.EncryptionSecret.AsSlice()) {
		t.Error("two reinit groups created from the same PSK produced identical encryption secrets")
	}
}

// TestNewGroupFromReInit_JoinFromWelcome checks that the successor group still admits a joiner through the
// same Commit + Welcome path that the interop ReInitWelcome handler uses.
func TestNewGroupFromReInit_JoinFromWelcome(t *testing.T) {
	reInit := makeReInitProposal([]byte("gid-reinit-join"))
	resumption, err := ciphersuite.NewSecretRandomCS(reInit.CipherSuite)
	if err != nil {
		t.Fatalf("NewSecretRandomCS: %v", err)
	}
	aliceKP, alicePriv := makeSingleKP(t)
	bobKP, bobPriv := makeSingleKP(t)

	alice, err := NewGroupFromReInit(reInit, resumption, []byte("old-group-id"), 1, aliceKP, alicePriv)
	if err != nil {
		t.Fatalf("NewGroupFromReInit: %v", err)
	}
	aliceSig := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)

	if _, err := alice.AddMember(bobKP); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	staged, err := alice.Commit(aliceSig, aliceSig.PublicKey(), nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	joinerSecret := staged.JoinerSecret()
	if err := alice.MergeCommit(staged); err != nil {
		t.Fatalf("MergeCommit: %v", err)
	}

	welcome, err := alice.CreateWelcomeWithOpts(
		[]*keypackages.KeyPackage{bobKP},
		aliceSig,
		WithJoinerSecret(joinerSecret),
		WithPSKIDs(staged.PskIDs()),
		WithPSKSecret(staged.RawPskSecret()),
		WithStagedCommit(staged),
	)
	if err != nil {
		t.Fatalf("CreateWelcomeWithOpts: %v", err)
	}

	bob, err := JoinFromWelcome(welcome, bobKP, bobPriv, nil)
	if err != nil {
		t.Fatalf("JoinFromWelcome: %v", err)
	}
	if bob.epoch.AsUint64() != 1 {
		t.Fatalf("joiner epoch = %d, want 1", bob.epoch.AsUint64())
	}
	if !bytes.Equal(bob.EpochAuthenticator(), alice.EpochAuthenticator()) {
		t.Fatal("joiner and creator derived different epoch authenticators")
	}
}
