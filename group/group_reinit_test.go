package group

import (
	"bytes"
	"testing"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/credentials"
	keypackages "github.com/openmls/go/keypackages"
)

func makeReInitProposal(groupID []byte) *ReInitProposal {
	return &ReInitProposal{
		GroupID:     groupID,
		Version:     keypackages.MLS10,
		CipherSuite: keypackages.MLS128DHKEMP256,
		Extensions:  nil,
	}
}

// makeSingleKP genera un KeyPackage + privKeys para usar en tests de ReInit.
func makeSingleKP(t *testing.T) (*keypackages.KeyPackage, *keypackages.KeyPackagePrivateKeys) {
	t.Helper()
	cred, _, err := credentials.GenerateCredentialWithKey([]byte("reinit-member"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey: %v", err)
	}
	kp, priv, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return kp, priv
}

func TestNewGroupFromReInit_Basic(t *testing.T) {
	groupID := []byte("reinit-group-id-1234")
	reInit := makeReInitProposal(groupID)

	resumptionSecret := ciphersuite.NewSecret(bytes.Repeat([]byte{0xAB}, 32))

	cred, _, err := credentials.GenerateCredentialWithKey([]byte("alice"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey: %v", err)
	}
	kp, priv, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	g, err := NewGroupFromReInit(reInit, resumptionSecret, kp, priv)
	if err != nil {
		t.Fatalf("NewGroupFromReInit: %v", err)
	}
	if g == nil {
		t.Fatal("NewGroupFromReInit returned nil")
	}
}

func TestNewGroupFromReInit_GroupIDPreserved(t *testing.T) {
	groupID := []byte("specific-group-id")
	kp, priv := makeSingleKP(t)
	g, err := NewGroupFromReInit(
		makeReInitProposal(groupID),
		ciphersuite.NewSecret(bytes.Repeat([]byte{0x11}, 32)),
		kp, priv,
	)
	if err != nil {
		t.Fatalf("NewGroupFromReInit: %v", err)
	}
	if !bytes.Equal(g.GroupContext.GroupID.AsSlice(), groupID) {
		t.Errorf("GroupID = %x, want %x", g.GroupContext.GroupID.AsSlice(), groupID)
	}
}

func TestNewGroupFromReInit_EpochZero(t *testing.T) {
	kp, priv := makeSingleKP(t)
	g, err := NewGroupFromReInit(
		makeReInitProposal([]byte("gid")),
		ciphersuite.NewSecret(bytes.Repeat([]byte{0x22}, 32)),
		kp, priv,
	)
	if err != nil {
		t.Fatalf("NewGroupFromReInit: %v", err)
	}
	if g.GroupContext.Epoch.AsUint64() != 0 {
		t.Errorf("Epoch = %d, want 0", g.GroupContext.Epoch.AsUint64())
	}
}

func TestNewGroupFromReInit_OperationalState(t *testing.T) {
	kp, priv := makeSingleKP(t)
	g, err := NewGroupFromReInit(
		makeReInitProposal([]byte("gid")),
		ciphersuite.NewSecret(bytes.Repeat([]byte{0x33}, 32)),
		kp, priv,
	)
	if err != nil {
		t.Fatalf("NewGroupFromReInit: %v", err)
	}
	if g.state != StateOperational {
		t.Errorf("state = %v, want StateOperational", g.state)
	}
}

func TestNewGroupFromReInit_SecretsNonNil(t *testing.T) {
	kp, priv := makeSingleKP(t)
	g, err := NewGroupFromReInit(
		makeReInitProposal([]byte("gid")),
		ciphersuite.NewSecret(bytes.Repeat([]byte{0x44}, 32)),
		kp, priv,
	)
	if err != nil {
		t.Fatalf("NewGroupFromReInit: %v", err)
	}
	if g.EpochSecrets == nil {
		t.Fatal("EpochSecrets is nil")
	}
	if g.EpochSecrets.EncryptionSecret == nil {
		t.Error("EncryptionSecret is nil")
	}
	if g.EpochSecrets.ExporterSecret == nil {
		t.Error("ExporterSecret is nil")
	}
	if g.SecretTree == nil {
		t.Error("SecretTree is nil")
	}
}

func TestNewGroupFromReInit_DifferentSecretsProduceDifferentEpochs(t *testing.T) {
	reInit := makeReInitProposal([]byte("gid"))
	kp, priv := makeSingleKP(t)

	g1, err := NewGroupFromReInit(reInit, ciphersuite.NewSecret(bytes.Repeat([]byte{0x01}, 32)), kp, priv)
	if err != nil {
		t.Fatalf("g1: %v", err)
	}

	kp2, priv2 := makeSingleKP(t)
	g2, err := NewGroupFromReInit(reInit, ciphersuite.NewSecret(bytes.Repeat([]byte{0x02}, 32)), kp2, priv2)
	if err != nil {
		t.Fatalf("g2: %v", err)
	}

	if bytes.Equal(
		g1.EpochSecrets.EncryptionSecret.AsSlice(),
		g2.EpochSecrets.EncryptionSecret.AsSlice(),
	) {
		t.Error("different resumption secrets should produce different encryption secrets")
	}
}

func TestNewGroupFromReInit_NilReInit(t *testing.T) {
	kp, priv := makeSingleKP(t)
	_, err := NewGroupFromReInit(nil, ciphersuite.NewSecret([]byte{0x01}), kp, priv)
	if err == nil {
		t.Error("expected error for nil ReInitProposal")
	}
}

func TestNewGroupFromReInit_NilResumptionSecret(t *testing.T) {
	kp, priv := makeSingleKP(t)
	_, err := NewGroupFromReInit(makeReInitProposal([]byte("gid")), nil, kp, priv)
	if err == nil {
		t.Error("expected error for nil resumption secret")
	}
}

func TestNewGroupFromReInit_NilKeyPackage(t *testing.T) {
	secret := ciphersuite.NewSecret(bytes.Repeat([]byte{0x01}, 32))
	_, err := NewGroupFromReInit(makeReInitProposal([]byte("gid")), secret, nil, nil)
	if err == nil {
		t.Error("expected error for nil KeyPackage")
	}
}
