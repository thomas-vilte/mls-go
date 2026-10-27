package mls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// credentialBindingMismatchText is the rejection that ValidateWithSignatureKey returns when the end-entity
// certificate key differs from signature_key (RFC 9420 §5.3).
const credentialBindingMismatchText = "does not match leaf signature_key"

// newCredentialBindingTestKey returns a fresh P-256 key, the signature scheme of MLS128DHKEMP256.
func newCredentialBindingTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return key
}

// newCredentialBindingTestKeyPackage returns an encoded KeyPackage with a certificate
// for certKey and signatures made with sigKey. Passing the same key makes them match.
func newCredentialBindingTestKeyPackage(t *testing.T, certKey, sigKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "member"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &certKey.PublicKey, certKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	sigECDH, err := sigKey.ECDH()
	if err != nil {
		t.Fatalf("sigKey.ECDH: %v", err)
	}
	cwk := &credentials.CredentialWithKey{
		Credential:        credentials.NewX509Credential([][]byte{der}),
		SignatureKey:      &sigKey.PublicKey,
		PrivateKey:        sigKey,
		SignatureKeyBytes: sigECDH.PublicKey().Bytes(),
	}
	kp, _, err := keypackages.Generate(cwk, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("keypackages.Generate(x509): %v", err)
	}
	return kp.Marshal()
}

// TestClientCredentialSignatureKeyBinding checks that Add operations reject a
// KeyPackage whose X.509 certificate key differs from its signature_key.
func TestClientCredentialSignatureKeyBinding(t *testing.T) {
	ctx := t.Context()
	cs := ciphersuite.MLS128DHKEMP256
	aliceCert, alicePriv := generateTestCertificate(t)
	alice, err := NewClient([]byte(""), cs, WithX509Credential(aliceCert, alicePriv))
	if err != nil {
		t.Fatalf("creating alice x509 client: %v", err)
	}
	t.Cleanup(func() {
		if err := alice.Close(); err != nil {
			t.Errorf("closing alice client: %v", err)
		}
	})
	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("creating group: %v", err)
	}

	t.Run("reject/mismatched_certificate", func(t *testing.T) {
		certKey, sigKey := newCredentialBindingTestKey(t), newCredentialBindingTestKey(t)
		_, _, err := alice.InviteMember(ctx, groupID, newCredentialBindingTestKeyPackage(t, certKey, sigKey))
		if err == nil || !strings.Contains(err.Error(), credentialBindingMismatchText) {
			t.Fatalf("InviteMember(mismatched certificate): err = %v, want %q", err, credentialBindingMismatchText)
		}
	})

	t.Run("control/matching_certificate_accepted", func(t *testing.T) {
		key := newCredentialBindingTestKey(t)
		commit, welcome, err := alice.InviteMember(ctx, groupID, newCredentialBindingTestKeyPackage(t, key, key))
		if err != nil {
			t.Fatalf("InviteMember(matching certificate): %v", err)
		}
		if len(commit) == 0 || len(welcome) == 0 {
			t.Fatal("InviteMember(matching certificate) returned no commit or welcome")
		}
	})

	// ProposeAddMember stores a standalone Add, so it refuses the mismatched KeyPackage as well.
	t.Run("reject/propose_add_mismatched_certificate", func(t *testing.T) {
		certKey, sigKey := newCredentialBindingTestKey(t), newCredentialBindingTestKey(t)
		_, err := alice.ProposeAddMember(ctx, groupID, newCredentialBindingTestKeyPackage(t, certKey, sigKey))
		if err == nil || !strings.Contains(err.Error(), credentialBindingMismatchText) {
			t.Fatalf("ProposeAddMember(mismatched certificate): err = %v, want %q", err, credentialBindingMismatchText)
		}
	})

	t.Run("control/propose_add_matching_certificate_accepted", func(t *testing.T) {
		key := newCredentialBindingTestKey(t)
		msg, err := alice.ProposeAddMember(ctx, groupID, newCredentialBindingTestKeyPackage(t, key, key))
		if err != nil {
			t.Fatalf("ProposeAddMember(matching certificate): %v", err)
		}
		if len(msg) == 0 {
			t.Fatal("ProposeAddMember(matching certificate) returned no message")
		}
	})
}
