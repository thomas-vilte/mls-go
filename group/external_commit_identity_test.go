package group

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/treesync"
)

// newExternalCommitTestCertificate returns a DER certificate for subject, for the public key of key, signed with
// issuerKey under the issuer name issuerName. Only the parsed identity matters to these tests.
func newExternalCommitTestCertificate(t *testing.T, subject string, key *ecdsa.PrivateKey, issuerName string, issuerKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	issuer := &x509.Certificate{Subject: pkix.Name{CommonName: issuerName}}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate(%s): %v", subject, err)
	}
	return der
}

// TestX509CredentialIdentityUsesIssuerAndSubject checks which X.509 credentials identify the same
// participant. The issuer and the subject identify a member, so a renewed certificate from the same
// issuer keeps the identity and a certificate from another issuer does not.
func TestX509CredentialIdentityUsesIssuerAndSubject(t *testing.T) {
	caKey := newCredentialBindingTestKey(t)
	otherCAKey := newCredentialBindingTestKey(t)
	cred := func(der []byte) *credentials.Credential { return credentials.NewX509Credential([][]byte{der}) }

	original := cred(newExternalCommitTestCertificate(t, "bob", newCredentialBindingTestKey(t), "ca-one", caKey))
	renewed := cred(newExternalCommitTestCertificate(t, "bob", newCredentialBindingTestKey(t), "ca-one", caKey))
	otherIssuer := cred(newExternalCommitTestCertificate(t, "bob", newCredentialBindingTestKey(t), "ca-two", otherCAKey))
	selfSigned := cred(newExternalCommitTestCertificate(t, "bob", newCredentialBindingTestKey(t), "bob", newCredentialBindingTestKey(t)))
	otherSubject := cred(newExternalCommitTestCertificate(t, "carol", newCredentialBindingTestKey(t), "ca-one", caKey))

	cases := []struct {
		name string
		b    *credentials.Credential
		want bool
	}{
		{"renewed certificate, same issuer and subject", renewed, true},
		{"same subject from another issuer", otherIssuer, false},
		{"self-signed certificate with the same subject", selfSigned, false},
		{"same issuer, other subject", otherSubject, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameCredentialIdentity(original, tc.b); got != tc.want {
				t.Fatalf("sameCredentialIdentity = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestExternalCommitBasicIdentityResync is the control for the BasicCredential rule. A member that
// resyncs as itself with a new signature key is the same participant by identity, so the external
// commit that removes its old leaf must be accepted (RFC 9420 §12.4.3.2; interop external_join).
func TestExternalCommitBasicIdentityResync(t *testing.T) {
	aliceGroup, bobGroup, alice, _ := makeTwoMemberGroups(t)
	resync := newTestUser(t, "bob")
	bobLeaf := bobGroup.ownLeafIndex

	staged := newExternalCommitTestCommit(t, aliceGroup, alice, resync, &bobLeaf)
	if err := aliceGroup.ProcessReceivedCommit(staged.authenticatedContent, treesync.LeafIndex(0), aliceGroup.myLeafEncryptionKey); err != nil {
		t.Fatalf("resync of bob as itself with a new key: %v", err)
	}
}

// TestExternalCommitRejectsDifferentBasicIdentityRemoval checks that an external joiner cannot remove a leaf with a different Basic identity.
func TestExternalCommitRejectsDifferentBasicIdentityRemoval(t *testing.T) {
	aliceGroup, bobGroup, alice, bob := makeTwoMemberGroups(t)
	mallory := newTestUser(t, "mallory")
	bobLeaf := bobGroup.ownLeafIndex
	before := captureExternalCommitTestState(aliceGroup)

	staged := newExternalCommitTestCommit(t, aliceGroup, alice, mallory, &bobLeaf)
	err := aliceGroup.ProcessReceivedCommit(staged.authenticatedContent, treesync.LeafIndex(0), aliceGroup.myLeafEncryptionKey)
	if !errors.Is(err, ErrInvalidProposal) {
		t.Fatalf("external commit by mallory removing bob: err = %v, want ErrInvalidProposal", err)
	}
	assertExternalCommitStateUnchanged(t, aliceGroup, before)
	if !groupHasBasicIdentity(aliceGroup, bob) {
		t.Fatal("bob's leaf was removed by an external commit under another identity")
	}
}

// TestExternalCommitRenewedCertificateResync is the control for the X.509 rule. bob resyncs with
// a renewed certificate for the same subject and a new key, which the identity rule keeps valid.
func TestExternalCommitRenewedCertificateResync(t *testing.T) {
	aliceGroup, bobGroup, alice, _ := newCredentialBindingTestGroups(t)
	renewedKey := newCredentialBindingTestKey(t)
	renewed := newCredentialBindingTestUser(t, renewedKey, renewedKey)
	bobLeaf := bobGroup.ownLeafIndex

	staged := newExternalCommitTestCommit(t, aliceGroup, alice, renewed, &bobLeaf)
	if err := aliceGroup.ProcessReceivedCommit(staged.authenticatedContent, treesync.LeafIndex(0), aliceGroup.myLeafEncryptionKey); err != nil {
		t.Fatalf("resync of bob with a renewed X.509 certificate: %v", err)
	}
	if got := aliceGroup.epoch.AsUint64(); got != 2 {
		t.Fatalf("alice epoch = %d after the resync, want 2", got)
	}
}
