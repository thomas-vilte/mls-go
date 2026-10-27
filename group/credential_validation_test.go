package group

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
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/schedule"
	"github.com/thomas-vilte/mls-go/secrettree"
	"github.com/thomas-vilte/mls-go/treesync"
)

// credentialBindingMismatchText identifies the certificate/signature-key mismatch
// reported by ValidateWithSignatureKey (RFC 9420 §5.3).
const credentialBindingMismatchText = "does not match leaf signature_key"

// newCredentialBindingTestKey returns a fresh P-256 signing key.
func newCredentialBindingTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return key
}

// newCredentialBindingTestCertificate returns a self-signed DER certificate whose subjectPublicKeyInfo is key's public key.
func newCredentialBindingTestCertificate(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "member"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	return der
}

// newCredentialBindingTestUser creates a user with a certificate for certKey
// and a KeyPackage signed with sigKey. Different public keys produce a
// certificate/signature-key mismatch.
func newCredentialBindingTestUser(t *testing.T, certKey, sigKey *ecdsa.PrivateKey) *testUser {
	t.Helper()
	sigECDH, err := sigKey.ECDH()
	if err != nil {
		t.Fatalf("sigKey.ECDH: %v", err)
	}
	cwk := &credentials.CredentialWithKey{
		Credential:        credentials.NewX509Credential([][]byte{newCredentialBindingTestCertificate(t, certKey)}),
		SignatureKey:      &sigKey.PublicKey,
		PrivateKey:        sigKey,
		SignatureKeyBytes: sigECDH.PublicKey().Bytes(),
	}
	kp, priv, err := keypackages.Generate(cwk, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("keypackages.Generate(x509): %v", err)
	}
	sigPriv := ciphersuite.NewSignaturePrivateKey(priv.SignatureKey)
	return &testUser{kp: kp, priv: priv, sigPriv: sigPriv, sigPub: sigPriv.PublicKey()}
}

// newCredentialBindingTestGroups creates Alice's group and joins Bob through
// a Commit and Welcome. Both users have X.509 credentials, matching the type
// used by the Add proposals tested below.
func newCredentialBindingTestGroups(t *testing.T) (aliceGroup, bobGroup *Group, alice, bob *testUser) {
	t.Helper()
	aliceKey, bobKey := newCredentialBindingTestKey(t), newCredentialBindingTestKey(t)
	alice = newCredentialBindingTestUser(t, aliceKey, aliceKey)
	bob = newCredentialBindingTestUser(t, bobKey, bobKey)
	groupID, err := NewGroupIDRandom()
	if err != nil {
		t.Fatalf("NewGroupIDRandom: %v", err)
	}
	aliceGroup, err = NewGroup(groupID, ciphersuite.MLS128DHKEMP256, alice.kp, alice.priv)
	if err != nil {
		t.Fatalf("NewGroup(alice): %v", err)
	}
	if _, err = aliceGroup.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember(bob): %v", err)
	}
	sc, err := aliceGroup.Commit(alice.sigPriv, alice.sigPub, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	joinerSecret := sc.JoinerSecret()
	if err = aliceGroup.MergeCommit(sc); err != nil {
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
	bobGroup, err = JoinFromWelcomeWithContext(t.Context(), welcome, bob.kp, bob.priv, nil)
	if err != nil {
		t.Fatalf("JoinFromWelcomeWithContext: %v", err)
	}
	// Align bob's epoch secrets with alice's, as makeTwoMemberGroups does.
	bobGroup.epochSecrets = &schedule.EpochSecrets{
		InitSecret:       aliceGroup.epochSecrets.InitSecret.Clone(),
		SenderDataSecret: aliceGroup.epochSecrets.SenderDataSecret.Clone(),
		EncryptionSecret: aliceGroup.epochSecrets.EncryptionSecret.Clone(),
		ExporterSecret:   aliceGroup.epochSecrets.ExporterSecret.Clone(),
		ExternalSecret:   aliceGroup.epochSecrets.ExternalSecret.Clone(),
		ConfirmationKey:  aliceGroup.epochSecrets.ConfirmationKey.Clone(),
		MembershipKey:    aliceGroup.epochSecrets.MembershipKey.Clone(),
		ResumptionSecret: aliceGroup.epochSecrets.ResumptionSecret.Clone(),
	}
	bobGroup.keySchedule = schedule.NewKeySchedule(bobGroup.cipherSuite, bobGroup.epochSecrets.InitSecret)
	bobGroup.secretTree, err = secrettree.NewTree(bobGroup.epochSecrets.EncryptionSecret, bobGroup.ratchetTree.NumLeaves, bobGroup.cipherSuite)
	if err != nil {
		t.Fatalf("secrettree.NewTree(bob): %v", err)
	}
	return aliceGroup, bobGroup, alice, bob
}

// newCredentialBindingTestExternalCommit builds an external commit by joiner against g's current GroupInfo.
func newCredentialBindingTestExternalCommit(t *testing.T, g *Group, signer, joiner *testUser) *StagedCommit {
	t.Helper()
	groupInfo, err := g.GetGroupInfo(signer.sigPriv)
	if err != nil {
		t.Fatalf("GetGroupInfo: %v", err)
	}
	_, staged, err := ExternalCommit(
		groupInfo,
		g.cipherSuite,
		joiner.sigPriv,
		joiner.sigPub,
		nil,
		joiner.kp.LeafNode.Credential,
	)
	if err != nil {
		t.Fatalf("ExternalCommit: %v", err)
	}
	return staged
}

// commitWithInlineAddKeyPackage copies ac, replaces its first inline Add with kp,
// and re-signs the changed content with signer. It constructs a commit for testing
// receiver validation without passing through the committer's Add checks.
func commitWithInlineAddKeyPackage(t *testing.T, ac *framing.AuthenticatedContent, kp *keypackages.KeyPackage, signer *testUser) *framing.AuthenticatedContent {
	t.Helper()
	body, ok := ac.Content.Body.(framing.CommitBody)
	if !ok {
		t.Fatal("content is not a commit")
	}
	commit, err := UnmarshalCommit(body.Data)
	if err != nil {
		t.Fatalf("UnmarshalCommit: %v", err)
	}
	replaced := false
	for i := range commit.Proposals {
		if commit.Proposals[i].Proposal != nil && commit.Proposals[i].Proposal.Type == ProposalTypeAdd {
			commit.Proposals[i].Proposal = &Proposal{Type: ProposalTypeAdd, Add: &AddProposal{KeyPackage: kp}}
			replaced = true
			break
		}
	}
	if !replaced {
		t.Fatal("commit carries no inline Add proposal")
	}
	forged := *ac
	forged.Content.Body = framing.CommitBody{Data: commit.Marshal()}
	sig, err := ciphersuite.SignWithLabel(signer.sigPriv, "FramedContentTBS", forged.MarshalTBS())
	if err != nil {
		t.Fatalf("SignWithLabel(forged commit): %v", err)
	}
	forged.Auth.Signature = sig
	return &forged
}

// newCredentialBindingTestAddMessage returns a standalone Add proposal for kp, sent as a PublicMessage by signer.
func newCredentialBindingTestAddMessage(t *testing.T, g *Group, signer *testUser, kp *keypackages.KeyPackage) *framing.PublicMessage {
	t.Helper()
	content := framing.FramedContent{
		GroupID: g.groupID.AsSlice(),
		Epoch:   g.epoch.AsUint64(),
		Sender:  framing.Sender{Type: framing.SenderTypeMember, LeafIndex: uint32(g.ownLeafIndex)},
		Body:    framing.ProposalBody{Data: ProposalMarshal(&Proposal{Type: ProposalTypeAdd, Add: &AddProposal{KeyPackage: kp}})},
	}
	pm, err := framing.NewPublicMessage(
		content,
		signer.sigPriv,
		g.groupContext.Marshal(),
		g.epochSecrets.MembershipKey,
		g.cipherSuite,
	)
	if err != nil {
		t.Fatalf("NewPublicMessage: %v", err)
	}
	return pm
}

// TestCredentialSignatureKeyBinding checks certificate/signature-key binding when
// adding members, processing inline or standalone Add proposals, accepting external
// commits, and branching a group. Each path includes a valid control case.
func TestCredentialSignatureKeyBinding(t *testing.T) {
	// Emitter: AddMember refuses the mismatched KeyPackage and stores no proposal.
	t.Run("reject/add_member_mismatched_certificate", func(t *testing.T) {
		_, bobGroup, _, _ := newCredentialBindingTestGroups(t)
		carolCert, carolSig := newCredentialBindingTestKey(t), newCredentialBindingTestKey(t)
		carol := newCredentialBindingTestUser(t, carolCert, carolSig)
		stored := len(bobGroup.proposals.Proposals)

		_, err := bobGroup.AddMember(carol.kp)
		if err == nil || !strings.Contains(err.Error(), credentialBindingMismatchText) {
			t.Fatalf("AddMember(mismatched certificate): err = %v, want %q", err, credentialBindingMismatchText)
		}
		if got := len(bobGroup.proposals.Proposals); got != stored {
			t.Fatalf("stored proposals = %d after rejected AddMember, want %d", got, stored)
		}
	})

	// Control: a certificate that matches signature_key is accepted by AddMember.
	t.Run("control/add_member_matching_certificate_accepted", func(t *testing.T) {
		_, bobGroup, _, _ := newCredentialBindingTestGroups(t)
		carolKey := newCredentialBindingTestKey(t)
		carol := newCredentialBindingTestUser(t, carolKey, carolKey)
		if _, err := bobGroup.AddMember(carol.kp); err != nil {
			t.Fatalf("AddMember(matching certificate): %v", err)
		}
	})

	// Receiver, inline Add: a malicious committer carries a mismatched KeyPackage by value. alice
	// must reject the commit before applying it, and remain at epoch 1.
	t.Run("attack/inline_add_mismatched_certificate_rejected", func(t *testing.T) {
		aliceGroup, bobGroup, _, bob := newCredentialBindingTestGroups(t)
		carolCert, carolSig := newCredentialBindingTestKey(t), newCredentialBindingTestKey(t)
		goodCarol := newCredentialBindingTestUser(t, carolSig, carolSig)
		badCarol := newCredentialBindingTestUser(t, carolCert, carolSig)
		bobLeaf := bobGroup.ownLeafIndex

		if _, err := bobGroup.AddMember(goodCarol.kp); err != nil {
			t.Fatalf("AddMember(good carol): %v", err)
		}
		sc, err := bobGroup.Commit(bob.sigPriv, bob.sigPub, nil)
		if err != nil {
			t.Fatalf("Commit(bob): %v", err)
		}
		forged := commitWithInlineAddKeyPackage(t, sc.authenticatedContent, badCarol.kp, bob)

		err = aliceGroup.ProcessReceivedCommit(forged, treesync.LeafIndex(bobLeaf), aliceGroup.myLeafEncryptionKey)
		if err == nil || !strings.Contains(err.Error(), credentialBindingMismatchText) {
			t.Fatalf("ProcessReceivedCommit(inline Add with mismatched certificate): err = %v, want %q", err, credentialBindingMismatchText)
		}
		if got := aliceGroup.epoch.AsUint64(); got != 1 {
			t.Fatalf("alice epoch = %d after rejected commit, want 1", got)
		}
	})

	// Control: the same inline Add with a matching certificate is accepted and advances the epoch.
	t.Run("control/inline_add_matching_certificate_accepted", func(t *testing.T) {
		aliceGroup, bobGroup, _, bob := newCredentialBindingTestGroups(t)
		carolKey := newCredentialBindingTestKey(t)
		carol := newCredentialBindingTestUser(t, carolKey, carolKey)
		bobLeaf := bobGroup.ownLeafIndex

		if _, err := bobGroup.AddMember(carol.kp); err != nil {
			t.Fatalf("AddMember(matching carol): %v", err)
		}
		sc, err := bobGroup.Commit(bob.sigPriv, bob.sigPub, nil)
		if err != nil {
			t.Fatalf("Commit(bob): %v", err)
		}
		if err := bobGroup.MergeCommit(sc); err != nil {
			t.Fatalf("MergeCommit(bob): %v", err)
		}
		if err := aliceGroup.ProcessReceivedCommit(sc.authenticatedContent, treesync.LeafIndex(bobLeaf), aliceGroup.myLeafEncryptionKey); err != nil {
			t.Fatalf("ProcessReceivedCommit(inline Add with matching certificate): %v", err)
		}
		if got := aliceGroup.epoch.AsUint64(); got != 2 {
			t.Fatalf("alice epoch = %d after inline Add, want 2", got)
		}
	})

	// Receiver, external commit: the joiner's UpdatePath LeafNode carries a mismatched certificate.
	t.Run("attack/external_commit_mismatched_certificate_rejected", func(t *testing.T) {
		aliceGroup, _, alice, _ := newCredentialBindingTestGroups(t)
		malloryCert, malloryKey := newCredentialBindingTestKey(t), newCredentialBindingTestKey(t)
		mallory := newCredentialBindingTestUser(t, malloryCert, malloryKey)
		staged := newCredentialBindingTestExternalCommit(t, aliceGroup, alice, mallory)

		err := aliceGroup.ProcessReceivedCommit(staged.authenticatedContent, treesync.LeafIndex(0), aliceGroup.myLeafEncryptionKey)
		if err == nil || !strings.Contains(err.Error(), credentialBindingMismatchText) {
			t.Fatalf("ProcessReceivedCommit(external commit with mismatched certificate): err = %v, want %q", err, credentialBindingMismatchText)
		}
		if got := aliceGroup.epoch.AsUint64(); got != 1 {
			t.Fatalf("alice epoch = %d after rejected external commit, want 1", got)
		}
	})

	// Control: an external commit whose certificate matches its leaf key is accepted.
	t.Run("control/external_commit_matching_certificate_accepted", func(t *testing.T) {
		aliceGroup, _, alice, _ := newCredentialBindingTestGroups(t)
		key := newCredentialBindingTestKey(t)
		mallory := newCredentialBindingTestUser(t, key, key)
		staged := newCredentialBindingTestExternalCommit(t, aliceGroup, alice, mallory)

		if err := aliceGroup.ProcessReceivedCommit(staged.authenticatedContent, treesync.LeafIndex(0), aliceGroup.myLeafEncryptionKey); err != nil {
			t.Fatalf("ProcessReceivedCommit(external commit with matching certificate): %v", err)
		}
		if got := aliceGroup.epoch.AsUint64(); got != 2 {
			t.Fatalf("alice epoch = %d after external commit, want 2", got)
		}
	})

	// Standalone Add proposals already passed through ValidateLeafNode, so this subtest guards
	// the shared validator: a standalone proposal must refuse the same KeyPackage as the others.
	t.Run("reject/standalone_add_mismatched_certificate", func(t *testing.T) {
		aliceGroup, _, alice, _ := newCredentialBindingTestGroups(t)
		carolCert, carolSig := newCredentialBindingTestKey(t), newCredentialBindingTestKey(t)
		carol := newCredentialBindingTestUser(t, carolCert, carolSig)
		stored := len(aliceGroup.proposals.Proposals)

		err := aliceGroup.ProcessPublicMessage(newCredentialBindingTestAddMessage(t, aliceGroup, alice, carol.kp))
		if err == nil || !strings.Contains(err.Error(), credentialBindingMismatchText) {
			t.Fatalf("ProcessPublicMessage(standalone Add, mismatched certificate): err = %v, want %q", err, credentialBindingMismatchText)
		}
		if got := len(aliceGroup.proposals.Proposals); got != stored {
			t.Fatalf("stored proposals = %d after rejected standalone Add, want %d", got, stored)
		}
	})

	t.Run("control/standalone_add_matching_certificate_accepted", func(t *testing.T) {
		aliceGroup, _, alice, _ := newCredentialBindingTestGroups(t)
		carolKey := newCredentialBindingTestKey(t)
		carol := newCredentialBindingTestUser(t, carolKey, carolKey)
		stored := len(aliceGroup.proposals.Proposals)

		if err := aliceGroup.ProcessPublicMessage(newCredentialBindingTestAddMessage(t, aliceGroup, alice, carol.kp)); err != nil {
			t.Fatalf("ProcessPublicMessage(standalone Add, matching certificate): %v", err)
		}
		if got := len(aliceGroup.proposals.Proposals); got != stored+1 {
			t.Fatalf("stored proposals = %d after standalone Add, want %d", got, stored+1)
		}
	})

	// Branch stages every other member as an Add in the new group, so a mismatched KeyPackage is
	// refused before the new group holds it.
	t.Run("reject/branch_member_mismatched_certificate", func(t *testing.T) {
		aliceGroup, _, _, _ := newCredentialBindingTestGroups(t)
		ownKey := newCredentialBindingTestKey(t)
		own := newCredentialBindingTestUser(t, ownKey, ownKey)
		carolCert, carolSig := newCredentialBindingTestKey(t), newCredentialBindingTestKey(t)
		carol := newCredentialBindingTestUser(t, carolCert, carolSig)

		_, err := Branch(aliceGroup, own.kp, own.priv, []*keypackages.KeyPackage{carol.kp})
		if err == nil || !strings.Contains(err.Error(), credentialBindingMismatchText) {
			t.Fatalf("Branch(mismatched certificate): err = %v, want %q", err, credentialBindingMismatchText)
		}
	})

	t.Run("control/branch_matching_certificate_accepted", func(t *testing.T) {
		aliceGroup, _, _, _ := newCredentialBindingTestGroups(t)
		ownKey := newCredentialBindingTestKey(t)
		own := newCredentialBindingTestUser(t, ownKey, ownKey)
		carolKey := newCredentialBindingTestKey(t)
		carol := newCredentialBindingTestUser(t, carolKey, carolKey)

		if _, err := Branch(aliceGroup, own.kp, own.priv, []*keypackages.KeyPackage{carol.kp}); err != nil {
			t.Fatalf("Branch(matching certificate): %v", err)
		}
	})
}
