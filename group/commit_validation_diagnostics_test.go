//go:build diagnostics

package group

import (
	"bytes"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/treesync"
)

// Additional diagnostics for commit and proposal validation.

// newCommitDiagnosticUpdateMessage has bob create an Update and sign it as a PublicMessage. It returns the
// proposal and the parsed message.
func newCommitDiagnosticUpdateMessage(t *testing.T, m *updateProposalTestMembers) (*Proposal, *framing.PublicMessage) {
	t.Helper()
	update, err := m.bobGroup.SelfUpdate(m.bob.sigPriv)
	if err != nil {
		t.Fatalf("SelfUpdate(bob): %v", err)
	}
	raw, err := m.bobGroup.SignProposalAsPublicMessage(update, m.bob.sigPriv)
	if err != nil {
		t.Fatalf("SignProposalAsPublicMessage(bob): %v", err)
	}
	mlsMsg, err := framing.UnmarshalMLSMessage(raw)
	if err != nil {
		t.Fatalf("UnmarshalMLSMessage: %v", err)
	}
	pm, ok := mlsMsg.AsPublic()
	if !ok {
		t.Fatal("bob update is not a PublicMessage")
	}
	return update, pm
}

// TestCommitRejectsEchoedOwnUpdate checks that receiving an echo of an own Update does not make it valid for the committer.
func TestCommitRejectsEchoedOwnUpdate(t *testing.T) {
	m := newUpdateProposalTestMembers(t)
	_, pm := newCommitDiagnosticUpdateMessage(t, m)
	// The DS fans the proposal out to every member, the sender included.
	for _, g := range []*Group{m.aliceGroup, m.charlieGroup, m.bobGroup} {
		if err := g.ProcessPublicMessage(pm); err != nil {
			t.Fatalf("ProcessPublicMessage(bob update): %v", err)
		}
	}
	_, err := m.bobGroup.Commit(m.bob.sigPriv, m.bob.sigPub, nil)
	if !errors.Is(err, ErrInvalidProposal) {
		t.Errorf("Commit by bob after echo of his own Update: err = %v, want ErrInvalidProposal", err)
	}
	t.Logf("reason for the refusal: %v", err)
}

// TestReceivedCommitRejectsOwnUpdateReference checks that a receiver rejects a commit containing the committer's own Update by reference.
func TestReceivedCommitRejectsOwnUpdateReference(t *testing.T) {
	m := newUpdateProposalTestMembers(t)
	update, pm := newCommitDiagnosticUpdateMessage(t, m)
	for _, g := range []*Group{m.aliceGroup, m.charlieGroup} {
		if err := g.ProcessPublicMessage(pm); err != nil {
			t.Fatalf("ProcessPublicMessage(bob update): %v", err)
		}
	}
	ac := &framing.AuthenticatedContent{WireFormat: framing.WireFormatPublicMessage, Content: pm.Content, Auth: pm.Auth}
	ref := ComputeProposalRef(ac.Marshal(), m.bobGroup.cipherSuite)
	m.bobGroup.RegisterProposalRef(update, ref)

	// bob's stored Update would be part of any commit he builds, so the honest base commit is built
	// after his proposal store is cleared.
	m.bobGroup.ClearProposals()
	base, err := m.bobGroup.Commit(m.bob.sigPriv, m.bob.sigPub, nil)
	if err != nil {
		t.Fatalf("Commit(bob, empty base): %v", err)
	}
	body, ok := base.authenticatedContent.Content.Body.(framing.CommitBody)
	if !ok {
		t.Fatal("base commit has no commit body")
	}
	commit, err := UnmarshalCommit(body.Data)
	if err != nil {
		t.Fatalf("UnmarshalCommit(base): %v", err)
	}
	commit.Proposals = append(commit.Proposals, ProposalOrRef{ProposalRef: ref})
	forged := *base.authenticatedContent
	forged.Content.Body = framing.CommitBody{Data: commit.Marshal()}
	sig, err := ciphersuite.SignWithLabel(m.bob.sigPriv, "FramedContentTBS", forged.MarshalTBS())
	if err != nil {
		t.Fatalf("re-signing the forged commit: %v", err)
	}
	forged.Auth.Signature = sig

	err = m.aliceGroup.ProcessReceivedCommit(&forged, treesync.LeafIndex(m.bobGroup.ownLeafIndex), m.aliceGroup.myLeafEncryptionKey)
	if !errors.Is(err, ErrInvalidProposal) {
		t.Errorf("alice.ProcessReceivedCommit(bob's commit with his own by-reference Update): err = %v, want ErrInvalidProposal; alice epoch now %d",
			err, m.aliceGroup.epoch.AsUint64())
	}
}

// TestCommitRejectsRegisteredOwnUpdateReference checks the rejection of a registered reference to the committer's own Update.
func TestCommitRejectsRegisteredOwnUpdateReference(t *testing.T) {
	m := newUpdateProposalTestMembers(t)
	update, pm := newCommitDiagnosticUpdateMessage(t, m)
	for _, g := range []*Group{m.aliceGroup, m.charlieGroup} {
		if err := g.ProcessPublicMessage(pm); err != nil {
			t.Fatalf("ProcessPublicMessage(bob update): %v", err)
		}
	}
	ac := &framing.AuthenticatedContent{WireFormat: framing.WireFormatPublicMessage, Content: pm.Content, Auth: pm.Auth}
	m.bobGroup.RegisterProposalRef(update, ComputeProposalRef(ac.Marshal(), m.bobGroup.cipherSuite))
	_, err := m.bobGroup.Commit(m.bob.sigPriv, m.bob.sigPub, nil)
	if !errors.Is(err, ErrInvalidProposal) {
		t.Errorf("Commit by bob after RegisterProposalRef(own Update): err = %v, want ErrInvalidProposal (RFC 9420 §12.2)", err)
	}
}

// TestReceiveApplicationMessagePreservesGenerationAfterInvalidSignature checks that an invalid sender signature does not consume an honest sender's generation.
func TestReceiveApplicationMessagePreservesGenerationAfterInvalidSignature(t *testing.T) {
	t.Run("control_honest_only", func(t *testing.T) {
		m := newUpdateProposalTestMembers(t)
		honest, err := m.bobGroup.SendApplicationMessage([]byte("honest"), []byte{}, m.bob.sigPriv)
		if err != nil {
			t.Fatalf("SendApplicationMessage(bob): %v", err)
		}
		if _, _, _, err := m.aliceGroup.ReceiveApplicationMessage(honest); err != nil {
			t.Fatalf("ReceiveApplicationMessage(honest): %v", err)
		}
	})
	t.Run("forged_then_honest", func(t *testing.T) {
		m := newUpdateProposalTestMembers(t)
		bobLeaf := m.bobGroup.ownLeafIndex
		forged, err := framing.Encrypt(framing.EncryptParams{
			Content: framing.FramedContent{
				GroupID:           m.aliceGroup.groupID.AsSlice(),
				Epoch:             m.aliceGroup.epoch.AsUint64(),
				Sender:            framing.Sender{Type: framing.SenderTypeMember, LeafIndex: uint32(bobLeaf)},
				AuthenticatedData: []byte{},
				Body:              framing.ApplicationData{Data: []byte("forged as bob")},
			},
			SenderLeafIndex:  uint32(bobLeaf),
			CipherSuite:      m.aliceGroup.cipherSuite,
			SenderDataSecret: m.charlieGroup.epochSecrets.SenderDataSecret,
			SecretTree:       m.charlieGroup.secretTree,
			SigKey:           m.charlie.sigPriv,
			GroupContext:     m.charlieGroup.groupContext.Marshal(),
		})
		if err != nil {
			t.Fatalf("forging message as bob: %v", err)
		}
		if _, _, _, err := m.aliceGroup.ReceiveApplicationMessage(forged); err == nil {
			t.Fatal("forged message as bob accepted, want a signature rejection")
		}
		honest, err := m.bobGroup.SendApplicationMessage([]byte("honest"), []byte{}, m.bob.sigPriv)
		if err != nil {
			t.Fatalf("SendApplicationMessage(bob): %v", err)
		}
		if _, _, _, err := m.aliceGroup.ReceiveApplicationMessage(honest); err != nil {
			t.Errorf("bob's honest generation 0 refused after a forged message with the same generation: %v", err)
		}
	})
}

// TestExternalCommitBasicIdentityDoesNotBindSigningKey documents that Basic identity equality permits resynchronization with a new key. Applications authenticate identities separately.
func TestExternalCommitBasicIdentityDoesNotBindSigningKey(t *testing.T) {
	aliceGroup, bobGroup, alice, bob := makeTwoMemberGroups(t)
	impostor := newTestUser(t, "bob")
	if !bytes.Equal(impostor.kp.LeafNode.Credential.Identity, bob.kp.LeafNode.Credential.Identity) {
		t.Fatalf("setup: impostor identity %q differs from bob's %q",
			impostor.kp.LeafNode.Credential.Identity, bob.kp.LeafNode.Credential.Identity)
	}
	bobLeaf := bobGroup.ownLeafIndex
	epochBefore := aliceGroup.epoch.AsUint64()
	staged := newExternalCommitTestCommit(t, aliceGroup, alice, impostor, &bobLeaf)
	err := aliceGroup.ProcessReceivedCommit(staged.authenticatedContent, treesync.LeafIndex(0), aliceGroup.myLeafEncryptionKey)
	if err != nil {
		t.Fatalf("resync with the same Basic identity and a new key: %v", err)
	}
	if got := aliceGroup.epoch.AsUint64(); got != epochBefore+1 {
		t.Fatalf("epoch after Basic identity resync = %d, want %d", got, epochBefore+1)
	}
	t.Logf("Basic identity %q permits resync with a new signing key; identity authentication is application policy", bob.kp.LeafNode.Credential.Identity)
}
