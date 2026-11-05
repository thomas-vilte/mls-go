//go:build diagnostics

package group

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/treesync"
)

// TestRejectedCommitMissingPSKLeavesStateUnchanged checks a commit that fails late: the receiver lacks the
// external PSK, and collectPSKsFromProposals runs after the Add of the commit has already changed the tree and the
// member map. The rejected commit must leave every field unchanged, and the same commit must be accepted once
// the PSK is known.
func TestRejectedCommitMissingPSKLeavesStateUnchanged(t *testing.T) {
	alice := newDiagnosticMember(t, "Alice")
	bob := newDiagnosticMember(t, "Bob")
	charlie := newDiagnosticMember(t, "Charlie")
	ag := createDiagnosticGroup(t, alice)
	if _, err := ag.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember(bob): %v", err)
	}
	bg := commitAndJoin(t, ag, alice, bob)[0]

	// Alice adds Charlie and references an external PSK that only she holds.
	pskID := []byte("psk-missing")
	pskBytes := bytes.Repeat([]byte{0x5a}, 32)
	if _, err := ag.AddMember(charlie.kp); err != nil {
		t.Fatalf("AddMember(charlie): %v", err)
	}
	ag.LoadPsk(pskID, pskBytes)
	pskProp := NewPreSharedKeyProposal(1, pskID)
	pskProp.PreSharedKey.PskID.Nonce = bytes.Repeat([]byte{0x11}, 32)
	ag.proposals.AddProposal(pskProp, ag.ownLeafIndex)

	staged, err := ag.Commit(alice.sig, alice.sig.PublicKey(), nil)
	if err != nil {
		t.Fatalf("SETUP: commit with PSK proposal: %v", err)
	}
	ac := staged.AuthenticatedContent()
	sender := treesync.LeafIndex(ag.ownLeafIndex)

	before := groupStateFingerprint(t, bg)
	if err := bg.ProcessReceivedCommit(ac, sender, bg.MyLeafEncryptionKey()); err == nil {
		t.Fatal("commit referencing a PSK that the receiver lacks was accepted")
	}
	if after := groupStateFingerprint(t, bg); after != before {
		t.Errorf("rejected commit changed the receiver state:\nbefore: %s\nafter:  %s", before, after)
	}

	// The receiver learns the PSK. The same commit must now be accepted from the unchanged state.
	bg.LoadPsk(pskID, pskBytes)
	if err := bg.ProcessReceivedCommit(ac, sender, bg.MyLeafEncryptionKey()); err != nil {
		t.Fatalf("same commit refused after the receiver learned the PSK: %v", err)
	}
	if err := ag.MergeCommit(staged); err != nil {
		t.Fatalf("MergeCommit by alice: %v", err)
	}
	assertDiagnosticExportEqual(t, ag, bg)
	exchangeMessages(t, ag, alice, bg, bob)
}

// TestRejectedTagKeepsPendingSelfUpdate checks that a commit rejected for a flipped confirmation_tag keeps the
// pending SelfUpdate of the receiver (pendingUpdatePrivKey and a stored proposal). Every field that the commit
// could touch must match the state before the rejection.
func TestRejectedTagKeepsPendingSelfUpdate(t *testing.T) {
	alice := newDiagnosticMember(t, "Alice")
	bob := newDiagnosticMember(t, "Bob")
	ag := createDiagnosticGroup(t, alice)
	if _, err := ag.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	bg := commitAndJoin(t, ag, alice, bob)[0]

	if _, err := bg.SelfUpdate(bob.sig); err != nil {
		t.Fatalf("SETUP: bob SelfUpdate: %v", err)
	}

	staged, err := ag.Commit(alice.sig, alice.sig.PublicKey(), nil)
	if err != nil {
		t.Fatalf("SETUP: alice commit: %v", err)
	}
	legit := *staged.AuthenticatedContent()
	tampered := legit
	tampered.Auth.ConfirmationTag = append([]byte(nil), legit.Auth.ConfirmationTag...)
	tampered.Auth.ConfirmationTag[0] ^= 0x01

	before := groupStateFingerprint(t, bg)
	sender := treesync.LeafIndex(ag.ownLeafIndex)
	if err := bg.ProcessReceivedCommit(&tampered, sender, bg.MyLeafEncryptionKey()); err == nil {
		t.Fatal("commit with a flipped confirmation_tag was accepted")
	}
	if after := groupStateFingerprint(t, bg); after != before {
		t.Errorf("rejected commit changed the receiver state:\nbefore: %s\nafter:  %s", before, after)
	}

	if err := bg.ProcessReceivedCommit(&legit, sender, bg.MyLeafEncryptionKey()); err != nil {
		t.Fatalf("legitimate commit refused after the rejection: %v", err)
	}
	if err := ag.MergeCommit(staged); err != nil {
		t.Fatalf("MergeCommit by alice: %v", err)
	}
	assertDiagnosticExportEqual(t, ag, bg)
}
