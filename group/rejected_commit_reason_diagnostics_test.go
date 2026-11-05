//go:build diagnostics

package group

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/thomas-vilte/mls-go/treesync"
)

// TestRejectedTagReasonAndFingerprintSensitivity checks two things. First, that the tampered-tag rejection
// really comes from the confirmation_tag check (the tests that only assert err != nil would also pass if another
// check failed first). Second, that the fingerprint used by the other tests does change when a commit is
// accepted, so an unchanged fingerprint means something.
func TestRejectedTagReasonAndFingerprintSensitivity(t *testing.T) {
	alice := newDiagnosticMember(t, "Alice")
	bob := newDiagnosticMember(t, "Bob")
	ag := createDiagnosticGroup(t, alice)
	if _, err := ag.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	bg := commitAndJoin(t, ag, alice, bob)[0]

	staged, err := ag.Commit(alice.sig, alice.sig.PublicKey(), nil)
	if err != nil {
		t.Fatalf("SETUP: commit: %v", err)
	}
	legit := *staged.AuthenticatedContent()
	tampered := legit
	tampered.Auth.ConfirmationTag = append([]byte(nil), legit.Auth.ConfirmationTag...)
	tampered.Auth.ConfirmationTag[0] ^= 0x01
	sender := treesync.LeafIndex(ag.ownLeafIndex)

	before := groupStateFingerprint(t, bg)
	err = bg.ProcessReceivedCommit(&tampered, sender, bg.MyLeafEncryptionKey())
	if !errors.Is(err, ErrConfirmationTagMismatch) {
		t.Fatalf("tampered tag rejected for another reason: err = %v, want ErrConfirmationTagMismatch", err)
	}
	if groupStateFingerprint(t, bg) != before {
		t.Fatal("control failed: the rejected commit changed the fingerprint")
	}

	if err := bg.ProcessReceivedCommit(&legit, sender, bg.MyLeafEncryptionKey()); err != nil {
		t.Fatalf("legitimate commit: %v", err)
	}
	if groupStateFingerprint(t, bg) == before {
		t.Fatal("control failed: an accepted commit left the fingerprint unchanged, so the fingerprint is blind")
	}
	if err := ag.MergeCommit(staged); err != nil {
		t.Fatalf("MergeCommit by alice: %v", err)
	}
	assertDiagnosticExportEqual(t, ag, bg)
}

// TestMissingPSKRejectionReason checks that the rejection names the missing PSK. It is the same scenario as
// TestRejectedCommitMissingPSKLeavesStateUnchanged, but it checks the reason.
func TestMissingPSKRejectionReason(t *testing.T) {
	alice := newDiagnosticMember(t, "Alice")
	bob := newDiagnosticMember(t, "Bob")
	ag := createDiagnosticGroup(t, alice)
	if _, err := ag.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	bg := commitAndJoin(t, ag, alice, bob)[0]

	pskID := []byte("psk-reason")
	ag.LoadPsk(pskID, bytes.Repeat([]byte{0x3c}, 32))
	pskProp := NewPreSharedKeyProposal(1, pskID)
	pskProp.PreSharedKey.PskID.Nonce = bytes.Repeat([]byte{0x22}, 32)
	ag.proposals.AddProposal(pskProp, ag.ownLeafIndex)
	staged, err := ag.Commit(alice.sig, alice.sig.PublicKey(), nil)
	if err != nil {
		t.Fatalf("SETUP: commit with PSK: %v", err)
	}

	err = bg.ProcessReceivedCommit(staged.AuthenticatedContent(), treesync.LeafIndex(ag.ownLeafIndex), bg.MyLeafEncryptionKey())
	if err == nil || !strings.Contains(err.Error(), "missing PSK") {
		t.Fatalf("commit with an unknown PSK: err = %v, want the missing PSK error", err)
	}
}

// TestRejectedCommitZeroesPathKeysItCreated checks the state that a rejected commit produced in memory. Bob
// starts with a non-nil path key map. decryptPathSecret stores the path private key derived from Alice's
// UpdatePath into the live map before mergeCommit checks the confirmation_tag. The rejection restores a copy and
// must zero the entries of the live map, so no key that the commit created survives in the discarded state.
func TestRejectedCommitZeroesPathKeysItCreated(t *testing.T) {
	alice := newDiagnosticMember(t, "Alice")
	bob := newDiagnosticMember(t, "Bob")
	ag := createDiagnosticGroup(t, alice)
	if _, err := ag.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	bg := commitAndJoin(t, ag, alice, bob)[0]

	staged, err := ag.Commit(alice.sig, alice.sig.PublicKey(), nil)
	if err != nil {
		t.Fatalf("SETUP: commit: %v", err)
	}
	tampered := *staged.AuthenticatedContent()
	tampered.Auth.ConfirmationTag = append([]byte(nil), tampered.Auth.ConfirmationTag...)
	tampered.Auth.ConfirmationTag[0] ^= 0x01

	bg.pathNodePrivKeys = map[treesync.NodeIndex][]byte{}
	live := bg.pathNodePrivKeys
	if err := bg.ProcessReceivedCommit(&tampered, treesync.LeafIndex(ag.ownLeafIndex), bg.MyLeafEncryptionKey()); !errors.Is(err, ErrConfirmationTagMismatch) {
		t.Fatalf("tampered commit: err = %v, want ErrConfirmationTagMismatch", err)
	}

	leftover := 0
	for idx, key := range live {
		nonZero := false
		for _, b := range key {
			if b != 0 {
				nonZero = true
				break
			}
		}
		if nonZero {
			leftover++
			t.Errorf("path private key for node %d survives the rejected commit unzeroed (%d bytes) in the discarded state", idx, len(key))
		}
	}
	if leftover == 0 {
		t.Log("no unzeroed path private keys left behind")
	}
}
