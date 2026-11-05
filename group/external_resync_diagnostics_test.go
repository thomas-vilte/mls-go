//go:build diagnostics

package group

import (
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/treesync"
)

// TestExternalResyncReusesOwnLeaf checks the external-commit variant of a commit that removes its own
// old leaf. Alice resyncs from Bob's GroupInfo and removes her own old leaf 0; the joiner takes leaf 0 again.
// The receivers pass sender index 0, so the rule that a commit does not remove its committer sees committer 0 and
// Removed 0 on this path. A valid resync must still be accepted, and a copy with a flipped confirmation_tag must
// leave the receiver unchanged.
func TestExternalResyncReusesOwnLeaf(t *testing.T) {
	alice := newDiagnosticMember(t, "Alice")
	bob := newDiagnosticMember(t, "Bob")
	charlie := newDiagnosticMember(t, "Charlie")
	ag := createDiagnosticGroup(t, alice)
	for _, u := range []diagnosticMember{bob, charlie} {
		if _, err := ag.AddMember(u.kp); err != nil {
			t.Fatalf("AddMember(%s): %v", u.name, err)
		}
	}
	joined := commitAndJoin(t, ag, alice, bob, charlie)
	bg, cg := joined[0], joined[1]

	gi, err := bg.GetGroupInfo(bob.sig)
	if err != nil {
		t.Fatalf("GetGroupInfo(bob): %v", err)
	}
	zero := LeafNodeIndex(0)
	ng, staged, err := ExternalCommit(gi, ciphersuite.MLS128DHKEMP256, alice.sig, alice.sig.PublicKey(), &zero, alice.kp.LeafNode.Credential)
	if err != nil {
		t.Fatalf("ExternalCommit(alice resync removing leaf 0): %v", err)
	}
	ac := staged.AuthenticatedContent()
	if ng.ownLeafIndex != 0 {
		t.Fatalf("resynced Alice is at leaf %d, want 0 (the leftmost blank leaf after her Remove)", ng.ownLeafIndex)
	}

	tampered := *ac
	tampered.Auth.ConfirmationTag = append([]byte(nil), ac.Auth.ConfirmationTag...)
	tampered.Auth.ConfirmationTag[0] ^= 0x01
	before := groupStateFingerprint(t, cg)
	if err := cg.ProcessReceivedCommit(&tampered, treesync.LeafIndex(0), cg.MyLeafEncryptionKey()); err == nil {
		t.Fatal("external commit with a flipped confirmation_tag was accepted")
	}
	if after := groupStateFingerprint(t, cg); after != before {
		t.Errorf("rejected external commit changed Charlie's state:\nbefore: %s\nafter:  %s", before, after)
	}

	if err := bg.ProcessReceivedCommit(ac, treesync.LeafIndex(0), bg.MyLeafEncryptionKey()); err != nil {
		t.Fatalf("Bob refused Alice's resync that reuses leaf 0: %v", err)
	}
	if err := cg.ProcessReceivedCommit(ac, treesync.LeafIndex(0), cg.MyLeafEncryptionKey()); err != nil {
		t.Fatalf("Charlie refused Alice's resync that reuses leaf 0: %v", err)
	}
	assertDiagnosticExportEqual(t, ng, bg)
	assertDiagnosticExportEqual(t, ng, cg)
	exchangeMessages(t, ng, alice, bg, bob)
	exchangeMessages(t, ng, alice, cg, charlie)
}
