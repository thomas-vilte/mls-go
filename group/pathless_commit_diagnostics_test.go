//go:build diagnostics

package group

import (
	"strings"
	"testing"

	"github.com/thomas-vilte/mls-go/treesync"
)

// TestPathlessGCECommitFailsOnPathRule checks that a path-less GroupContextExtensions commit is refused by
// the RFC 9420 §12.4 path rule and not by another check that also returns ErrInvalidProposal, and that the
// refusal leaves the receiver state unchanged. TestCommitRequiresPathForGroupContextExtensions asserts only
// the sentinel error.
func TestPathlessGCECommitFailsOnPathRule(t *testing.T) {
	alice := newDiagnosticMember(t, "Alice")
	bob := newDiagnosticMember(t, "Bob")
	ag := createDiagnosticGroup(t, alice)
	if _, err := ag.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	bg := commitAndJoin(t, ag, alice, bob)[0]

	forged := pathlessGCECommit(t, ag, alice.sig, pathRuleExtensions())
	before := groupStateFingerprint(t, bg)
	err := bg.ProcessReceivedCommit(forged, treesync.LeafIndex(ag.ownLeafIndex), bg.MyLeafEncryptionKey())
	if err == nil || !strings.Contains(err.Error(), "commit requires UpdatePath") {
		t.Fatalf("path-less GCE commit: err = %v, want the RFC 9420 §12.4 path rule (\"commit requires UpdatePath\")", err)
	}
	if after := groupStateFingerprint(t, bg); after != before {
		t.Errorf("path-less commit changed the receiver state:\nbefore: %s\nafter:  %s", before, after)
	}
}
