package group

import (
	"strings"
	"testing"

	"github.com/thomas-vilte/mls-go/treesync"
)

// TestPathlessGCECommitRefusalNamesPathRule checks that a path-less GroupContextExtensions Commit is
// refused by the path rule (RFC 9420 §12.4), not by another check that also returns ErrInvalidProposal.
func TestPathlessGCECommitRefusalNamesPathRule(t *testing.T) {
	alice := newJoinTestMember(t, "Alice")
	bob := newJoinTestMember(t, "Bob")
	ag := createJoinTestGroup(t, alice)
	if _, err := ag.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	bg := joinThroughWelcome(t, ag, alice, bob)[0]

	forged := pathlessGCECommit(t, ag, alice.sig, pathRuleExtensions())
	err := bg.ProcessReceivedCommit(forged, treesync.LeafIndex(ag.ownLeafIndex), bg.MyLeafEncryptionKey())
	if err == nil || !strings.Contains(err.Error(), "commit requires UpdatePath") {
		t.Fatalf("path-less GCE commit: err = %v, want the RFC 9420 §12.4 path rule (\"commit requires UpdatePath\")", err)
	}
}
