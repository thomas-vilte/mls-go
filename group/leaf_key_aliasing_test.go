package group

import (
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

func TestMyLeafEncryptionKey_NotZeroedAfterMergeCommit(t *testing.T) {
	t.Parallel()

	group, _, kpPrivKeys, _ := setupTwoMemberGroup(t)
	sigPriv := ciphersuite.NewSignaturePrivateKey(kpPrivKeys.SignatureKey)

	// A commit with no proposals refreshes the sender's leaf through its UpdatePath (RFC 9420
	// §12.4), which fills pendingLeafKey. An Update sent by value would be rejected.
	if _, err := group.Commit(sigPriv, sigPriv.PublicKey(), nil); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if len(group.pendingLeafKey) == 0 {
		t.Fatal("pendingLeafKey should be populated")
	}

	if err := group.MergeCommit(group.pendingCommit); err != nil {
		t.Fatalf("MergeCommit: %v", err)
	}

	if len(group.myLeafEncryptionKey) == 0 {
		t.Fatal("myLeafEncryptionKey should be set after MergeCommit")
	}
	allZero := true
	for _, b := range group.myLeafEncryptionKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatalf("BUG: myLeafEncryptionKey is all zeros after MergeCommit (sender side)")
	}
}
