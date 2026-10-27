package group

import (
	"errors"
	"strings"
	"testing"

	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/treesync"
)

// TestMemberCommitCredentialSignatureKeyBinding checks certificate/signature-key binding in the UpdatePath of a member commit.
func TestMemberCommitCredentialSignatureKeyBinding(t *testing.T) {
	t.Run("control/matching_path_credential", func(t *testing.T) {
		aliceGroup, bobGroup, _, bob := newCredentialBindingTestGroups(t)
		sc, err := bobGroup.Commit(bob.sigPriv, bob.sigPub, nil)
		if err != nil {
			t.Fatalf("Commit(bob): %v", err)
		}
		if err := aliceGroup.ProcessReceivedCommit(sc.authenticatedContent, treesync.LeafIndex(bobGroup.ownLeafIndex), aliceGroup.myLeafEncryptionKey); err != nil {
			t.Fatalf("ProcessReceivedCommit(bob, matching certificate): %v", err)
		}
	})

	t.Run("reject/path_certificate_of_other_key", func(t *testing.T) {
		aliceGroup, bobGroup, _, bob := newCredentialBindingTestGroups(t)
		bobLeaf := bobGroup.ownLeafIndex
		// bob's generator copies the credential of his member entry into the UpdatePath LeafNode.
		bobGroup.members[bobLeaf].Credential = credentials.NewX509Credential([][]byte{newCredentialBindingTestCertificate(t, newCredentialBindingTestKey(t))})
		sc, err := bobGroup.Commit(bob.sigPriv, bob.sigPub, nil)
		if err != nil {
			t.Fatalf("Commit(bob) with the certificate of another key: %v", err)
		}
		epochBefore := aliceGroup.epoch.AsUint64()

		err = aliceGroup.ProcessReceivedCommit(sc.authenticatedContent, treesync.LeafIndex(bobLeaf), aliceGroup.myLeafEncryptionKey)
		if !errors.Is(err, ErrInvalidProposal) || !strings.Contains(err.Error(), credentialBindingMismatchText) {
			t.Fatalf("ProcessReceivedCommit(UpdatePath with a certificate of another key): err = %v, want ErrInvalidProposal with the X.509 binding rejection", err)
		}
		if got := aliceGroup.epoch.AsUint64(); got != epochBefore {
			t.Fatalf("rejected commit changed alice's epoch: %d -> %d", epochBefore, got)
		}
	})
}
