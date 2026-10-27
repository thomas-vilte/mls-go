//go:build diagnostics

package group

import (
	"strings"
	"testing"

	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/treesync"
)

// TestUpdateProposalCredentialBindingAtReceipt checks certificate/signature-key binding when a signed Update proposal is received.
func TestUpdateProposalCredentialBindingAtReceipt(t *testing.T) {
	signedUpdate := func(t *testing.T, mismatched bool) (aliceGroup *Group, pm *framing.PublicMessage) {
		t.Helper()
		var bobGroup *Group
		var bob *testUser
		aliceGroup, bobGroup, _, bob = newCredentialBindingTestGroups(t)
		if mismatched {
			leaf := bobGroup.ratchetTree.GetLeaf(treesync.LeafIndex(bobGroup.ownLeafIndex))
			if leaf == nil || leaf.LeafData == nil {
				t.Fatal("bob's own leaf is missing")
			}
			// SelfUpdate copies the credential of the current leaf into the new LeafNode.
			leaf.LeafData.Credential = credentials.NewX509Credential([][]byte{newCredentialBindingTestCertificate(t, newCredentialBindingTestKey(t))})
		}
		update, err := bobGroup.SelfUpdate(bob.sigPriv)
		if err != nil {
			t.Fatalf("SelfUpdate(bob): %v", err)
		}
		raw, err := bobGroup.SignProposalAsPublicMessage(update, bob.sigPriv)
		if err != nil {
			t.Fatalf("SignProposalAsPublicMessage(bob): %v", err)
		}
		mlsMsg, err := framing.UnmarshalMLSMessage(raw)
		if err != nil {
			t.Fatalf("UnmarshalMLSMessage: %v", err)
		}
		pub, ok := mlsMsg.AsPublic()
		if !ok {
			t.Fatal("bob's Update is not a PublicMessage")
		}
		return aliceGroup, pub
	}

	t.Run("control_matching_certificate", func(t *testing.T) {
		aliceGroup, pm := signedUpdate(t, false)
		if err := aliceGroup.ProcessPublicMessage(pm); err != nil {
			t.Fatalf("alice.ProcessPublicMessage(bob's Update, matching certificate): %v", err)
		}
	})
	t.Run("attack_certificate_of_other_key", func(t *testing.T) {
		aliceGroup, pm := signedUpdate(t, true)
		err := aliceGroup.ProcessPublicMessage(pm)
		if err == nil || !strings.Contains(err.Error(), credentialBindingMismatchText) {
			t.Errorf("alice.ProcessPublicMessage(bob's Update with a certificate of another key): err = %v, want the X.509 binding rejection", err)
		}
	})
}
