package group

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/treesync"
)

// joinByExternalCommit has charlie join a two-member group with an external
// commit. It returns alice's group, the joiner's group and the staged commit.
func joinByExternalCommit(t *testing.T) (aliceGroup, joiner *Group, charlie *testUser, sc *StagedCommit) {
	t.Helper()
	aliceGroup, _, alice, _ := makeTwoMemberGroups(t)
	charlie = newTestUser(t, "charlie")

	info, err := aliceGroup.GetGroupInfo(alice.sigPriv)
	if err != nil {
		t.Fatalf("GetGroupInfo: %v", err)
	}
	joiner, sc, err = ExternalCommit(info, aliceGroup.cipherSuite, charlie.sigPriv, charlie.sigPub, nil, charlie.kp.LeafNode.Credential)
	if err != nil {
		t.Fatalf("ExternalCommit: %v", err)
	}
	return aliceGroup, joiner, charlie, sc
}

// TestExternalCommitJoinerKeepsConfirmationTag checks that the group returned
// by ExternalCommit holds the confirmation tag of the epoch it creates, the
// same tag the commit carries and the existing members end up with.
func TestExternalCommitJoinerKeepsConfirmationTag(t *testing.T) {
	aliceGroup, joiner, _, sc := joinByExternalCommit(t)

	wire := sc.authenticatedContent.Auth.ConfirmationTag
	if len(wire) == 0 {
		t.Fatal("external commit carries an empty confirmation tag")
	}
	if got := joiner.ConfirmationTag(); !bytes.Equal(got, wire) {
		t.Fatalf("joiner.ConfirmationTag() = %x, want %x", got, wire)
	}

	if err := aliceGroup.ProcessReceivedCommit(sc.authenticatedContent, treesync.LeafIndex(0), aliceGroup.myLeafEncryptionKey); err != nil {
		t.Fatalf("alice ProcessReceivedCommit(external commit): %v", err)
	}
	if got := aliceGroup.ConfirmationTag(); !bytes.Equal(got, joiner.ConfirmationTag()) {
		t.Fatalf("alice.ConfirmationTag() = %x, joiner = %x", got, joiner.ConfirmationTag())
	}
}

// TestExternalJoinerGroupInfoAndRestoredStateCarryTag checks that the
// joiner's GroupInfo carries the confirmation tag, and that a restored joiner
// state is checked against it: an intact state is accepted and a state with a
// modified tag is refused.
func TestExternalJoinerGroupInfoAndRestoredStateCarryTag(t *testing.T) {
	_, joiner, charlie, sc := joinByExternalCommit(t)
	wire := sc.authenticatedContent.Auth.ConfirmationTag

	info, err := joiner.GetGroupInfo(charlie.sigPriv)
	if err != nil {
		t.Fatalf("joiner GetGroupInfo: %v", err)
	}
	if !bytes.Equal(info.ConfirmationTag, wire) {
		t.Fatalf("GroupInfo.ConfirmationTag = %x, want %x", info.ConfirmationTag, wire)
	}

	data, err := joiner.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState: %v", err)
	}
	restored, err := UnmarshalGroupState(data)
	if err != nil {
		t.Fatalf("UnmarshalGroupState: %v", err)
	}
	if err := restored.ValidateRestoredState(); err != nil {
		t.Fatalf("ValidateRestoredState(intact joiner state): %v", err)
	}
	if len(restored.confirmationTag) == 0 {
		t.Fatal("restored joiner state has no confirmation tag")
	}

	restored.confirmationTag = append([]byte(nil), restored.confirmationTag...)
	restored.confirmationTag[0] ^= 0xFF
	if err := restored.ValidateRestoredState(); err == nil {
		t.Fatal("ValidateRestoredState accepted a modified confirmation tag in an external joiner state")
	}
}
