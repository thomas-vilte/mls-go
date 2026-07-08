package group

import (
	"testing"

	mlsext "github.com/thomas-vilte/mls-go/extensions"
	"github.com/thomas-vilte/mls-go/treesync"
)

// TestExternalCommit_RejectsTamperedRatchetTree verifies that ExternalCommit
// validates the ratchet_tree extension (RFC 9420 §12.4.3.2, same integrity
// checklist as Welcome join per §12.4.3.1) instead of trusting it blindly.
//
// Before this check existed, ExternalCommit parsed the ratchet_tree extension
// and used it directly with no tree_hash verification at all — a forged tree
// in GroupInfo.extensions would have been silently accepted.
func TestExternalCommit_RejectsTamperedRatchetTree(t *testing.T) {
	aliceGroup, bobGroup, alice, bob := makeTwoMemberGroups(t)

	// Force a real UpdatePath (the first Add-only commit in makeTwoMemberGroups
	// has LeafCount()==1 beforehand, so it omits the path and leaves root
	// blank). With 2 members present, a self-update commit must include one,
	// populating the root's parent-hash chain — matching what a real,
	// multi-epoch group looks like when a new member arrives via ExternalCommit.
	_, err := bobGroup.SelfUpdate(bob.sigPriv)
	if err != nil {
		t.Fatalf("SelfUpdate: %v", err)
	}
	sc, err := bobGroup.Commit(bob.sigPriv, bob.sigPub, nil)
	if err != nil {
		t.Fatalf("Commit(bob self-update): %v", err)
	}
	if err := bobGroup.MergeCommit(sc); err != nil {
		t.Fatalf("MergeCommit(bob): %v", err)
	}
	if err := aliceGroup.ProcessReceivedCommit(sc.authenticatedContent, treesync.LeafIndex(bobGroup.ownLeafIndex), aliceGroup.myLeafEncryptionKey); err != nil {
		t.Fatalf("alice ProcessReceivedCommit(bob self-update): %v", err)
	}

	groupInfo, err := aliceGroup.GetGroupInfo(alice.sigPriv)
	if err != nil {
		t.Fatalf("GetGroupInfo: %v", err)
	}

	charlie := newTestUser(t, "charlie-tamper")

	// Sanity check: an untampered GroupInfo must still work.
	if _, _, err := ExternalCommit(groupInfo, aliceGroup.cipherSuite, charlie.sigPriv, charlie.sigPub, nil, charlie.kp.LeafNode.Credential); err != nil {
		t.Fatalf("ExternalCommit with a genuine tree should succeed, got: %v", err)
	}

	// Tamper with the serialized ratchet_tree extension: flip a byte in a
	// leaf's encryption key. This changes the tree's computed tree_hash while
	// GroupContext.TreeHash (signed, untouched) still reflects the original.
	for i, ext := range groupInfo.Extensions {
		if ext.Type != mlsext.ExtensionTypeRatchetTree {
			continue
		}
		tree, err := treesync.UnmarshalTreeFromExtension(ext.Data, groupInfo.GroupContext.CipherSuite)
		if err != nil {
			t.Fatalf("UnmarshalTreeFromExtension: %v", err)
		}
		leaf := tree.GetLeaf(0)
		if leaf == nil || leaf.LeafData == nil || len(leaf.LeafData.EncryptionKey) == 0 {
			t.Fatalf("leaf 0 has no encryption key to tamper with")
		}
		tampered := append([]byte(nil), leaf.LeafData.EncryptionKey...)
		tampered[0] ^= 0xFF
		leaf.LeafData.EncryptionKey = tampered
		if err := tree.SetLeaf(0, *leaf.LeafData); err != nil {
			t.Fatalf("SetLeaf(0) with tampered key: %v", err)
		}
		groupInfo.Extensions[i].Data = tree.MarshalTreeRFC()
	}

	if _, _, err := ExternalCommit(groupInfo, aliceGroup.cipherSuite, charlie.sigPriv, charlie.sigPub, nil, charlie.kp.LeafNode.Credential); err == nil {
		t.Fatal("ExternalCommit should reject a tampered ratchet_tree extension, but it succeeded")
	}
}
