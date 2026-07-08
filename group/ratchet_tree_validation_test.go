package group

import (
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/treesync"
)

// TestValidateJoinedRatchetTree_RejectsInvalidLeaf verifies that a tree whose
// tree_hash is internally consistent, but whose leaf node fails structural
// validation (here: an invalid signature), is rejected (RFC 9420 §12.4.3.1:
// "For each non-empty leaf node, validate the LeafNode as described in
// Section 7.3").
func TestValidateJoinedRatchetTree_RejectsInvalidLeaf(t *testing.T) {
	aliceGroup, _, _, _ := makeTwoMemberGroups(t)
	tree := aliceGroup.ratchetTree.Clone()

	leaf := tree.GetLeaf(0)
	if leaf == nil || leaf.LeafData == nil {
		t.Fatal("leaf 0 has no LeafData")
	}
	tamperedLeaf := *leaf.LeafData
	tamperedSig := append([]byte(nil), tamperedLeaf.Signature...)
	if len(tamperedSig) == 0 {
		t.Fatal("leaf 0 has no signature to tamper with")
	}
	tamperedSig[0] ^= 0xFF
	tamperedLeaf.Signature = tamperedSig
	if err := tree.SetLeaf(0, tamperedLeaf); err != nil {
		t.Fatalf("SetLeaf(tampered): %v", err)
	}

	// Recompute tree_hash so the tampered tree is internally consistent —
	// isolating the leaf-validation check from the tree_hash check.
	gc := &GroupContext{
		GroupID:  aliceGroup.groupID,
		TreeHash: tree.TreeHash(),
	}

	err := validateJoinedRatchetTree(tree, gc, aliceGroup.cipherSuite)
	if err == nil {
		t.Fatal("validateJoinedRatchetTree should reject a leaf with an invalid signature")
	}
	if !errors.Is(err, ErrLeafNodeInvalid) {
		t.Fatalf("error = %v, want ErrLeafNodeInvalid", err)
	}
}

// TestValidateJoinedRatchetTree_RejectsBadUnmergedLeaves verifies that a
// parent node whose unmerged_leaves references a blank leaf is rejected
// (RFC 9420 §12.4.3.1).
func TestValidateJoinedRatchetTree_RejectsBadUnmergedLeaves(t *testing.T) {
	aliceGroup, _, alice, _ := makeTwoMemberGroups(t)

	// makeTwoMemberGroups' own commit has LeafCount()==1 beforehand, so it
	// omits the UpdatePath and root stays blank. Add a third member with
	// LeafCount()>1 so this commit forces a real path, making root Present
	// with a genuinely valid parent-hash chain — isolating the
	// unmerged_leaves check from the parent-hash check below.
	charlie := newTestUser(t, "charlie-unmerged-leaves")
	if _, err := aliceGroup.AddMember(charlie.kp); err != nil {
		t.Fatalf("AddMember(charlie): %v", err)
	}
	sc, err := aliceGroup.Commit(alice.sigPriv, alice.sigPub, nil)
	if err != nil {
		t.Fatalf("Commit(add charlie): %v", err)
	}
	if err := aliceGroup.MergeCommit(sc); err != nil {
		t.Fatalf("MergeCommit(add charlie): %v", err)
	}

	tree := aliceGroup.ratchetTree.Clone()
	rootIdx := tree.Root()
	if tree.Nodes[rootIdx].State != treesync.NodeStatePresent {
		t.Fatal("root should be present after a commit with LeafCount()>1")
	}
	// Append a bogus entry without touching ParentHash/EncryptionKey, so the
	// (already valid) parent-hash chain is undisturbed.
	tree.Nodes[rootIdx].UnmergedLeaves = append(tree.Nodes[rootIdx].UnmergedLeaves, 99)

	gc := &GroupContext{
		GroupID:  aliceGroup.groupID,
		TreeHash: tree.TreeHash(),
	}

	err = validateJoinedRatchetTree(tree, gc, aliceGroup.cipherSuite)
	if err == nil {
		t.Fatal("validateJoinedRatchetTree should reject an unmerged_leaves entry referencing a nonexistent/blank leaf")
	}
	if !errors.Is(err, ErrUnmergedLeavesInvalid) {
		t.Fatalf("error = %v, want ErrUnmergedLeavesInvalid", err)
	}
}
