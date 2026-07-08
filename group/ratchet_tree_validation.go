package group

import (
	"bytes"
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/treesync"
)

// validateJoinedRatchetTree performs the integrity checks a joiner MUST run on
// a ratchet tree received via GroupInfo, per RFC 9420 §12.4.3.1 (Welcome join)
// and §12.4.3.2 (External Commit join), which both delegate to the same
// "verify the integrity of the ratchet tree" checklist:
//
//   - tree_hash matches the GroupContext's tree_hash.
//   - every non-blank LeafNode is structurally valid (RFC §7.3).
//   - every non-blank parent node is parent-hash valid (RFC §7.9.2), checked
//     across the whole tree since a fresh joiner has no prior verified state
//     to lean on (unlike processing a Commit, where only the committer's
//     direct path needs checking).
//   - every unmerged_leaves entry references a non-blank descendant leaf.
func validateJoinedRatchetTree(tree *treesync.RatchetTree, groupContext *GroupContext, cs ciphersuite.CipherSuite) error {
	computedTreeHash := tree.TreeHash()
	if !bytes.Equal(computedTreeHash, groupContext.TreeHash) {
		return fmt.Errorf("ratchet tree hash mismatch: computed=%x want=%x: %w",
			computedTreeHash, groupContext.TreeHash, ErrTreeHashMismatch)
	}

	groupID := groupContext.GroupID.AsSlice()
	for i := treesync.LeafIndex(0); i < treesync.LeafIndex(tree.NumLeaves); i++ {
		leaf := tree.GetLeaf(i)
		if leaf == nil || leaf.State != treesync.NodeStatePresent || leaf.LeafData == nil {
			continue
		}
		if err := treesync.ValidateLeafNodeStructureWithContext(
			leaf.LeafData, cs, groupID, uint32(i),
		); err != nil {
			return fmt.Errorf("invalid leaf node at index %d in ratchet tree: %w", i, ErrLeafNodeInvalid)
		}
	}

	if err := tree.VerifyAllParentHashes(); err != nil {
		return fmt.Errorf("parent hash verification failed: %w", err)
	}

	for nodeIdx := range tree.Nodes {
		node := &tree.Nodes[nodeIdx]
		if node.State != treesync.NodeStatePresent || treesync.IsLeaf(treesync.NodeIndex(nodeIdx)) {
			continue
		}
		for _, unmergedLeafIdx := range node.UnmergedLeaves {
			leafNode := tree.GetLeaf(unmergedLeafIdx)
			if leafNode == nil || leafNode.State != treesync.NodeStatePresent {
				return fmt.Errorf("unmerged_leaves entry %d in node %d references a blank or missing leaf: %w",
					unmergedLeafIdx, nodeIdx, ErrUnmergedLeavesInvalid)
			}
			if !tree.SubtreeContainsLeaf(treesync.NodeIndex(nodeIdx), unmergedLeafIdx) {
				return fmt.Errorf("unmerged_leaves entry %d in node %d is not a descendant of that node: %w",
					unmergedLeafIdx, nodeIdx, ErrUnmergedLeavesInvalid)
			}
		}
	}

	return nil
}
