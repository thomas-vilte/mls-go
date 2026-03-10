import re

with open('group/external_commit.go', 'r') as f:
    content = f.read()

# Add BlankNode
old_blanking_search = """	// Compute filtered levels BEFORE modifying the tree.
	_, copath, levels := filteredDirectPathLevels(treeDiff, treesync.LeafIndex(ownLeafIdx))
	F := len(levels)"""

new_blanking_replace = """	// Compute filtered levels BEFORE modifying the tree.
	_, copath, levels := filteredDirectPathLevels(treeDiff, treesync.LeafIndex(ownLeafIdx))
	F := len(levels)

	// RFC 9420 §12.4.2 step 6: Blank ALL intermediate nodes on the committer's
	// direct path before applying the UpdatePath encryption keys.
	for i := 1; i < len(directPath); i++ {
		treeDiff.BlankNode(directPath[i])
	}"""

content = content.replace(old_blanking_search, new_blanking_replace)

# Fix parent hashing
old_ph_search = """		var parentKey []byte
		if parent.EncryptionKey != nil {
			parentKey = parent.EncryptionKey.Bytes()
		}
		ph := treesync.ComputeParentHash(parentKey, parent.ParentHash, siblingHash)
		treeDiff.Nodes[nodeIdx].ParentHash = ph"""

new_ph_replace = """		var ph []byte
		if parent.State == treesync.NodeStatePresent {
			var parentKey []byte
			if parent.EncryptionKey != nil {
				parentKey = parent.EncryptionKey.Bytes()
			}
			ph = treesync.ComputeParentHash(parentKey, parent.ParentHash, siblingHash)
		} else {
			ph = parent.ParentHash
		}
		treeDiff.Nodes[nodeIdx].ParentHash = ph"""

content = content.replace(old_ph_search, new_ph_replace)

with open('group/external_commit.go', 'w') as f:
    f.write(content)

