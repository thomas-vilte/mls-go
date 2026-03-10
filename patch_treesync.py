with open('treesync/tree.go', 'r') as f:
    content = f.read()

old_code = """		siblingIdx := t.GetSibling(nodeIdx)
		siblingHash := t.HashNode(siblingIdx)

		var parentKey []byte
		if parent.EncryptionKey != nil {
			parentKey = parent.EncryptionKey.Bytes()
		}

		expected := ComputeParentHash(parentKey, parent.ParentHash, siblingHash)"""

new_code = """		var expected []byte
		if parent.State == NodeStatePresent {
			var parentKey []byte
			if parent.EncryptionKey != nil {
				parentKey = parent.EncryptionKey.Bytes()
			}
			siblingIdx := t.GetSibling(nodeIdx)
			siblingHash := t.HashNode(siblingIdx)
			expected = ComputeParentHash(parentKey, parent.ParentHash, siblingHash)
		} else {
			expected = parent.ParentHash
		}"""

content = content.replace(old_code, new_code)

with open('treesync/tree.go', 'w') as f:
    f.write(content)

