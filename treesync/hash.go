package treesync

import (
	"hash"

	"github.com/thomas-vilte/mls-go/internal/tls"
)

// ComputeParentHash computes the parent hash for a node (RFC 9420 §7.9).
//
//	struct {
//	    HPKEPublicKey public_key;
//	    opaque parent_hash<V>;
//	    opaque original_sibling_tree_hash<V>;
//	} ParentHashInput;
func ComputeParentHash(
	publicKey []byte,
	parentHash []byte,
	originalSiblingTreeHash []byte,
	hashFunc func() hash.Hash,
) []byte {
	buf := tls.NewWriter()

	buf.WriteVLBytes(publicKey)
	buf.WriteVLBytes(parentHash)
	buf.WriteVLBytes(originalSiblingTreeHash)

	h := hashFunc()
	h.Write(buf.Bytes())
	return h.Sum(nil)
}

// ComputeLeafNodeHash computes the hash of a leaf node (RFC 9420 §7.8).
//
//	struct {
//	    uint32 leaf_index;
//	    optional<LeafNode> leaf_node;
//	} LeafNodeHashInput;
func ComputeLeafNodeHash(leafIndex LeafIndex, leafData *LeafNodeData, hashFunc func() hash.Hash) []byte {
	buf := tls.NewWriter()
	buf.WriteUint8(nodeTypeLeaf)

	buf.WriteUint32(uint32(leafIndex))

	if leafData != nil {
		buf.WriteUint8(1) // present
		buf.WriteRaw(leafData.Marshal())
	} else {
		buf.WriteUint8(0) // not present
	}

	h := hashFunc()
	h.Write(buf.Bytes())
	return h.Sum(nil)
}
