package treesync

import (
	"crypto/sha256"

	"github.com/mls-go/internal/tls"
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
) []byte {
	buf := tls.NewWriter()

	buf.WriteVLBytes(publicKey)
	buf.WriteVLBytes(parentHash)
	buf.WriteVLBytes(originalSiblingTreeHash)

	hash := sha256.Sum256(buf.Bytes())
	return hash[:]
}

// ComputeLeafNodeHash computes the hash of a leaf node (RFC 9420 §7.8).
//
//	struct {
//	    uint32 leaf_index;
//	    optional<LeafNode> leaf_node;
//	} LeafNodeHashInput;
func ComputeLeafNodeHash(leafIndex LeafIndex, leafData *LeafNodeData) []byte {
	buf := tls.NewWriter()
	buf.WriteUint8(nodeTypeLeaf)

	buf.WriteUint32(uint32(leafIndex))

	if leafData != nil {
		buf.WriteUint8(1) // present
		buf.WriteRaw(leafData.Marshal())
	} else {
		buf.WriteUint8(0) // not present
	}

	hash := sha256.Sum256(buf.Bytes())
	return hash[:]
}
