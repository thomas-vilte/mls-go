package treesync

import (
	"crypto/sha256"

	"github.com/openmls/go/internal/tls"
)

// ComputeParentHash computes the parent hash for a node (RFC 9420 §7.9).
func ComputeParentHash(
	leftHash []byte,
	rightHash []byte,
	encryptionKey []byte,
	parentHash []byte,
	unmergedLeaves []LeafIndex,
) []byte {
	buf := tls.NewWriter()

	buf.WriteVLBytes(leftHash)
	buf.WriteVLBytes(rightHash)
	buf.WriteVLBytes(encryptionKey)
	buf.WriteVLBytes(parentHash)

	unmergedBuf := tls.NewWriter()
	for _, leaf := range unmergedLeaves {
		unmergedBuf.WriteUint32(uint32(leaf))
	}
	buf.WriteVLBytes(unmergedBuf.Bytes())

	hash := sha256.Sum256(buf.Bytes())
	return hash[:]
}

// ComputeLeafNodeHash computes the hash of a leaf node.
func ComputeLeafNodeHash(leafIndex LeafIndex, leafData *LeafNodeData) []byte {
	buf := tls.NewWriter()

	buf.WriteUint8(1)
	buf.WriteUint32(uint32(leafIndex))

	if leafData != nil {
		buf.WriteUint8(1)
		buf.WriteRaw(leafData.Marshal())
	} else {
		buf.WriteUint8(0)
	}

	hash := sha256.Sum256(buf.Bytes())
	return hash[:]
}
