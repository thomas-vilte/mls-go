package treesync

import (
	"errors"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/internal/tls"
)

// UpdatePath represents a path through the tree used in Commit messages.
type UpdatePath struct {
	LeafNode *LeafNodeData
	Nodes    []ciphersuite.HpkeCiphertext
}

// PathSecret represents a secret derived from a path node.
type PathSecret struct {
	Secret []byte
}

// NewUpdatePath creates a new UpdatePath.
func NewUpdatePath(leafNode *LeafNodeData, nodes []ciphersuite.HpkeCiphertext) *UpdatePath {
	return &UpdatePath{
		LeafNode: leafNode,
		Nodes:    nodes,
	}
}

// Marshal serializes UpdatePath to TLS format (RFC 9420 §7.6).
func (u *UpdatePath) Marshal() []byte {
	buf := tls.NewWriter()

	if u.LeafNode != nil {
		buf.WriteVLBytes(u.LeafNode.Marshal())
	} else {
		buf.WriteVLBytes([]byte{})
	}

	nodesBuf := tls.NewWriter()
	for _, node := range u.Nodes {
		// Manual serialization of HpkeCiphertext
		ctBuf := tls.NewWriter()
		ctBuf.WriteVLBytes(node.KEMOutput)
		ctBuf.WriteVLBytes(node.Ciphertext)
		nodesBuf.WriteVLBytes(ctBuf.Bytes())
	}
	buf.WriteVLBytes(nodesBuf.Bytes())

	return buf.Bytes()
}

// UnmarshalUpdatePath parses an UpdatePath from TLS format.
func UnmarshalUpdatePath(data []byte) (*UpdatePath, error) {
	buf := tls.NewReader(data)

	leafData, err := buf.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	// TODO: Unmarshal leaf node data
	_ = leafData

	nodesBytes, err := buf.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	nodesBuf := tls.NewReader(nodesBytes)
	var nodes []ciphersuite.HpkeCiphertext

	for nodesBuf.Remaining() > 0 {
		ctData, err := nodesBuf.ReadVLBytes()
		if err != nil {
			break
		}

		ctReader := tls.NewReader(ctData)
		kemOutput, err := ctReader.ReadVLBytes()
		if err != nil {
			return nil, err
		}
		ciphertext, err := ctReader.ReadVLBytes()
		if err != nil {
			return nil, err
		}

		nodes = append(nodes, ciphersuite.HpkeCiphertext{
			KEMOutput:  kemOutput,
			Ciphertext: ciphertext,
		})
	}

	return &UpdatePath{
		LeafNode: nil,
		Nodes:    nodes,
	}, nil
}

// DerivePathSecret derives a path secret from an HPKE shared secret.
func DerivePathSecret(sharedSecret []byte, context []byte) (*PathSecret, error) {
	if len(sharedSecret) == 0 {
		return nil, errors.New("shared secret is empty")
	}

	return &PathSecret{
		Secret: sharedSecret,
	}, nil
}

// Validate validates an UpdatePath.
func (u *UpdatePath) Validate() error {
	if u.LeafNode == nil {
		return errors.New("leaf_node is nil")
	}

	if err := u.LeafNode.Validate(); err != nil {
		return err
	}

	return nil
}
