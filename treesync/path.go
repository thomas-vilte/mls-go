package treesync

import (
	"errors"

	"github.com/openmls/go/internal/tls"
)

// UpdatePath represents a path through the tree used in Commit messages.
type UpdatePath struct {
	LeafNode *LeafNodeData
	Nodes    []HPKECiphertext
}

// HPKECiphertext represents encrypted path node data.
type HPKECiphertext struct {
	KEMOutput  []byte
	Ciphertext []byte
}

// PathSecret represents a secret derived from a path node.
type PathSecret struct {
	Secret []byte
}

// NewUpdatePath creates a new UpdatePath.
func NewUpdatePath(leafNode *LeafNodeData, nodes []HPKECiphertext) *UpdatePath {
	return &UpdatePath{
		LeafNode: leafNode,
		Nodes:    nodes,
	}
}

// Marshal serializes UpdatePath to TLS format (RFC 9420 §7.6).
func (u *UpdatePath) Marshal() []byte {
	buf := tls.NewWriter()

	if u.LeafNode != nil {
		buf.WriteRaw(u.LeafNode.Marshal())
	} else {
		buf.WriteVLBytes([]byte{})
	}

	nodesBuf := tls.NewWriter()
	for _, node := range u.Nodes {
		nodesBuf.WriteVLBytes(node.KEMOutput)
		nodesBuf.WriteVLBytes(node.Ciphertext)
	}
	buf.WriteVLBytes(nodesBuf.Bytes())

	return buf.Bytes()
}

// UnmarshalUpdatePath parses an UpdatePath from TLS format.
func UnmarshalUpdatePath(data []byte) (*UpdatePath, error) {
	buf := tls.NewReader(data)

	// Skip leaf_node for now
	_, err := buf.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	nodesBytes, err := buf.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	nodesBuf := tls.NewReader(nodesBytes)
	var nodes []HPKECiphertext

	for nodesBuf.Remaining() > 0 {
		kemOutput, err := nodesBuf.ReadVLBytes()
		if err != nil {
			return nil, err
		}

		ciphertext, err := nodesBuf.ReadVLBytes()
		if err != nil {
			return nil, err
		}

		nodes = append(nodes, HPKECiphertext{
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
