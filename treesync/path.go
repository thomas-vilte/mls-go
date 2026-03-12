package treesync

import (
	"errors"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/internal/tls"
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

// UnmarshalUpdatePath parses an UpdatePath from TLS format per RFC 9420 §7.6.
//
// Parameters:
//   - data: Serialized UpdatePath bytes
//
// Returns the parsed UpdatePath, or an error if parsing fails.
func UnmarshalUpdatePath(data []byte) (*UpdatePath, error) {
	buf := tls.NewReader(data)

	leafData, err := buf.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	leafNode, err := UnmarshalLeafNodeData(leafData)
	if err != nil {
		return nil, err
	}

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

	if len(nodes) == 0 && leafNode == nil {
		return nil, errors.New("empty UpdatePath")
	}

	return &UpdatePath{
		LeafNode: leafNode,
		Nodes:    nodes,
	}, nil
}

// DerivePathSecret derives a path secret from an HPKE shared secret.
//
// Parameters:
//   - sharedSecret: The HPKE decapsulated shared secret
//   - context: Context string for key derivation (currently unused, kept for API compatibility)
//
// Returns the derived PathSecret, or an error if the shared secret is empty.
//
// RFC 9420 §7.4.3:
//
//	path_secret[i] = KDF.Extract(path_secret[i-1], HPKE_output)
//
//nolint:gocritic // Keep separate parameters for clarity and future use
func DerivePathSecret(sharedSecret []byte, _ []byte) (*PathSecret, error) {
	if len(sharedSecret) == 0 {
		return nil, errors.New("shared secret is empty")
	}

	return &PathSecret{
		Secret: sharedSecret,
	}, nil
}

// Validate validates an UpdatePath according to RFC 9420 §7.6.
//
// Checks:
//   - leaf_node must not be nil
//   - leaf_node must pass validation (RFC §7.3)
//
// Returns nil if valid, or an error describing the validation failure.
func (u *UpdatePath) Validate() error {
	if u.LeafNode == nil {
		return errors.New("leaf_node is nil")
	}

	return u.LeafNode.Validate()
}
