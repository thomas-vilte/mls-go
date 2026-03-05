// Package extensions - Ratchet Tree Extension (RFC 9420 §12.4.3.3)
package extensions

import (
	"fmt"

	"github.com/openmls/go/internal/tls"
	"github.com/openmls/go/treesync"
)

// RatchetTreeExtension contains the full ratchet tree for a group.
//
// This extension is used in GroupInfo to help new members join the group
// without needing to receive the tree through other means.
//
// The extension_data contains: opaque ratchet_tree<V>
// where ratchet_tree is encoded as defined in RFC 9420 §7.
type RatchetTreeExtension struct {
	Tree *treesync.RatchetTree
}

// NewRatchetTreeExtension creates a new RatchetTreeExtension.
func NewRatchetTreeExtension(tree *treesync.RatchetTree) *RatchetTreeExtension {
	return &RatchetTreeExtension{
		Tree: tree,
	}
}

// Marshal serializes the RatchetTreeExtension to TLS format.
//
// The tree is encoded as a vector of nodes, where each node is optional.
func (r *RatchetTreeExtension) Marshal() []byte {
	if r.Tree == nil {
		return []byte{}
	}

	buf := tls.NewWriter()

	// Encode each node in the tree
	for i := range r.Tree.Nodes {
		node := &r.Tree.Nodes[i]
		if node.State == treesync.NodeStateEmpty {
			// Empty node - encode as absent
			buf.WriteUint8(0)
		} else {
			// Present node
			buf.WriteUint8(1)

			if i%2 == 0 {
				// Leaf node
				buf.WriteUint8(1)              // node_type = leaf
				buf.WriteUint32(uint32(i / 2)) // leaf_index
				if node.LeafData != nil {
					buf.WriteUint8(1)
					buf.WriteRaw(node.LeafData.Marshal())
				} else {
					buf.WriteUint8(0)
				}
			} else {
				// Parent node
				buf.WriteUint8(2) // node_type = parent

				// Left and right child hashes would go here
				// For simplicity, we encode the encryption key
				if node.EncryptionKey != nil {
					buf.WriteVLBytes(node.EncryptionKey.Bytes())
					buf.WriteVLBytes(node.ParentHash)

					// unmerged_leaves<V>
					unmergedBuf := tls.NewWriter()
					for _, leaf := range node.UnmergedLeaves {
						unmergedBuf.WriteUint32(uint32(leaf))
					}
					buf.WriteVLBytes(unmergedBuf.Bytes())
				}
			}
		}
	}

	return buf.Bytes()
}

// UnmarshalRatchetTreeExtension parses a RatchetTreeExtension from TLS format.
func UnmarshalRatchetTreeExtension(data []byte) (*RatchetTreeExtension, error) {
	if len(data) == 0 {
		return &RatchetTreeExtension{Tree: nil}, nil
	}

	buf := tls.NewReader(data)

	// Count nodes (simplified - would need proper tree structure)
	tree := &treesync.RatchetTree{
		Nodes:     make([]treesync.Node, 0),
		NumLeaves: 1,
	}

	for buf.Remaining() > 0 {
		present, err := buf.ReadUint8()
		if err != nil {
			break
		}

		if present == 0 {
			// Empty node
			tree.Nodes = append(tree.Nodes, treesync.Node{State: treesync.NodeStateEmpty})
		} else {
			// Present node - simplified parsing
			tree.Nodes = append(tree.Nodes, treesync.Node{State: treesync.NodeStatePresent})
		}
	}

	return &RatchetTreeExtension{
		Tree: tree,
	}, nil
}

// Validate validates the RatchetTreeExtension.
func (r *RatchetTreeExtension) Validate() error {
	if r.Tree == nil {
		return nil // Nil tree is valid (empty extension)
	}

	// Validate tree structure
	if err := r.Tree.Validate(); err != nil {
		return fmt.Errorf("invalid ratchet tree: %w", err)
	}

	return nil
}

// GetTree returns the ratchet tree.
func (r *RatchetTreeExtension) GetTree() *treesync.RatchetTree {
	return r.Tree
}

// SetTree sets the ratchet tree.
func (r *RatchetTreeExtension) SetTree(tree *treesync.RatchetTree) {
	r.Tree = tree
}

// Equal compares two RatchetTreeExtensions for equality.
func (r *RatchetTreeExtension) Equal(other *RatchetTreeExtension) bool {
	if r == nil || other == nil {
		return r == other
	}

	if r.Tree == nil && other.Tree == nil {
		return true
	}

	if r.Tree == nil || other.Tree == nil {
		return false
	}

	// Compare tree hashes instead of full tree structure
	hash1 := r.Tree.TreeHash()
	hash2 := other.Tree.TreeHash()

	if len(hash1) != len(hash2) {
		return false
	}

	for i := range hash1 {
		if hash1[i] != hash2[i] {
			return false
		}
	}

	return true
}

// ExtensionType returns the type code for this extension.
func (r *RatchetTreeExtension) ExtensionType() ExtensionType {
	return ExtensionTypeRatchetTree
}

// ToExtension converts this to a generic Extension.
func (r *RatchetTreeExtension) ToExtension() (*Extension, error) {
	data := r.Marshal()
	return &Extension{
		Type: ExtensionTypeRatchetTree,
		Data: data,
	}, nil
}

// FromExtension creates a RatchetTreeExtension from a generic Extension.
func FromExtension(ext *Extension) (*RatchetTreeExtension, error) {
	if ext.Type != ExtensionTypeRatchetTree {
		return nil, fmt.Errorf("wrong extension type: %d", ext.Type)
	}

	return UnmarshalRatchetTreeExtension(ext.Data)
}
