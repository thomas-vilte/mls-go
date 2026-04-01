// Package extensions - Ratchet Tree Extension (RFC 9420 §12.4.3.3)
package extensions

import (
	"fmt"

	"github.com/thomas-vilte/mls-go/internal/tls"
	"github.com/thomas-vilte/mls-go/treesync"
)

// RatchetTreeExtension contains the full ratchet tree for a group.
//
// Per RFC 9420 §12.4.3.3, this extension appears in GroupInfo and provides
// the complete ratchet tree to new members joining via External Commit.
//
// # Structure (RFC 9420 §12.4.3.3)
//
// ```text
//
//	struct {
//	    opaque ratchet_tree<V>;
//	        // Vector of nodes:
//	        // - present: uint8 (0 = empty, 1 = present)
//	        // - if present:
//	        //   - node_type: uint8 (1 = leaf, 2 = parent)
//	        //   - type-specific data
//	} RatchetTreeExtension;
//
// ```
//
// # Location
//
// - GroupInfo: Yes
// - KeyPackage: No
// - GroupContext: No
//
// # Purpose
//
// New members joining via External Commit need the tree structure to:
//
//  1. Verify existing leaves
//  2. Calculate path secrets
//  3. Encrypt their Commit correctly
//
// # Example
//
// // Create extension with tree
// tree := getRatchetTree()
// ext := NewRatchetTreeExtension(tree)
//
// // Validate
//
//	if err := ext.Validate(); err != nil {
//	    return err
//	}
//
// // Serialize
// data := ext.Marshal()
//
// # Parent Hash Validation
//
// Parent hashes ensure tree integrity. Each parent node contains a hash
// of its children, creating a chain of tgo from root to leaves.
//
// # RFC Compliance
//
// RFC 9420 §12.4.3.3:
// "The RatchetTree extension provides the full public state of the
// ratchet tree to allow new members to initialize their state."
type RatchetTreeExtension struct {
	Tree *treesync.RatchetTree
}

// NewRatchetTreeExtension creates a RatchetTreeExtension.
func NewRatchetTreeExtension(tree *treesync.RatchetTree) *RatchetTreeExtension {
	return &RatchetTreeExtension{
		Tree: tree,
	}
}

// Marshal serializes the RatchetTreeExtension to TLS format.
//
// Tree is encoded as a vector of nodes per RFC 9420 §7.
//
// ```text
// ┌─────────────────────────────────────────────────────────────┐
// │         RatchetTreeExtension Encoding                       │
// ├─────────────────────────────────────────────────────────────┤
// │  ratchet_tree<V>                                            │
// │    └─ Node[]                                                │
// │       ├─ present: uint8 (0 = empty, 1 = present)            │
// │       └─ if present:                                        │
// │           ├─ node_type: uint8 (1 = leaf, 2 = parent)        │
// │           ├─ LeafNode or ParentNode data                    │
// └─────────────────────────────────────────────────────────────┘
// ```
func (r *RatchetTreeExtension) Marshal() []byte {
	if r.Tree == nil {
		return []byte{}
	}

	buf := tls.NewWriter()

	for i := range r.Tree.Nodes {
		node := &r.Tree.Nodes[i]
		if node.State == treesync.NodeStateEmpty {
			buf.WriteUint8(0)
		} else {
			buf.WriteUint8(1)

			if i%2 == 0 {
				// Leaf node
				buf.WriteUint8(1)
				buf.WriteUint32(uint32(i / 2))
				if node.LeafData != nil {
					buf.WriteUint8(1)
					buf.WriteRaw(node.LeafData.Marshal())
				} else {
					buf.WriteUint8(0)
				}
			} else {
				// Parent node
				buf.WriteUint8(2)

				if node.EncryptionKey != nil {
					buf.WriteVLBytes(node.EncryptionKey.Bytes())
					buf.WriteVLBytes(node.ParentHash)

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

// UnmarshalRatchetTreeExtension parses a RatchetTreeExtension from TLS.
//
// Decodes the ratchet_tree vector per RFC 9420 §7.
func UnmarshalRatchetTreeExtension(data []byte) (*RatchetTreeExtension, error) {
	if len(data) == 0 {
		return &RatchetTreeExtension{Tree: nil}, nil
	}

	buf := tls.NewReader(data)
	nodes := make([]treesync.Node, 0)

	for buf.Remaining() > 0 {
		present, err := buf.ReadUint8()
		if err != nil {
			break
		}

		if present == 0 {
			nodes = append(nodes, treesync.Node{State: treesync.NodeStateEmpty})
			continue
		}

		nodeType, err := buf.ReadUint8()
		if err != nil {
			return nil, fmt.Errorf("reading node_type: %w", err)
		}

		var node treesync.Node
		switch nodeType {
		case 1: // Leaf node
			_, err := buf.ReadUint32()
			if err != nil {
				return nil, fmt.Errorf("reading leaf_index: %w", err)
			}

			leafPresent, err := buf.ReadUint8()
			if err != nil {
				return nil, fmt.Errorf("reading leaf_node presence: %w", err)
			}

			if leafPresent == 1 {
				_, err := buf.ReadVLBytes()
				if err != nil {
					return nil, fmt.Errorf("reading leaf_node: %w", err)
				}
				node = treesync.Node{
					State:    treesync.NodeStatePresent,
					LeafData: &treesync.LeafNodeData{},
				}
			} else {
				node = treesync.Node{State: treesync.NodeStatePresent}
			}

		case 2: // Parent node
			_, err := buf.ReadVLBytes()
			if err != nil {
				return nil, fmt.Errorf("reading encryption_key: %w", err)
			}

			parentHash, err := buf.ReadVLBytes()
			if err != nil {
				return nil, fmt.Errorf("reading parent_hash: %w", err)
			}

			unmergedLeavesBytes, err := buf.ReadVLBytes()
			if err != nil {
				return nil, fmt.Errorf("reading unmerged_leaves: %w", err)
			}

			unmergedBuf := tls.NewReader(unmergedLeavesBytes)
			unmergedLeaves := make([]treesync.LeafIndex, 0)
			for unmergedBuf.Remaining() > 0 {
				leafIndex, err := unmergedBuf.ReadUint32()
				if err != nil {
					break
				}
				unmergedLeaves = append(unmergedLeaves, treesync.LeafIndex(leafIndex))
			}

			node = treesync.Node{
				State:          treesync.NodeStatePresent,
				ParentHash:     parentHash,
				UnmergedLeaves: unmergedLeaves,
			}

		default:
			return nil, fmt.Errorf("unknown node_type: %d", nodeType)
		}

		nodes = append(nodes, node)
	}

	// Calculate number of leaves
	numLeaves := uint32(0)
	for i := range nodes {
		if i >= len(nodes)/2 && nodes[i].State != treesync.NodeStateEmpty {
			numLeaves++
		}
	}

	tree := &treesync.RatchetTree{
		Nodes:     nodes,
		NumLeaves: numLeaves,
	}

	if err := tree.Validate(); err != nil {
		return nil, fmt.Errorf("invalid tree structure: %w", err)
	}

	return &RatchetTreeExtension{Tree: tree}, nil
}

// Validate validates the RatchetTreeExtension.
func (r *RatchetTreeExtension) Validate() error {
	if r.Tree == nil {
		return nil
	}
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

// Equal compares two RatchetTreeExtension instances.
//
// Compares tree hashes rather than full structure for efficiency.
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

// ToExtension converts to a generic Extension.
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
