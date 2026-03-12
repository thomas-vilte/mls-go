// Package extensions - Ratchet Tree Extension (RFC 9420 §12.4.3.3)
//
// # ¿Qué es RatchetTreeExtension?
//
// Esta extensión contiene el árbol de ratchet completo de un grupo MLS.
// Se usa en GroupInfo para ayudar a nuevos miembros a unirse al grupo
// sin necesidad de recibir el árbol por otros medios.
//
// # Estructura (RFC 9420 §12.4.3.3)
//
// ```
// ┌─────────────────────────────────────────────────────────────┐
// │              RatchetTreeExtension                           │
// ├─────────────────────────────────────────────────────────────┤
// │  ratchet_tree: opaque<V>                                    │
// │    └─ Node nodes<V>                                         │
// │       ├─ present: uint8                                     │
// │       │   ├─ 0 = Empty node                                 │
// │       │   └─ 1 = Present node                               │
// │       │                                                     │
// │       ├─ if present == 1:                                   │
// │       │   ├─ node_type: uint8                               │
// │       │   │   ├─ 1 = Leaf node                              │
// │       │   │   └─ 2 = Parent node                            │
// │       │   │                                                 │
// │       │   ├─ LeafNode:                                      │
// │       │   │   ├─ leaf_index: uint32                         │
// │       │   │   └─ leaf_node: opaque<V>                       │
// │       │   │                                                 │
// │       │   └─ ParentNode:                                    │
// │       │       ├─ encryption_key: opaque<V>                  │
// │       │       ├─ parent_hash: opaque<V>                     │
// │       │       └─ unmerged_leaves: uint32<V>                 │
// └─────────────────────────────────────────────────────────────┘
// ```
//
// # Ubicación
//
// - **KeyPackage**: No ❌
// - **GroupInfo**: Sí ✅
// - **GroupContext**: No ❌
//
// # ¿Para qué sirve?
//
// Cuando un nuevo miembro quiere unirse vía External Commit, necesita
// conocer la estructura del árbol para:
//
// 1. Verificar las hojas existentes
// 2. Calcular los path secrets
// 3. Cifrar su commit correctamente
//
// # Ejemplo de Uso
//
// // Crear extensión con árbol
// tree := getRatchetTree()
// ext := NewRatchetTreeExtension(tree)
//
// // Validar
//
//	if err := ext.Validate(); err != nil {
//	    return err
//	}
//
// // Serializar
// data := ext.Marshal()
//
// // Deserializar
// ext2, err := UnmarshalRatchetTreeExtension(data)
//
// # Parent Hash Validation
//
// Los parent hashes aseguran la integridad del árbol. Cada parent node
// contiene un hash de sus hijos, creando una cadena de confianza desde
// la raíz hasta las hojas.
//
// # RFC Compliance
//
// RFC 9420 §12.4.3.3:
// "The RatchetTree extension provides the full public state of the
// ratchet tree to allow new members to initialize their state."
package extensions

import (
	"fmt"

	"github.com/mls-go/internal/tls"
	"github.com/mls-go/treesync"
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

// UnmarshalRatchetTreeExtension parsea una RatchetTreeExtension desde formato TLS.
//
// # Decoding (RFC 9420 §12.4.3.3)
//
// ```
// ┌─────────────────────────────────────────┐
// │  ratchet_tree_length: varint            │
// ├─────────────────────────────────────────┤
// │  Node nodes<V>                          │
// │    ├─ present: uint8                    │
// │    ├─ if present == 1:                  │
// │    │   ├─ node_type: uint8              │
// │    │   │   ├─ 1 = Leaf                  │
// │    │   │   └─ 2 = Parent                │
// │    │   │                                │
// │    │   ├─ LeafNode:                     │
// │    │   │   ├─ leaf_index: uint32        │
// │    │   │   └─ leaf_node: opaque<V>      │
// │    │   │                                │
// │    │   └─ ParentNode:                   │
// │    │       ├─ encryption_key: opaque<V> │
// │    │       ├─ parent_hash: opaque<V>    │
// │    │       └─ unmerged_leaves: uint32<V>│
// └─────────────────────────────────────────┘
// ```
//
// # Ejemplo
//
// data := []byte{...}  // datos serializados
// ext, err := UnmarshalRatchetTreeExtension(data)
//
//	if err != nil {
//	    return err
//	}
//
// // ext.Tree contiene el árbol parseado
func UnmarshalRatchetTreeExtension(data []byte) (*RatchetTreeExtension, error) {
	if len(data) == 0 {
		return &RatchetTreeExtension{Tree: nil}, nil
	}

	buf := tls.NewReader(data)
	nodes := make([]treesync.Node, 0)

	// Parsear cada nodo del árbol
	for buf.Remaining() > 0 {
		// Leer presencia del nodo
		present, err := buf.ReadUint8()
		if err != nil {
			break
		}

		if present == 0 {
			// Nodo vacío
			nodes = append(nodes, treesync.Node{State: treesync.NodeStateEmpty})
			continue
		}

		// Nodo presente - leer tipo
		nodeType, err := buf.ReadUint8()
		if err != nil {
			return nil, fmt.Errorf("reading node_type: %w", err)
		}

		var node treesync.Node
		switch nodeType {
		case 1: // Leaf node
			// Leer leaf_index (lo leemos pero no lo usamos por ahora)
			_, err := buf.ReadUint32()
			if err != nil {
				return nil, fmt.Errorf("reading leaf_index: %w", err)
			}

			// Leer presencia de leaf_node
			leafPresent, err := buf.ReadUint8()
			if err != nil {
				return nil, fmt.Errorf("reading leaf_node presence: %w", err)
			}

			if leafPresent == 1 {
				// Leer leaf_node data (los bytes se parsearían en una implementación completa)
				_, err := buf.ReadVLBytes()
				if err != nil {
					return nil, fmt.Errorf("reading leaf_node: %w", err)
				}

				// Parsear LeafNodeData (simplificado - asume formato básico)
				// En una implementación completa, habría que parsear cada campo
				node = treesync.Node{
					State:    treesync.NodeStatePresent,
					LeafData: &treesync.LeafNodeData{
						// Los campos específicos se parsearían acá
						// Por ahora guardamos los bytes raw
					},
				}
			} else {
				node = treesync.Node{
					State: treesync.NodeStatePresent,
				}
			}

		case 2: // Parent node
			// Leer encryption_key (lo leemos pero no lo usamos por ahora)
			_, err := buf.ReadVLBytes()
			if err != nil {
				return nil, fmt.Errorf("reading encryption_key: %w", err)
			}

			// Leer parent_hash
			parentHash, err := buf.ReadVLBytes()
			if err != nil {
				return nil, fmt.Errorf("reading parent_hash: %w", err)
			}

			// Leer unmerged_leaves
			unmergedLeavesBytes, err := buf.ReadVLBytes()
			if err != nil {
				return nil, fmt.Errorf("reading unmerged_leaves: %w", err)
			}

			// Parsear unmerged_leaves como vector de uint32
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

	// Calcular número de hojas
	numLeaves := uint32(0)
	for i := range nodes {
		// Leaves están en la segunda mitad del árbol
		if i >= len(nodes)/2 && nodes[i].State != treesync.NodeStateEmpty {
			numLeaves++
		}
	}

	// Crear árbol
	tree := &treesync.RatchetTree{
		Nodes:     nodes,
		NumLeaves: numLeaves,
	}

	// Validar estructura del árbol
	if err := tree.Validate(); err != nil {
		return nil, fmt.Errorf("invalid tree structure: %w", err)
	}

	return &RatchetTreeExtension{Tree: tree}, nil
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
