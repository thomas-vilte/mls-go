package treesync

import (
	"crypto/ecdh"
	"fmt"

	"github.com/mls-go/internal/tls"
)

const (
	nodeTypeEmpty  uint8 = 0
	nodeTypeLeaf   uint8 = 1
	nodeTypeParent uint8 = 2
)

// MarshalTree serializa el RatchetTree completo para transporte
// (extensión ratchet_tree en GroupInfo, RFC §12.4.3.3).
func (t *RatchetTree) MarshalTree() []byte {
	w := tls.NewWriter()
	w.WriteUint32(t.NumLeaves)

	for i := range t.Nodes {
		node := &t.Nodes[i]

		if node.State == NodeStateEmpty || node.State == NodeStateBlank {
			w.WriteUint8(nodeTypeEmpty)
			continue
		}

		if IsLeaf(NodeIndex(i)) {
			w.WriteUint8(nodeTypeLeaf)
			if node.LeafData != nil {
				w.WriteVLBytes(node.LeafData.Marshal())
			} else {
				w.WriteVLBytes([]byte{})
			}
		} else {
			w.WriteUint8(nodeTypeParent)
			if node.EncryptionKey != nil {
				w.WriteVLBytes(node.EncryptionKey.Bytes())
			} else {
				w.WriteVLBytes([]byte{})
			}
			w.WriteVLBytes(node.ParentHash)

			unmergedBuf := tls.NewWriter()
			for _, li := range node.UnmergedLeaves {
				unmergedBuf.WriteUint32(uint32(li))
			}
			w.WriteVLBytes(unmergedBuf.Bytes())
		}
	}

	return w.Bytes()
}

// UnmarshalTree deserializa un RatchetTree desde formato TLS.
func UnmarshalTree(data []byte) (*RatchetTree, error) {
	r := tls.NewReader(data)

	numLeaves, err := r.ReadUint32()
	if err != nil {
		return nil, fmt.Errorf("reading num_leaves: %w", err)
	}
	if numLeaves == 0 {
		return nil, fmt.Errorf("num_leaves must be > 0")
	}

	expectedNodes := int(numLeaves*2 - 1)
	nodes := make([]Node, expectedNodes)

	for i := 0; i < expectedNodes; i++ {
		nodeType, err := r.ReadUint8()
		if err != nil {
			return nil, fmt.Errorf("reading node type at index %d: %w", i, err)
		}

		switch nodeType {
		case nodeTypeEmpty:
			nodes[i] = Node{State: NodeStateEmpty}

		case nodeTypeLeaf:
			leafBytes, err := r.ReadVLBytes()
			if err != nil {
				return nil, fmt.Errorf("reading leaf data at index %d: %w", i, err)
			}
			if len(leafBytes) == 0 {
				nodes[i] = Node{State: NodeStatePresent}
			} else {
				ld, err := UnmarshalLeafNodeData(leafBytes)
				if err != nil {
					return nil, fmt.Errorf("unmarshaling leaf at index %d: %w", i, err)
				}
				nodes[i] = Node{State: NodeStatePresent, LeafData: ld}
			}

		case nodeTypeParent:
			encKeyBytes, err := r.ReadVLBytes()
			if err != nil {
				return nil, fmt.Errorf("reading enc_key at index %d: %w", i, err)
			}
			parentHash, err := r.ReadVLBytes()
			if err != nil {
				return nil, fmt.Errorf("reading parent_hash at index %d: %w", i, err)
			}
			unmergedData, err := r.ReadVLBytes()
			if err != nil {
				return nil, fmt.Errorf("reading unmerged_leaves at index %d: %w", i, err)
			}

			var encKey *ecdh.PublicKey
			if len(encKeyBytes) > 0 {
				encKey, err = ecdh.P256().NewPublicKey(encKeyBytes)
				if err != nil {
					return nil, fmt.Errorf("parsing enc_key at index %d: %w", i, err)
				}
			}

			unmergedR := tls.NewReader(unmergedData)
			var unmergedLeaves []LeafIndex
			for unmergedR.Remaining() > 0 {
				li, err := unmergedR.ReadUint32()
				if err != nil {
					break
				}
				unmergedLeaves = append(unmergedLeaves, LeafIndex(li))
			}

			nodes[i] = Node{
				State:          NodeStatePresent,
				EncryptionKey:  encKey,
				ParentHash:     parentHash,
				UnmergedLeaves: unmergedLeaves,
			}

		default:
			return nil, fmt.Errorf("unknown node type %d at index %d", nodeType, i)
		}
	}

	return &RatchetTree{
		Nodes:     nodes,
		NumLeaves: numLeaves,
	}, nil
}

// UnmarshalTreeFromExtension parses the RFC 9420 ratchet_tree extension wire format.
// Format: nodes<V>, each node encoded as presence(u8) [node_type(u8) fields...].
func UnmarshalTreeFromExtension(data []byte) (*RatchetTree, error) {
	r := tls.NewReader(data)
	nodesData, err := r.ReadVLBytes()
	if err != nil {
		return UnmarshalTree(data)
	}
	if r.Remaining() != 0 {
		return UnmarshalTree(data)
	}

	nodeReader := tls.NewReader(nodesData)
	nodes := make([]Node, 0)
	for nodeReader.Remaining() > 0 {
		present, err := nodeReader.ReadUint8()
		if err != nil {
			return nil, fmt.Errorf("reading node presence: %w", err)
		}
		if present == 0 {
			nodes = append(nodes, Node{State: NodeStateEmpty})
			continue
		}

		nodeType, err := nodeReader.ReadUint8()
		if err != nil {
			return nil, fmt.Errorf("reading node type: %w", err)
		}

		switch nodeType {
		case nodeTypeLeaf:
			leaf, err := UnmarshalLeafNodeDataFromReader(nodeReader)
			if err != nil {
				return nil, fmt.Errorf("reading leaf node: %w", err)
			}
			nodes = append(nodes, Node{State: NodeStatePresent, LeafData: leaf})

		case nodeTypeParent:
			encKeyBytes, err := nodeReader.ReadVLBytes()
			if err != nil {
				return nil, fmt.Errorf("reading parent encryption key: %w", err)
			}
			parentHash, err := nodeReader.ReadVLBytes()
			if err != nil {
				return nil, fmt.Errorf("reading parent hash: %w", err)
			}
			unmergedData, err := nodeReader.ReadVLBytes()
			if err != nil {
				return nil, fmt.Errorf("reading unmerged leaves: %w", err)
			}

			var encKey *ecdh.PublicKey
			if len(encKeyBytes) > 0 {
				encKey, err = ecdh.P256().NewPublicKey(encKeyBytes)
				if err != nil {
					return nil, fmt.Errorf("parsing parent encryption key: %w", err)
				}
			}

			unmergedReader := tls.NewReader(unmergedData)
			var unmerged []LeafIndex
			for unmergedReader.Remaining() > 0 {
				leafIndex, err := unmergedReader.ReadUint32()
				if err != nil {
					return nil, fmt.Errorf("reading unmerged leaf index: %w", err)
				}
				unmerged = append(unmerged, LeafIndex(leafIndex))
			}

			nodes = append(nodes, Node{
				State:          NodeStatePresent,
				EncryptionKey:  encKey,
				ParentHash:     parentHash,
				UnmergedLeaves: unmerged,
			})

		default:
			return nil, fmt.Errorf("unknown node type %d", nodeType)
		}
	}

	if len(nodes) == 0 {
		return UnmarshalTree(data)
	}

	return &RatchetTree{
		Nodes:     nodes,
		NumLeaves: uint32((len(nodes) + 1) / 2),
	}, nil
}
