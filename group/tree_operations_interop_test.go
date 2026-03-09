package group

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/bits"
	"os"
	"testing"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/internal/tls"
	"github.com/openmls/go/treesync"
)

type treeOperationsVector struct {
	CipherSuite    uint16 `json:"cipher_suite"`
	Proposal       string `json:"proposal"`
	ProposalSender uint32 `json:"proposal_sender"`
	TreeBefore     string `json:"tree_before"`
	TreeAfter      string `json:"tree_after"`
	TreeHashBefore string `json:"tree_hash_before"`
	TreeHashAfter  string `json:"tree_hash_after"`
}

func mustDecodeHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

func TestTreeOperationsVectors(t *testing.T) {
	data, err := os.ReadFile("../testdata/mls-interop-testvectors/test-vectors/tree-operations.json")
	if err != nil {
		t.Skipf("tree-operations.json not found: %v", err)
	}

	var vectors []treeOperationsVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse tree-operations.json: %v", err)
	}

	runnable := make([]int, 0, len(vectors))
	for i := range vectors {
		cs := ciphersuite.CipherSuite(vectors[i].CipherSuite)
		if cs == 1 || cs.IsSupported() {
			runnable = append(runnable, i)
		}
	}
	if len(runnable) == 0 {
		t.Fatalf("no runnable vectors found in tree-operations.json")
	}

	for _, idx := range runnable {
		v := vectors[idx]
		t.Run(fmt.Sprintf("vector-%d", idx), func(t *testing.T) {
			cs := ciphersuite.CipherSuite(v.CipherSuite)

			treeBeforeBytes := mustDecodeHexBytes(t, v.TreeBefore)
			treeAfterBytes := mustDecodeHexBytes(t, v.TreeAfter)
			proposalBytes := mustDecodeHexBytes(t, v.Proposal)

			tree, err := unmarshalInteropTree(treeBeforeBytes, cs)
			if err != nil {
				t.Fatalf("UnmarshalTree(before): %v", err)
			}

			expectedAfter, err := unmarshalInteropTree(treeAfterBytes, cs)
			if err != nil {
				t.Fatalf("UnmarshalTree(after): %v", err)
			}

			if got := tree.TreeHash(); !bytes.Equal(got, mustDecodeHexBytes(t, v.TreeHashBefore)) {
				t.Fatalf("tree_hash_before mismatch\n  got  %x\n  want %x", got, mustDecodeHexBytes(t, v.TreeHashBefore))
			}

			proposal, err := UnmarshalProposal(proposalBytes)
			if err != nil {
				t.Fatalf("UnmarshalProposal: %v", err)
			}

			g := &Group{GroupContext: &GroupContext{}}
			if err := g.applyProposalToTree(proposal, tree, LeafNodeIndex(v.ProposalSender)); err != nil {
				t.Fatalf("applyProposalToTree: %v", err)
			}

			if got := tree.TreeHash(); !bytes.Equal(got, mustDecodeHexBytes(t, v.TreeHashAfter)) {
				t.Fatalf("tree_hash_after mismatch\n  got  %x\n  want %x", got, mustDecodeHexBytes(t, v.TreeHashAfter))
			}
			if got, want := tree.TreeHash(), expectedAfter.TreeHash(); !bytes.Equal(got, want) {
				t.Fatalf("tree_after parsed hash mismatch\n  got  %x\n  want %x", got, want)
			}
		})
	}
}

func unmarshalInteropTree(data []byte, cs ciphersuite.CipherSuite) (*treesync.RatchetTree, error) {
	r := tls.NewReader(data)
	nodesData, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading tree vector: %w", err)
	}

	nodeReader := tls.NewReader(nodesData)
	nodes := make([]treesync.Node, 0)
	for nodeReader.Remaining() > 0 {
		present, err := nodeReader.ReadUint8()
		if err != nil {
			return nil, fmt.Errorf("reading node presence: %w", err)
		}
		if present == 0 {
			nodes = append(nodes, treesync.Node{State: treesync.NodeStateEmpty})
			continue
		}

		nodeType, err := nodeReader.ReadUint8()
		if err != nil {
			return nil, fmt.Errorf("reading node type: %w", err)
		}

		switch nodeType {
		case 1:
			leaf, err := treesync.UnmarshalLeafNodeDataFromReader(nodeReader)
			if err != nil {
				return nil, fmt.Errorf("reading leaf node: %w", err)
			}
			nodes = append(nodes, treesync.Node{State: treesync.NodeStatePresent, LeafData: leaf})
		case 2:
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
				var curve ecdh.Curve
				switch cs {
				case 1, 3:
					curve = ecdh.X25519()
				case ciphersuite.MLS128DHKEMP256:
					curve = ecdh.P256()
				case 4:
					curve = ecdh.P521()
				case 6:
					curve = ecdh.P384()
				default:
					return nil, fmt.Errorf("unsupported cipher suite %d for HPKE key parsing", cs)
				}
				encKey, err = curve.NewPublicKey(encKeyBytes)
				if err != nil {
					return nil, fmt.Errorf("parsing parent encryption key: %w", err)
				}
			}

			unmergedReader := tls.NewReader(unmergedData)
			var unmerged []treesync.LeafIndex
			for unmergedReader.Remaining() > 0 {
				leafIndex, err := unmergedReader.ReadUint32()
				if err != nil {
					return nil, fmt.Errorf("reading unmerged leaf index: %w", err)
				}
				unmerged = append(unmerged, treesync.LeafIndex(leafIndex))
			}

			nodes = append(nodes, treesync.Node{
				State:          treesync.NodeStatePresent,
				EncryptionKey:  encKey,
				ParentHash:     parentHash,
				UnmergedLeaves: unmerged,
			})
		default:
			return nil, fmt.Errorf("unknown node type %d", nodeType)
		}
	}

	if len(nodes) == 0 {
		return nil, fmt.Errorf("empty tree")
	}

	numLeaves := uint32((len(nodes) + 1) / 2)
	if numLeaves > 1 && (numLeaves&(numLeaves-1)) != 0 {
		next := uint32(1) << bits.Len32(numLeaves-1)
		targetNodes := int(next*2 - 1)
		expanded := make([]treesync.Node, targetNodes)
		copy(expanded, nodes)
		for i := len(nodes); i < len(expanded); i++ {
			expanded[i] = treesync.Node{State: treesync.NodeStateEmpty}
		}
		nodes = expanded
		numLeaves = next
	}

	return &treesync.RatchetTree{
		Nodes:     nodes,
		NumLeaves: numLeaves,
	}, nil
}
