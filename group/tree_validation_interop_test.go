package group

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/mls-go/ciphersuite"
	"github.com/mls-go/treesync"
)

type treeValidationVector struct {
	CipherSuite uint16   `json:"cipher_suite"`
	Tree        string   `json:"tree"`
	GroupID     string   `json:"group_id"`
	TreeHashes  []string `json:"tree_hashes"`
	Resolutions [][]int  `json:"resolutions"`
}

func TestTreeValidationVectors(t *testing.T) {
	data, err := os.ReadFile("../testdata/mls-interop-testvectors/test-vectors/tree-validation.json")
	if err != nil {
		t.Skipf("tree-validation.json not found: %v", err)
	}

	var vectors []treeValidationVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse tree-validation.json: %v", err)
	}

	supported := make([]int, 0, len(vectors))
	for i := range vectors {
		if ciphersuite.CipherSuite(vectors[i].CipherSuite) == ciphersuite.MLS128DHKEMP256 {
			supported = append(supported, i)
		}
	}
	if len(supported) == 0 {
		t.Fatalf("no supported vectors found in tree-validation.json")
	}

	for _, idx := range supported {
		v := vectors[idx]
		t.Run(fmt.Sprintf("vector-%d", idx), func(t *testing.T) {
			cs := ciphersuite.CipherSuite(v.CipherSuite)

			treeBytes := mustDecodeHexBytes(t, v.Tree)
			tree, err := unmarshalInteropTree(treeBytes, cs)
			if err != nil {
				t.Fatalf("UnmarshalTree: %v", err)
			}

			if len(tree.Nodes) < len(v.TreeHashes) {
				nodes := make([]treesync.Node, len(v.TreeHashes))
				copy(nodes, tree.Nodes)
				for j := len(tree.Nodes); j < len(nodes); j++ {
					nodes[j] = treesync.Node{State: treesync.NodeStateEmpty}
				}
				tree.Nodes = nodes
				tree.NumLeaves = uint32((len(nodes) + 1) / 2)
			}

			if len(v.TreeHashes) != len(tree.Nodes) {
				t.Fatalf("tree_hashes length mismatch: got %d, want %d", len(v.TreeHashes), len(tree.Nodes))
			}
			if len(v.Resolutions) != len(tree.Nodes) {
				t.Fatalf("resolutions length mismatch: got %d, want %d", len(v.Resolutions), len(tree.Nodes))
			}

			for j := range tree.Nodes {
				gotHash := tree.HashNode(treesync.NodeIndex(j))
				wantHash := mustDecodeHexBytes(t, v.TreeHashes[j])
				if !bytes.Equal(gotHash, wantHash) {
					t.Fatalf("tree hash mismatch at node %d\n  got  %x\n  want %x", j, gotHash, wantHash)
				}

				gotResolution := tree.Resolution(treesync.NodeIndex(j))
				wantResolution := v.Resolutions[j]
				if len(gotResolution) != len(wantResolution) {
					t.Fatalf("resolution length mismatch at node %d\n  got  %v\n  want %v", j, gotResolution, wantResolution)
				}
				for k, got := range gotResolution {
					if int(got) != wantResolution[k] {
						t.Fatalf("resolution mismatch at node %d element %d\n  got  %v\n  want %v", j, k, gotResolution, wantResolution)
					}
				}
			}
		})
	}
}
