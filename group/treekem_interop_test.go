package group

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/mls-go/ciphersuite"
	"github.com/mls-go/internal/tls"
	keypackages "github.com/mls-go/keypackages"
	"github.com/mls-go/treesync"
)

type treeKEMVector struct {
	CipherSuite             uint16            `json:"cipher_suite"`
	GroupID                 string            `json:"group_id"`
	Epoch                   uint64            `json:"epoch"`
	ConfirmedTranscriptHash string            `json:"confirmed_transcript_hash"`
	RatchetTree             string            `json:"ratchet_tree"`
	LeavesPrivate           []leafPrivate     `json:"leaves_private"`
	UpdatePaths             []updatePathEntry `json:"update_paths"`
}

type leafPrivate struct {
	Index          int              `json:"index"`
	EncryptionPriv string           `json:"encryption_priv"`
	SignaturePriv  string           `json:"signature_priv"`
	PathSecrets    []nodePathSecret `json:"path_secrets"`
}

type nodePathSecret struct {
	Node       int    `json:"node"`
	PathSecret string `json:"path_secret"`
}

type updatePathEntry struct {
	Sender        int       `json:"sender"`
	UpdatePath    string    `json:"update_path"`
	PathSecrets   []*string `json:"path_secrets"`
	CommitSecret  string    `json:"commit_secret"`
	TreeHashAfter string    `json:"tree_hash_after"`
}

type interopUpdatePathNode struct {
	EncryptionKey        []byte
	EncryptedPathSecrets []ciphersuite.HpkeCiphertext
}

type interopUpdatePath struct {
	LeafNode *treesync.LeafNodeData
	Nodes    []interopUpdatePathNode
}

// unmarshalInteropUpdatePath parses an UpdatePath in RFC 9420 §7.6 wire format:
//   - leaf_node: inline LeafNode (not VL-prefixed)
//   - nodes<V>: VL-prefixed; elements packed sequentially (not individually VL-wrapped)
//
// This differs from the internal format used by group/commit.go which VL-wraps
// both the leaf and each node for internal consistency.
func unmarshalInteropUpdatePath(data []byte) (*interopUpdatePath, error) {
	r := tls.NewReader(data)

	// leaf_node is inline — parse field-by-field directly from the stream.
	leafNode, err := treesync.UnmarshalLeafNodeDataFromReader(r)
	if err != nil {
		return nil, fmt.Errorf("reading leaf_node: %w", err)
	}

	// nodes<V>: outer VL-prefix, then UpdatePathNode structs packed inside.
	nodesData, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading nodes: %w", err)
	}
	nr := tls.NewReader(nodesData)
	nodes := make([]interopUpdatePathNode, 0)
	for nr.Remaining() > 0 {
		// UpdatePathNode: encryption_key<V> + encrypted_path_secret<V>
		encKey, err := nr.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading update path node encryption key: %w", err)
		}
		epsData, err := nr.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading encrypted path secrets: %w", err)
		}

		// encrypted_path_secret<V> is a list of HPKECiphertext: kem_output<V> + ciphertext<V>
		epsr := tls.NewReader(epsData)
		cts := make([]ciphersuite.HpkeCiphertext, 0)
		for epsr.Remaining() > 0 {
			kemOutput, err := epsr.ReadVLBytes()
			if err != nil {
				return nil, fmt.Errorf("reading kem_output: %w", err)
			}
			ciphertext, err := epsr.ReadVLBytes()
			if err != nil {
				return nil, fmt.Errorf("reading ciphertext: %w", err)
			}
			cts = append(cts, ciphersuite.HpkeCiphertext{KEMOutput: kemOutput, Ciphertext: ciphertext})
		}

		nodes = append(nodes, interopUpdatePathNode{EncryptionKey: encKey, EncryptedPathSecrets: cts})
	}

	return &interopUpdatePath{LeafNode: leafNode, Nodes: nodes}, nil
}

// applyUpdatePathToTree applies an UpdatePath to a cloned tree (RFC §12.4.2):
//  1. Replaces the sender's leaf with updatePath.leaf_node.
//  2. For each filtered parent in the sender's direct path: sets the new
//     encryption_key and clears unmerged_leaves.
//  3. Recomputes parent_hash fields down the direct path so that tree hashes
//     computed afterwards are correct.
func applyUpdatePathToTree(tree *treesync.RatchetTree, senderLeafIdx treesync.LeafIndex, up *interopUpdatePath) error {
	// 1. Replace sender's leaf.
	senderNodeIdx := treesync.LeafIndexToNodeIndex(senderLeafIdx)
	tree.Nodes[senderNodeIdx] = treesync.Node{State: treesync.NodeStatePresent, LeafData: up.LeafNode}

	// 2. Update filtered parent nodes (RFC §12.4.1 filtered direct path).
	directPath, _, levels := filteredDirectPathLevels(tree, senderLeafIdx)
	for m, level := range levels {
		if m >= len(up.Nodes) {
			break
		}
		nodeIdx := directPath[level+1]
		encKey, err := ecdh.P256().NewPublicKey(up.Nodes[m].EncryptionKey)
		if err != nil {
			return fmt.Errorf("parsing encryption key at filtered level %d: %w", m, err)
		}
		node := tree.Nodes[nodeIdx]
		node.State = treesync.NodeStatePresent
		node.EncryptionKey = encKey
		node.UnmergedLeaves = nil // RFC §12.4.2: clear unmerged_leaves
		tree.Nodes[nodeIdx] = node
	}

	// 3. Recompute parent_hash for direct path nodes (needed for correct tree hash).
	// The root has an empty parent_hash by convention; then we walk downward
	// from root to leaf, setting each node's parent_hash.
	//
	// RFC §7.9: blank nodes are transparent for parent_hash purposes. If the direct
	// parent is blank (no encryption key), the child inherits the parent's parent_hash
	// unchanged (the blank node "passes through" the binding from the nearest non-blank
	// ancestor). If the direct parent is non-blank, compute normally.
	if len(directPath) > 1 {
		rootIdx := tree.Root()
		tree.Nodes[rootIdx].ParentHash = []byte{}

		for k := len(directPath) - 2; k >= 0; k-- {
			childIdx := directPath[k]
			parentIdx := directPath[k+1]
			parent := &tree.Nodes[parentIdx]

			var parentHash []byte
			if parent.EncryptionKey != nil {
				// Non-blank parent: compute parent_hash normally.
				siblingIdx := tree.GetSibling(childIdx)
				siblingHash := tree.HashNode(siblingIdx)
				parentHash = treesync.ComputeParentHash(parent.EncryptionKey.Bytes(), parent.ParentHash, siblingHash)
			} else {
				// Blank parent: child inherits parent's parent_hash (transparent pass-through).
				parentHash = parent.ParentHash
			}

			// Only parent nodes store parent_hash in their Node struct;
			// the leaf's parent_hash is already baked into up.LeafNode.
			if !treesync.IsLeaf(childIdx) {
				tree.Nodes[childIdx].ParentHash = parentHash
			}
		}
	}

	return nil
}

// decryptInteropPathSecret decrypts the path secret for a receiver leaf from an
// UpdatePath, then derives forward to produce the commit_secret.
//
// RFC §12.4.1: the encrypted_path_secret for each copath resolution node uses
// EncryptWithLabel(pk, "UpdatePathNode", group_context, path_secret) where
// group_context is the current epoch's serialized GroupContext.
//
// Key selection per RFC §7.3 (Resolution):
//   - If resNode == receiver's leaf node: use the leaf's encryption_priv directly.
//   - If resNode is a parent node the receiver knows the path_secret for (from
//     leaves_private.path_secrets): derive node_key via DeriveSecret("node") +
//     DeriveKeyPair.
//
// Returns (pathSecret, commitSecret, decryptLevel, error) where decryptLevel is
// the index into levels[] at which decryption succeeded. Callers can use
// decryptLevel to accumulate path_secrets for subsequent update_paths.
func decryptInteropPathSecret(
	tree *treesync.RatchetTree,
	senderLeafIdx treesync.LeafIndex,
	receiverLeafIdx treesync.LeafIndex,
	up *interopUpdatePath,
	leafPrivKeyBytes []byte,
	receiverNodeSecrets map[int][]byte, // nodeIdx → path_secret from leaves_private
	gcBytes []byte, // serialized GroupContext for current epoch
	cs ciphersuite.CipherSuite,
) ([]byte, []byte, int, error) {
	_, copath, levels := filteredDirectPathLevels(tree, senderLeafIdx)
	receiverNodeIdx := treesync.LeafIndexToNodeIndex(receiverLeafIdx)

	for m, level := range levels {
		copathNode := copath[level]
		resolution := tree.Resolution(copathNode)

		for j, resNode := range resolution {
			// Determine the decryption private key for this resolution slot.
			var privKeyBytes []byte
			if resNode == receiverNodeIdx {
				// Receiver appears as their own leaf in the resolution.
				privKeyBytes = leafPrivKeyBytes
			} else if pathSecret, ok := receiverNodeSecrets[int(resNode)]; ok {
				// resNode is a parent node the receiver knows the path_secret for
				// (via unmerged_leaves). Derive the node's encryption private key:
				// node_secret = DeriveSecret(path_secret, "node")
				// node_priv   = DeriveKeyPair(node_secret)
				secret := ciphersuite.NewSecret(pathSecret)
				nodeSecret, err := secret.DeriveSecret(cs, "node")
				if err != nil {
					continue
				}
				privKey, err := ciphersuite.DeriveKeyPair(cs, nodeSecret.AsSlice())
				if err != nil {
					continue
				}
				privKeyBytes = privKey.Bytes()
			} else {
				// Receiver has no key for this slot — skip.
				continue
			}

			if m >= len(up.Nodes) || j >= len(up.Nodes[m].EncryptedPathSecrets) {
				continue
			}

			ct := up.Nodes[m].EncryptedPathSecrets[j]
			psBytes, err := ciphersuite.DecryptWithLabel(privKeyBytes, "UpdatePathNode", gcBytes, &ct, cs)
			if err != nil {
				continue
			}

			// Derive the path_secret forward through remaining filtered levels
			// to produce the commit_secret (RFC §12.4.1).
			secret := ciphersuite.NewSecret(psBytes)
			for k := m; k < len(levels); k++ {
				secret, err = secret.DeriveSecret(cs, "path")
				if err != nil {
					return nil, nil, 0, fmt.Errorf("derive path secret at step %d: %w", k, err)
				}
			}

			return psBytes, secret.AsSlice(), m, nil
		}
	}

	return nil, nil, 0, fmt.Errorf("receiver %d not in copath resolution", receiverLeafIdx)
}

func TestTreeKEMVectors(t *testing.T) {
	data, err := os.ReadFile("../testdata/mls-interop-testvectors/test-vectors/treekem.json")
	if err != nil {
		t.Skipf("treekem.json not found: %v", err)
	}

	var vectors []treeKEMVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse treekem.json: %v", err)
	}

	for i, v := range vectors {
		if ciphersuite.CipherSuite(v.CipherSuite) != ciphersuite.MLS128DHKEMP256 {
			continue
		}

		t.Run(fmt.Sprintf("vector-%d", i), func(t *testing.T) {
			cs := ciphersuite.CipherSuite(v.CipherSuite)

			// Parse the ratchet tree using the existing interop parser.
			// unmarshalInteropTree correctly handles non-power-of-2 leaf counts
			// (e.g. 6 leaves → 11 nodes, NOT expanded to 15).
			originalTree, err := unmarshalInteropTree(mustDecodeHexBytes(t, v.RatchetTree), cs)
			if err != nil {
				t.Fatalf("UnmarshalTree: %v", err)
			}

			// Build per-leaf private key and node-secret maps.
			leafPrivByIndex := make(map[int][]byte, len(v.LeavesPrivate))
			leafNodeSecretsByIndex := make(map[int]map[int][]byte, len(v.LeavesPrivate))
			for _, lp := range v.LeavesPrivate {
				leafPrivByIndex[lp.Index] = mustDecodeHexBytes(t, lp.EncryptionPriv)
				nodeSecrets := make(map[int][]byte, len(lp.PathSecrets))
				for _, ps := range lp.PathSecrets {
					nodeSecrets[ps.Node] = mustDecodeHexBytes(t, ps.PathSecret)
				}
				leafNodeSecretsByIndex[lp.Index] = nodeSecrets
			}

			// baseGC holds all GroupContext fields except tree_hash, which differs
			// per update_path (RFC §12.4.1 uses the PROVISIONAL GroupContext that
			// includes the post-commit tree_hash, i.e. tree_hash_after).
			baseGCGroupID := NewGroupID(mustDecodeHexBytes(t, v.GroupID))
			baseGCConfirmedTranscript := mustDecodeHexBytes(t, v.ConfirmedTranscriptHash)

			for upIndex, entry := range v.UpdatePaths {
				up, err := unmarshalInteropUpdatePath(mustDecodeHexBytes(t, entry.UpdatePath))
				if err != nil {
					t.Fatalf("update_path[%d] parse: %v", upIndex, err)
				}

				// Apply the UpdatePath to a fresh clone of the original tree.
				treeCopy := originalTree.Clone()
				senderLeafIdx := treesync.LeafIndex(entry.Sender)
				if err := applyUpdatePathToTree(treeCopy, senderLeafIdx, up); err != nil {
					t.Fatalf("apply update_path[%d]: %v", upIndex, err)
				}

				// Verify tree_hash_after.
				if got, want := treeCopy.TreeHash(), mustDecodeHexBytes(t, entry.TreeHashAfter); !bytes.Equal(got, want) {
					t.Fatalf("tree_hash_after mismatch for update_path[%d]\n  got  %x\n  want %x", upIndex, got, want)
				}

				// RFC §12.4.1: UpdatePathNode encryption uses the PROVISIONAL GroupContext
				// which includes tree_hash_after (the tree hash after the commit).
				gcBytes := (&GroupContext{
					Version:                 keypackages.MLS10,
					CipherSuite:             cs,
					GroupID:                 baseGCGroupID,
					Epoch:                   NewGroupEpoch(v.Epoch),
					TreeHash:                treeCopy.TreeHash(),
					ConfirmedTranscriptHash: baseGCConfirmedTranscript,
					Extensions:              nil,
				}).Marshal()

				// Get the sender's direct path and levels for path_secret accumulation.
				directPath, _, levels := filteredDirectPathLevels(originalTree, senderLeafIdx)

				// Verify path_secret and commit_secret for each receiver leaf.
				for leafIdx, expected := range entry.PathSecrets {
					if leafIdx == entry.Sender || expected == nil {
						continue
					}

					privKeyBytes, ok := leafPrivByIndex[leafIdx]
					if !ok {
						t.Fatalf("missing private key for leaf %d", leafIdx)
					}

					pathSecret, commitSecret, mIdx, err := decryptInteropPathSecret(
						originalTree,
						senderLeafIdx,
						treesync.LeafIndex(leafIdx),
						up,
						privKeyBytes,
						leafNodeSecretsByIndex[leafIdx],
						gcBytes,
						cs,
					)
					if err != nil {
						t.Fatalf("decrypt path secret update_path[%d] receiver %d: %v", upIndex, leafIdx, err)
					}

					wantPathSecret := mustDecodeHexBytes(t, *expected)
					if !bytes.Equal(pathSecret, wantPathSecret) {
						t.Fatalf("path_secret mismatch update_path[%d] receiver %d\n  got  %x\n  want %x", upIndex, leafIdx, pathSecret, wantPathSecret)
					}

					wantCommitSecret := mustDecodeHexBytes(t, entry.CommitSecret)
					if !bytes.Equal(commitSecret, wantCommitSecret) {
						t.Fatalf("commit_secret mismatch update_path[%d] receiver %d\n  got  %x\n  want %x", upIndex, leafIdx, commitSecret, wantCommitSecret)
					}

					// Accumulate path_secrets so subsequent update_paths can decrypt via
					// parent node keys derived from these secrets (RFC §12.4.1).
					// path_secret[mIdx]   → directPath[levels[mIdx]+1]
					// path_secret[mIdx+1] = DeriveSecret(path_secret[mIdx], "path") → directPath[levels[mIdx+1]+1]
					// etc.
					// Only store if not already present to avoid overwriting correct initial values.
					nodeSecrets := leafNodeSecretsByIndex[leafIdx]
					if nodeSecrets == nil {
						nodeSecrets = make(map[int][]byte)
						leafNodeSecretsByIndex[leafIdx] = nodeSecrets
					}
					curSecret := ciphersuite.NewSecret(pathSecret)
					for k := mIdx; k < len(levels); k++ {
						nodeIdx := directPath[levels[k]+1]
						if _, exists := nodeSecrets[int(nodeIdx)]; !exists {
							nodeSecrets[int(nodeIdx)] = curSecret.AsSlice()
						}
						if k < len(levels)-1 {
							curSecret, err = curSecret.DeriveSecret(cs, "path")
							if err != nil {
								t.Fatalf("accumulate path secret at step %d: %v", k, err)
							}
						}
					}
				}
			}
		})
	}
}
