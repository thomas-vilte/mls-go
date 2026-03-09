package treesync

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/openmls/go/credentials"
)

func testLeaf(t *testing.T, id string) LeafNodeData {
	t.Helper()
	cred, _, err := credentials.GenerateCredentialWithKey([]byte(id))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(%s): %v", id, err)
	}
	return LeafNodeData{
		EncryptionKey: []byte(id + "-enc"),
		SignatureKey: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     big.NewInt(1),
			Y:     big.NewInt(2),
		},
		Credential: cred.Credential,
		Capabilities: &LeafNodeCapabilities{
			ProtocolVersions: []uint16{1},
			CipherSuites:     []uint16{2},
		},
		Lifetime:  &LeafNodeLifetime{},
		Signature: []byte{1},
	}
}

func setParentHashChain(t *testing.T, tree *RatchetTree, leafIdx LeafIndex) {
	t.Helper()
	path := tree.DirectPath(leafIdx)
	if len(path) <= 1 {
		return
	}
	rootIdx := tree.Root()
	tree.Nodes[rootIdx].ParentHash = []byte{}
	for i := len(path) - 2; i >= 0; i-- {
		nodeIdx := path[i]
		parentIdx, err := tree.Parent(nodeIdx)
		if err != nil {
			t.Fatalf("Parent(%d): %v", nodeIdx, err)
		}
		parent := &tree.Nodes[parentIdx]
		siblingIdx := tree.GetSibling(nodeIdx)
		siblingHash := tree.HashNode(siblingIdx)
		var parentKey []byte
		if parent.EncryptionKey != nil {
			parentKey = parent.EncryptionKey.Bytes()
		}
		ph := ComputeParentHash(parentKey, parent.ParentHash, siblingHash)
		if IsLeaf(nodeIdx) {
			if tree.Nodes[nodeIdx].LeafData == nil {
				t.Fatalf("leaf %d has nil LeafData", nodeIdx)
			}
			tree.Nodes[nodeIdx].LeafData.ParentHash = ph
		} else {
			tree.Nodes[nodeIdx].ParentHash = ph
		}
	}
}
func TestRatchetTree_VerifyParentHashes_FullChain(t *testing.T) {
	tree := NewRatchetTree(4)
	for i, id := range []string{"a", "b", "c", "d"} {
		leaf := testLeaf(t, id)
		if err := tree.SetLeaf(LeafIndex(i), leaf); err != nil {
			t.Fatalf("SetLeaf(%d): %v", i, err)
		}
	}
	// Mark intermediate/root parents as present with deterministic parent hashes.
	for idx := range tree.Nodes {
		nodeIdx := NodeIndex(idx)
		if IsLeaf(nodeIdx) {
			continue
		}
		tree.Nodes[idx].State = NodeStatePresent
		tree.Nodes[idx].ParentHash = []byte{}
	}
	setParentHashChain(t, tree, 0)
	if err := tree.VerifyParentHashes(0); err != nil {
		t.Fatalf("VerifyParentHashes(0): %v", err)
	}
}
func TestRatchetTree_VerifyParentHashes_DetectsDeepMismatch(t *testing.T) {
	tree := NewRatchetTree(4)
	for i, id := range []string{"a", "b", "c", "d"} {
		leaf := testLeaf(t, id)
		if err := tree.SetLeaf(LeafIndex(i), leaf); err != nil {
			t.Fatalf("SetLeaf(%d): %v", i, err)
		}
	}
	for idx := range tree.Nodes {
		nodeIdx := NodeIndex(idx)
		if IsLeaf(nodeIdx) {
			continue
		}
		tree.Nodes[idx].State = NodeStatePresent
		tree.Nodes[idx].ParentHash = []byte{}
	}
	setParentHashChain(t, tree, 0)
	// Corrupt a higher-level parent hash in the chain, not just the leaf-level one.
	path := tree.DirectPath(0)
	if len(path) < 3 {
		t.Fatalf("direct path too short: %d", len(path))
	}
	deepNodeIdx := path[1]
	tree.Nodes[deepNodeIdx].ParentHash = []byte("corrupt")
	if err := tree.VerifyParentHashes(0); err == nil {
		t.Fatal("expected parent hash verification failure")
	}
}
