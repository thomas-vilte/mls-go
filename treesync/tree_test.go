package treesync

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/thomas-vilte/mls-go/credentials"
)

func testLeaf(t *testing.T, id string) LeafNodeData {
	t.Helper()
	cred, _, err := credentials.GenerateCredentialWithKey([]byte(id))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(%s): %v", id, err)
	}
	sigKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return LeafNodeData{
		EncryptionKey: []byte(id + "-enc"),
		SignatureKey:  &sigKey.PublicKey,
		Credential:    cred.Credential,
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
		ph := ComputeParentHash(parentKey, parent.ParentHash, siblingHash, sha256.New)
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

// setFullTreeParentHashChain chains parent hashes for every non-blank node in
// the tree, descending top-down from the root. Unlike setParentHashChain
// (which only chains a single leaf's direct path, leaving sibling branches
// with placeholder values), this produces a tree where every non-blank
// parent node is genuinely parent-hash valid — the scenario VerifyAllParentHashes
// is meant to accept.
func setFullTreeParentHashChain(t *testing.T, tree *RatchetTree) {
	t.Helper()
	rootIdx := tree.Root()
	if tree.Nodes[rootIdx].State != NodeStatePresent {
		return
	}
	tree.Nodes[rootIdx].ParentHash = []byte{}

	var descend func(nodeIdx NodeIndex)
	descend = func(nodeIdx NodeIndex) {
		node := &tree.Nodes[nodeIdx]
		left, err := tree.LeftChild(nodeIdx)
		if err != nil {
			t.Fatalf("LeftChild(%d): %v", nodeIdx, err)
		}
		right, err := tree.RightChild(nodeIdx)
		if err != nil {
			t.Fatalf("RightChild(%d): %v", nodeIdx, err)
		}
		for _, pair := range [][2]NodeIndex{{left, right}, {right, left}} {
			child, sibling := pair[0], pair[1]
			if tree.Nodes[child].State != NodeStatePresent {
				continue
			}
			siblingHash := tree.HashNode(sibling)
			var parentKey []byte
			if node.EncryptionKey != nil {
				parentKey = node.EncryptionKey.Bytes()
			}
			ph := ComputeParentHash(parentKey, node.ParentHash, siblingHash, sha256.New)
			if IsLeaf(child) {
				if tree.Nodes[child].LeafData == nil {
					t.Fatalf("leaf %d has nil LeafData", child)
				}
				tree.Nodes[child].LeafData.ParentHash = ph
			} else {
				tree.Nodes[child].ParentHash = ph
				descend(child)
			}
		}
	}
	descend(rootIdx)
}

func TestRatchetTree_VerifyAllParentHashes_FullyChainedTree(t *testing.T) {
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
	setFullTreeParentHashChain(t, tree)
	if err := tree.VerifyAllParentHashes(); err != nil {
		t.Fatalf("VerifyAllParentHashes(): %v", err)
	}
}

func TestRatchetTree_VerifyAllParentHashes_SingleLeafVacuouslyValid(t *testing.T) {
	tree := NewRatchetTree(1)
	if err := tree.SetLeaf(0, testLeaf(t, "solo")); err != nil {
		t.Fatalf("SetLeaf(0): %v", err)
	}
	// A single-leaf tree has no parent nodes at all: nothing to verify.
	if err := tree.VerifyAllParentHashes(); err != nil {
		t.Fatalf("VerifyAllParentHashes() on single-leaf tree: %v", err)
	}
}

// TestRatchetTree_VerifyAllParentHashes_DetectsUncoveredBranch is the scenario
// that motivates VerifyAllParentHashes over VerifyParentHashes(leafIdx) at join
// time: setParentHashChain only chains leaf 0's branch, leaving the sibling
// branch (parent(2,3)) as a non-blank parent node with a never-computed
// parent_hash. VerifyParentHashes(0) — which only walks leaf 0's own direct
// path — cannot see that other branch and reports success. A joiner receiving
// this tree fresh (no prior verified history) must catch it; VerifyAllParentHashes
// does, by requiring every non-blank parent to be covered by some leaf's chain.
func TestRatchetTree_VerifyAllParentHashes_DetectsUncoveredBranch(t *testing.T) {
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

	if err := tree.VerifyParentHashes(0); err != nil {
		t.Fatalf("VerifyParentHashes(0) should pass (leaf 0's own branch is valid), got: %v", err)
	}
	if err := tree.VerifyAllParentHashes(); err == nil {
		t.Fatal("VerifyAllParentHashes() should reject the uncovered sibling branch, but passed")
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
