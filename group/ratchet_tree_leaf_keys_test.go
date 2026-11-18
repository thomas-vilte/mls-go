package group

import (
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/schedule"
	"github.com/thomas-vilte/mls-go/treesync"
)

// leafKeyWorld is a Welcome whose ratchet tree is
//
//	leaf 0 = mallory (encryption_key = carol's when duplicateCarolKey is set; the LeafNode is signed by mallory)
//	leaf 1 = alice   (signer of the GroupInfo)
//	leaf 2 = carol   (the joiner; her KeyPackage has that encryption_key)
//	leaf 3 = blank, and every parent node blank
type leafKeyWorld struct {
	cs      ciphersuite.CipherSuite
	tree    *treesync.RatchetTree
	gc      *GroupContext
	welcome *Welcome
	carol   *testUser
}

func newLeafKeyWorld(t *testing.T, duplicateCarolKey bool) *leafKeyWorld {
	t.Helper()
	cs := ciphersuite.MLS128DHKEMP256
	alice := newTestUser(t, "alice")
	carol := newTestUser(t, "carol")
	mallory := newTestUser(t, "mallory")

	malloryLeaf := keyPackageLeafToTreeSync(mallory.kp.LeafNode)
	if duplicateCarolKey {
		malloryLeaf.EncryptionKey = append([]byte(nil), carol.kp.LeafNode.EncryptionKey...)
		// The signature of a LeafNode covers encryption_key, so the leaf is signed again with mallory's
		// signature key. It stays valid on its own.
		sig, err := ciphersuite.SignWithLabel(mallory.sigPriv, "LeafNodeTBS", malloryLeaf.MarshalTBS())
		if err != nil {
			t.Fatalf("signing mallory's LeafNode: %v", err)
		}
		malloryLeaf.Signature = sig.AsSlice()
	}

	tree := treesync.NewRatchetTree(4, cs)
	for idx, leaf := range []*treesync.LeafNodeData{
		malloryLeaf,
		keyPackageLeafToTreeSync(alice.kp.LeafNode),
		keyPackageLeafToTreeSync(carol.kp.LeafNode),
	} {
		if err := tree.SetLeaf(treesync.LeafIndex(idx), *leaf); err != nil {
			t.Fatalf("SetLeaf(%d): %v", idx, err)
		}
	}

	groupID, err := NewGroupIDRandom()
	if err != nil {
		t.Fatalf("NewGroupIDRandom: %v", err)
	}
	confirmedHash, err := ciphersuite.NewSecretRandomCS(cs)
	if err != nil {
		t.Fatalf("confirmed_transcript_hash: %v", err)
	}
	gc := &GroupContext{
		Version:                 keypackages.MLS10,
		CipherSuite:             cs,
		GroupID:                 groupID,
		Epoch:                   NewGroupEpoch(1),
		TreeHash:                tree.TreeHash(),
		ConfirmedTranscriptHash: confirmedHash.AsSlice(),
	}

	// The epoch secrets are derived as the joiner derives them.
	joinerSecret, err := ciphersuite.NewSecretRandomCS(cs)
	if err != nil {
		t.Fatalf("joiner_secret: %v", err)
	}
	ks := schedule.NewKeySchedule(cs, ciphersuite.ZeroSecretCS(cs))
	ks.SetJoinerSecret(ciphersuite.NewSecretForCS(cs, joinerSecret.AsSlice()))
	if _, err := ks.ComputePskSecret(nil); err != nil {
		t.Fatalf("ComputePskSecret: %v", err)
	}
	if _, err := ks.ComputeEpochSecret(gc.Marshal()); err != nil {
		t.Fatalf("ComputeEpochSecret: %v", err)
	}
	epochSecrets, err := ks.DeriveEpochSecrets()
	if err != nil {
		t.Fatalf("DeriveEpochSecrets: %v", err)
	}
	confTag := schedule.ComputeConfirmationTag(cs, epochSecrets.ConfirmationKey.AsSlice(), gc.ConfirmedTranscriptHash)

	// alice (leaf 1) signs the GroupInfo. createWelcome uses the tree and the GroupContext as they are in
	// the state of the group.
	committer := &Group{
		groupID:         groupID,
		epoch:           gc.Epoch,
		cipherSuite:     cs,
		groupContext:    gc,
		ratchetTree:     tree,
		ownLeafIndex:    1,
		epochSecrets:    epochSecrets,
		confirmationTag: confTag,
		state:           StateOperational,
	}
	welcome, err := committer.createWelcome(
		[]*keypackages.KeyPackage{carol.kp}, joinerSecret, nil, alice.sigPriv, nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("createWelcome: %v", err)
	}
	return &leafKeyWorld{cs: cs, tree: tree, gc: gc, welcome: welcome, carol: carol}
}

// TestRatchetTreeWithUniqueLeafKeysIsAccepted checks that a tree whose leaves have distinct encryption keys
// validates, and that the joiner takes the leaf that matches her KeyPackage.
func TestRatchetTreeWithUniqueLeafKeysIsAccepted(t *testing.T) {
	w := newLeafKeyWorld(t, false)
	if err := validateJoinedRatchetTree(w.tree, w.gc, w.cs); err != nil {
		t.Fatalf("validateJoinedRatchetTree refused a valid tree: %v", err)
	}
	joined, err := JoinFromWelcome(w.welcome, w.carol.kp, w.carol.priv, nil)
	if err != nil {
		t.Fatalf("JoinFromWelcome: %v", err)
	}
	if joined.ownLeafIndex != 2 {
		t.Fatalf("ownLeafIndex = %d, want 2", joined.ownLeafIndex)
	}
}

// TestValidateJoinedRatchetTreeRejectsDuplicateLeafKey checks that a tree with two leaves that share an
// encryption_key is refused with ErrDuplicateLeafEncryptionKey (RFC 9420 section 7.3 requires the key to be
// unique among the members). Each leaf is valid on its own, so only the uniqueness can refuse the tree.
func TestValidateJoinedRatchetTreeRejectsDuplicateLeafKey(t *testing.T) {
	w := newLeafKeyWorld(t, true)
	for _, idx := range []treesync.LeafIndex{0, 2} {
		leaf := w.tree.GetLeaf(idx)
		if err := treesync.ValidateLeafNodeStructureWithContext(leaf.LeafData, w.cs, w.gc.GroupID.AsSlice(), uint32(idx)); err != nil {
			t.Fatalf("leaf %d is not valid on its own: %v", idx, err)
		}
	}
	err := validateJoinedRatchetTree(w.tree, w.gc, w.cs)
	if !errors.Is(err, ErrDuplicateLeafEncryptionKey) {
		t.Fatalf("validateJoinedRatchetTree err = %v, want ErrDuplicateLeafEncryptionKey", err)
	}
}

// TestJoinFromWelcomeRejectsTreeWithDuplicateLeafKey checks that a joiner whose encryption_key matches two
// leaves of the tree refuses the Welcome. She used to take the first match, which was mallory's leaf 0 and not
// her own leaf 2. The tree validation refuses the Welcome first, and the check of the own leaf in JoinFromWelcome
// is a second guard behind it.
func TestJoinFromWelcomeRejectsTreeWithDuplicateLeafKey(t *testing.T) {
	w := newLeafKeyWorld(t, true)
	joined, err := JoinFromWelcome(w.welcome, w.carol.kp, w.carol.priv, nil)
	if err == nil {
		t.Fatalf("JoinFromWelcome joined with ownLeafIndex = %d, want the Welcome to be refused", joined.ownLeafIndex)
	}
	if !errors.Is(err, ErrDuplicateLeafEncryptionKey) {
		t.Fatalf("JoinFromWelcome err = %v, want ErrDuplicateLeafEncryptionKey", err)
	}
}
