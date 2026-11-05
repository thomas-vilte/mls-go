package group

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/treesync"
)

// Tests for the private keys that a commit stages: the path keys of a rejected or discarded commit, the leaf
// key of an own Update, the PSK cache, and a pending commit that another commit supersedes.

// commitAndMerge has committer create a Commit from its pending proposals and merge it. It returns the
// signed content that the other members process.
func commitAndMerge(t *testing.T, committer *Group, by joinTestMember) *framing.AuthenticatedContent {
	t.Helper()
	staged, err := committer.Commit(by.sig, by.sig.PublicKey(), nil)
	if err != nil {
		t.Fatalf("Commit by %s: %v", by.name, err)
	}
	ac := staged.AuthenticatedContent()
	if err := committer.MergeCommit(staged); err != nil {
		t.Fatalf("MergeCommit by %s: %v", by.name, err)
	}
	return ac
}

// fullStateFingerprint captures the state that a rejected commit must not change. It includes the fields
// that MarshalState does not serialize: the epoch history, the proposal refs, the key maps, the key
// schedule and the pending commit.
func fullStateFingerprint(t *testing.T, g *Group) string {
	t.Helper()
	state, err := g.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState: %v", err)
	}
	stateSum := sha256.Sum256(state)

	paths := make([]string, 0, len(g.pathNodePrivKeys))
	for idx, key := range g.pathNodePrivKeys {
		paths = append(paths, fmt.Sprintf("%d=%x", idx, key))
	}
	sort.Strings(paths)

	members := make([]string, 0, len(g.members))
	for idx, m := range g.members {
		members = append(members, fmt.Sprintf("%d:%v", idx, m != nil && m.Active))
	}
	sort.Strings(members)

	var initSecret []byte
	if g.keySchedule != nil && g.keySchedule.InitSecret() != nil {
		initSecret = g.keySchedule.InitSecret().AsSlice()
	}

	return fmt.Sprintf("epoch=%d state=%v marshal=%x hist=%d byref=%d store=%d cachedpsk=%d pendingLeaf=%x pendingUpd=%x myLeaf=%x path=%v members=%v conf=%x interim=%x pendingCommit=%v lastCommitted=%d init=%x tree=%x",
		g.epoch.AsUint64(), g.state, stateSum[:], len(g.epochHistory), len(g.proposalByRef), len(g.proposals.Proposals),
		len(g.cachedPsks), g.pendingLeafKey, g.pendingUpdatePrivKey, g.myLeafEncryptionKey, paths, members,
		g.confirmationTag, g.interimTranscriptHash, g.pendingCommit != nil, len(g.lastCommittedProposals), initSecret,
		g.ratchetTree.TreeHash())
}

// withFlippedConfirmationTag returns a copy of ac whose confirmation_tag has one bit flipped.
func withFlippedConfirmationTag(ac *framing.AuthenticatedContent) *framing.AuthenticatedContent {
	tampered := *ac
	tampered.Auth.ConfirmationTag = append([]byte(nil), ac.Auth.ConfirmationTag...)
	tampered.Auth.ConfirmationTag[0] ^= 0x01
	return &tampered
}

// TestRejectedCommitLeavesNoPathKeys checks that a commit refused for an invalid confirmation_tag leaves no
// path private key of its own. Before the tampered Commit is refused, bob's key map is set to an empty map that
// the test keeps. A refused Commit must leave no key of its own in that map, and the honest Commit must still be
// accepted afterwards.
func TestRejectedCommitLeavesNoPathKeys(t *testing.T) {
	alice := newJoinTestMember(t, "Alice")
	bob := newJoinTestMember(t, "Bob")
	ag := createJoinTestGroup(t, alice)
	if _, err := ag.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	bg := joinThroughWelcome(t, ag, alice, bob)[0]

	staged, err := ag.Commit(alice.sig, alice.sig.PublicKey(), nil)
	if err != nil {
		t.Fatalf("Commit by alice: %v", err)
	}
	legit := staged.AuthenticatedContent()
	sender := treesync.LeafIndex(ag.ownLeafIndex)

	live := map[treesync.NodeIndex][]byte{}
	bg.pathNodePrivKeys = live
	err = bg.ProcessReceivedCommit(withFlippedConfirmationTag(legit), sender, bg.MyLeafEncryptionKey())
	if !errors.Is(err, ErrConfirmationTagMismatch) {
		t.Fatalf("tampered commit: err = %v, want ErrConfirmationTagMismatch", err)
	}
	for idx, key := range live {
		for _, b := range key {
			if b != 0 {
				t.Errorf("path private key of node %d derived by a refused commit is left in the group (%d bytes)", idx, len(key))
				break
			}
		}
	}

	if err := bg.ProcessReceivedCommit(legit, sender, bg.MyLeafEncryptionKey()); err != nil {
		t.Fatalf("honest commit after the refused one: %v", err)
	}
	if err := ag.MergeCommit(staged); err != nil {
		t.Fatalf("MergeCommit by alice: %v", err)
	}
	assertSameExport(t, ag, bg)
}

// TestRejectedCommitLeavesFullStateUnchanged checks that a refused Commit leaves the whole state of bob
// unchanged. The fingerprint covers the fields that MarshalState does not serialize, and it must change when
// the honest Commit is accepted.
func TestRejectedCommitLeavesFullStateUnchanged(t *testing.T) {
	alice := newJoinTestMember(t, "Alice")
	bob := newJoinTestMember(t, "Bob")
	ag := createJoinTestGroup(t, alice)
	if _, err := ag.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	bg := joinThroughWelcome(t, ag, alice, bob)[0]

	staged, err := ag.Commit(alice.sig, alice.sig.PublicKey(), nil)
	if err != nil {
		t.Fatalf("Commit by alice: %v", err)
	}
	legit := staged.AuthenticatedContent()
	sender := treesync.LeafIndex(ag.ownLeafIndex)

	before := fullStateFingerprint(t, bg)
	if err := bg.ProcessReceivedCommit(withFlippedConfirmationTag(legit), sender, bg.MyLeafEncryptionKey()); !errors.Is(err, ErrConfirmationTagMismatch) {
		t.Fatalf("tampered commit: err = %v, want ErrConfirmationTagMismatch", err)
	}
	if after := fullStateFingerprint(t, bg); after != before {
		t.Errorf("a refused commit changed bob's state:\nbefore: %s\nafter:  %s", before, after)
	}

	// Control: the honest commit does change the fingerprint, so the comparison above means something.
	if err := bg.ProcessReceivedCommit(legit, sender, bg.MyLeafEncryptionKey()); err != nil {
		t.Fatalf("honest commit: %v", err)
	}
	if fullStateFingerprint(t, bg) == before {
		t.Error("an accepted commit left the fingerprint unchanged, so the fingerprint is blind")
	}
}

// TestDiscardedCommitKeepsPathKeysOfCurrentEpoch checks that discarding a Commit keeps the path keys of the
// current epoch. Alice derives the path keys of a Commit and then discards it (DiscardPendingCommit). The keys
// of the current epoch, which the tree still uses, must stay in place: charlie's Commit, which encrypts to them,
// must still be processed by alice.
func TestDiscardedCommitKeepsPathKeysOfCurrentEpoch(t *testing.T) {
	alice := newJoinTestMember(t, "Alice")
	bob := newJoinTestMember(t, "Bob")
	charlie := newJoinTestMember(t, "Charlie")
	ag := createJoinTestGroup(t, alice)
	for _, u := range []joinTestMember{bob, charlie} {
		if _, err := ag.AddMember(u.kp); err != nil {
			t.Fatalf("AddMember(%s): %v", u.name, err)
		}
	}
	joined := joinThroughWelcome(t, ag, alice, bob, charlie)
	bg, cg := joined[0], joined[1]

	// Bob's Commit gives alice the private keys of the nodes on the path she shares with charlie.
	bobAC := commitAndMerge(t, bg, bob)
	receiveCommitFrom(t, ag, "Alice", bobAC, bg.ownLeafIndex)
	receiveCommitFrom(t, cg, "Charlie", bobAC, bg.ownLeafIndex)

	if _, err := ag.Commit(alice.sig, alice.sig.PublicKey(), nil); err != nil {
		t.Fatalf("Alice Commit: %v", err)
	}
	if err := ag.DiscardPendingCommit(); err != nil {
		t.Fatalf("DiscardPendingCommit: %v", err)
	}

	ac := commitAndMerge(t, cg, charlie)
	receiveCommitFrom(t, bg, "Bob", ac, cg.ownLeafIndex)
	receiveCommitFrom(t, ag, "Alice", ac, cg.ownLeafIndex)
	assertSameExport(t, ag, cg)
}

// TestRejectedCommitKeepsOwnUpdateLeafKey checks that a refused commit does not replace the leaf key of an own
// Update. Alice has a pending Update (SelfUpdate). Bob commits Alice's Update by reference, and alice refuses
// the Commit because its confirmation_tag is wrong. The refusal must not replace the leaf key that alice's
// caller holds, and the pending key must stay pending. The honest Commit then installs the pending key as the
// leaf key (RFC 9420 §12.4.3.3).
func TestRejectedCommitKeepsOwnUpdateLeafKey(t *testing.T) {
	m := newUpdateProposalTestMembers(t)
	_, pm := newSignedUpdateMessage(t, m.aliceGroup, m.alice.sigPriv)
	for _, g := range []*Group{m.bobGroup, m.charlieGroup} {
		if err := g.ProcessPublicMessage(pm); err != nil {
			t.Fatalf("ProcessPublicMessage(alice update): %v", err)
		}
	}
	sc, err := m.bobGroup.Commit(m.bob.sigPriv, m.bob.sigPub, nil)
	if err != nil {
		t.Fatalf("Commit(bob) with alice's Update by reference: %v", err)
	}

	leafHeld := m.aliceGroup.myLeafEncryptionKey // the slice that alice's caller holds
	leafBefore := append([]byte(nil), leafHeld...)
	pendingBefore := append([]byte(nil), m.aliceGroup.pendingUpdatePrivKey...)
	if len(pendingBefore) == 0 {
		t.Fatal("SETUP: alice has no pending Update key")
	}
	bobLeaf := treesync.LeafIndex(m.bobGroup.ownLeafIndex)

	err = m.aliceGroup.ProcessReceivedCommit(withFlippedConfirmationTag(sc.authenticatedContent), bobLeaf, m.aliceGroup.myLeafEncryptionKey)
	if !errors.Is(err, ErrConfirmationTagMismatch) {
		t.Fatalf("tampered commit: err = %v, want ErrConfirmationTagMismatch", err)
	}
	if !bytes.Equal(leafHeld, leafBefore) {
		t.Error("a refused commit erased the leaf key that alice's caller holds")
	}
	if !bytes.Equal(m.aliceGroup.myLeafEncryptionKey, leafBefore) {
		t.Error("a refused commit replaced alice's leaf key")
	}
	if !bytes.Equal(m.aliceGroup.pendingUpdatePrivKey, pendingBefore) {
		t.Error("a refused commit changed alice's pending Update key")
	}

	if err := m.aliceGroup.ProcessReceivedCommit(sc.authenticatedContent, bobLeaf, m.aliceGroup.myLeafEncryptionKey); err != nil {
		t.Fatalf("honest commit after the refused one: %v", err)
	}
	if !bytes.Equal(m.aliceGroup.myLeafEncryptionKey, pendingBefore) {
		t.Error("the confirmed commit did not install alice's pending Update key as her leaf key")
	}
	if m.aliceGroup.pendingUpdatePrivKey != nil {
		t.Error("the pending Update key was not released once it became the leaf key")
	}
}

// TestFailedCommitLeavesNoStagedKeys checks that a Commit that fails after its UpdatePath is built leaves no
// staged key. The PreSharedKey proposal names a PSK that is not loaded, so the failure comes after the path keys
// are derived. The failed Commit must leave no staged leaf key and no path key behind. Charlie's later Commit
// must still be processed by alice, who is in the middle of the path that Charlie encrypts to.
func TestFailedCommitLeavesNoStagedKeys(t *testing.T) {
	alice := newJoinTestMember(t, "Alice")
	bob := newJoinTestMember(t, "Bob")
	charlie := newJoinTestMember(t, "Charlie")
	ag := createJoinTestGroup(t, alice)
	for _, u := range []joinTestMember{bob, charlie} {
		if _, err := ag.AddMember(u.kp); err != nil {
			t.Fatalf("AddMember(%s): %v", u.name, err)
		}
	}
	joined := joinThroughWelcome(t, ag, alice, bob, charlie)
	bg, cg := joined[0], joined[1]
	bobAC := commitAndMerge(t, bg, bob)
	receiveCommitFrom(t, ag, "Alice", bobAC, bg.ownLeafIndex)
	receiveCommitFrom(t, cg, "Charlie", bobAC, bg.ownLeafIndex)

	pskProp := NewPreSharedKeyProposal(1, []byte("unloaded-psk"))
	pskProp.PreSharedKey.PskID.Nonce = bytes.Repeat([]byte{0x5a}, 32)
	ag.proposals.AddProposal(pskProp, ag.ownLeafIndex)
	if _, err := ag.Commit(alice.sig, alice.sig.PublicKey(), nil); err == nil {
		t.Fatal("SETUP: a Commit with an unloaded PSK succeeded")
	}
	if ag.pendingLeafKey != nil {
		t.Error("a failed Commit left its staged leaf key in the group")
	}
	if ag.state != StateOperational {
		t.Errorf("state after the failed Commit = %v, want StateOperational", ag.state)
	}

	ag.ClearProposals()
	ac := commitAndMerge(t, cg, charlie)
	receiveCommitFrom(t, ag, "Alice", ac, cg.ownLeafIndex)
	receiveCommitFrom(t, bg, "Bob", ac, cg.ownLeafIndex)
	assertSameExport(t, ag, cg)
}

// TestCachedPskAccessIsLocked checks that LoadPsk and the commit snapshot can run at the same time. Both touch
// the PSK cache, which pskMu guards. Under the race detector an unlocked read of the cache fails this test.
func TestCachedPskAccessIsLocked(t *testing.T) {
	g := createJoinTestGroup(t, newJoinTestMember(t, "Alice"))
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			g.LoadPsk([]byte{byte(i), byte(i >> 8)}, []byte("external-psk"))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			_ = g.snapshotForCommit()
		}
	}()
	wg.Wait()
	if len(g.cachedPsks) != 500 {
		t.Errorf("cached PSKs = %d, want 500", len(g.cachedPsks))
	}
}

// TestReceivedCommitSupersedesPendingCommit checks that a commit of another member, merged while this member
// has a Commit pending, supersedes the pending one (RFC 9420 §14). The leaf key that the pending Commit staged
// must not become the member's leaf key. Alice's leaf key must stay the one the tree uses, and bob's next
// Commit, which encrypts to that leaf, must still be processed.
func TestReceivedCommitSupersedesPendingCommit(t *testing.T) {
	alice := newJoinTestMember(t, "Alice")
	bob := newJoinTestMember(t, "Bob")
	charlie := newJoinTestMember(t, "Charlie")
	ag := createJoinTestGroup(t, alice)
	for _, u := range []joinTestMember{bob, charlie} {
		if _, err := ag.AddMember(u.kp); err != nil {
			t.Fatalf("AddMember(%s): %v", u.name, err)
		}
	}
	joined := joinThroughWelcome(t, ag, alice, bob, charlie)
	bg, cg := joined[0], joined[1]
	leafBefore := append([]byte(nil), ag.myLeafEncryptionKey...)

	staged, err := ag.Commit(alice.sig, alice.sig.PublicKey(), nil)
	if err != nil {
		t.Fatalf("Commit by alice: %v", err)
	}
	bobAC1 := commitAndMerge(t, bg, bob)
	receiveCommitFrom(t, ag, "Alice", bobAC1, bg.ownLeafIndex)
	receiveCommitFrom(t, cg, "Charlie", bobAC1, bg.ownLeafIndex)
	if !bytes.Equal(ag.myLeafEncryptionKey, leafBefore) {
		t.Error("a received commit replaced alice's leaf key with the key that her pending Commit staged")
	}
	if !staged.discarded || staged.pathPrivKeys != nil {
		t.Error("the superseded Commit was not released: its path keys must be erased and it must not be merged")
	}
	if err := ag.MergeCommit(staged); !errors.Is(err, ErrNoPendingCommit) {
		t.Fatalf("MergeCommit of the superseded Commit: err = %v, want ErrNoPendingCommit", err)
	}

	bobAC2 := commitAndMerge(t, bg, bob)
	receiveCommitFrom(t, ag, "Alice", bobAC2, bg.ownLeafIndex)
	receiveCommitFrom(t, cg, "Charlie", bobAC2, bg.ownLeafIndex)
	assertSameExport(t, ag, cg)
}

// TestDiscardedCommitCannotBeMerged checks that MergeCommit refuses a discarded Commit. DiscardPendingCommit
// erases the path keys of the commit, so merging it afterwards would install a tree whose public keys have no
// private keys. The group is unchanged after the refusal, then commits normally and bob follows.
func TestDiscardedCommitCannotBeMerged(t *testing.T) {
	alice := newJoinTestMember(t, "Alice")
	bob := newJoinTestMember(t, "Bob")
	ag := createJoinTestGroup(t, alice)
	if _, err := ag.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	bg := joinThroughWelcome(t, ag, alice, bob)[0]

	staged, err := ag.Commit(alice.sig, alice.sig.PublicKey(), nil)
	if err != nil {
		t.Fatalf("Commit by alice: %v", err)
	}
	if err := ag.DiscardPendingCommit(); err != nil {
		t.Fatalf("DiscardPendingCommit: %v", err)
	}
	before := fullStateFingerprint(t, ag)
	if err := ag.MergeCommit(staged); !errors.Is(err, ErrNoPendingCommit) {
		t.Fatalf("MergeCommit of a discarded commit: err = %v, want ErrNoPendingCommit", err)
	}
	if after := fullStateFingerprint(t, ag); after != before {
		t.Errorf("merging a discarded commit changed alice's state:\nbefore: %s\nafter:  %s", before, after)
	}

	ac := commitAndMerge(t, ag, alice)
	receiveCommitFrom(t, bg, "Bob", ac, ag.ownLeafIndex)
	assertSameExport(t, ag, bg)
}
