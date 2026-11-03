//go:build diagnostics

package group

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"testing"
)

// groupStateFingerprint captures every field that a rejected commit could change, including the fields that
// MarshalState does not serialize (epochHistory, proposalByRef, pendingLeafKey, pathNodePrivKeys,
// lastCommittedProposals, keySchedule, pendingCommit, the proposal store).
func groupStateFingerprint(t *testing.T, g *Group) string {
	t.Helper()
	state, err := g.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState: %v", err)
	}
	sum := sha256.Sum256(state)

	active := ""
	for i := 0; i < int(g.ratchetTree.NumLeaves); i++ {
		if m, ok := g.members[LeafNodeIndex(i)]; ok && m != nil {
			active += fmt.Sprintf("%d:%v;", i, m.Active)
		}
	}

	paths := make([]string, 0, len(g.pathNodePrivKeys))
	for k, v := range g.pathNodePrivKeys {
		paths = append(paths, fmt.Sprintf("%d=%x", k, v))
	}
	sort.Strings(paths)

	ksInit := []byte(nil)
	if g.keySchedule != nil && g.keySchedule.InitSecret() != nil {
		ksInit = g.keySchedule.InitSecret().AsSlice()
	}

	return fmt.Sprintf("epoch=%d state=%v marshal=%x hist=%d byref=%d store=%d cachedpsk=%d pendingLeaf=%x pendingUpd=%x myLeaf=%x pathkeys=%v lastCommitted=%d members=[%s] conf=%x interim=%x pendingCommit=%v ks=%x tree=%x",
		g.epoch.AsUint64(), g.state, sum[:], len(g.epochHistory), len(g.proposalByRef), len(g.proposals.Proposals),
		len(g.cachedPsks), g.pendingLeafKey, g.pendingUpdatePrivKey, g.myLeafEncryptionKey, paths,
		len(g.lastCommittedProposals), active, g.confirmationTag, g.interimTranscriptHash, g.pendingCommit != nil,
		ksInit, g.ratchetTree.TreeHash())
}

// TestSoleMemberGCECommitCarriesPath checks that the GroupContextExtensions commit of a sole member carries
// an UpdatePath built over a one-leaf tree. The epoch that follows must still accept a new member through a
// Welcome.
func TestSoleMemberGCECommitCarriesPath(t *testing.T) {
	alice := newDiagnosticMember(t, "Alice")
	bob := newDiagnosticMember(t, "Bob")
	ag := createDiagnosticGroup(t, alice)

	ag.proposals.AddProposal(NewGroupContextExtensionsProposal(ag.groupContext.Extensions), ag.ownLeafIndex)
	staged, err := ag.Commit(alice.sig, alice.sig.PublicKey(), nil)
	if err != nil {
		t.Fatalf("sole-member GCE commit: %v", err)
	}
	if staged.commit == nil || staged.commit.Path == nil {
		t.Fatal("sole-member commit with a GroupContextExtensions proposal carries no UpdatePath")
	}
	if err := ag.MergeCommit(staged); err != nil {
		t.Fatalf("MergeCommit: %v", err)
	}
	if ag.Epoch().AsUint64() != 1 {
		t.Fatalf("epoch = %d, want 1", ag.Epoch().AsUint64())
	}

	if _, err := ag.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember after sole-member path commit: %v", err)
	}
	bg := commitAndJoin(t, ag, alice, bob)[0]
	assertDiagnosticExportEqual(t, ag, bg)
	exchangeMessages(t, ag, alice, bg, bob)
}

// TestSoleMemberEmptyCommitCarriesPath checks that the empty commit of a sole member carries a path, as
// RFC 9420 §12.4 requires, and that the epoch that follows still accepts a new member through a Welcome.
func TestSoleMemberEmptyCommitCarriesPath(t *testing.T) {
	alice := newDiagnosticMember(t, "Alice")
	bob := newDiagnosticMember(t, "Bob")
	ag := createDiagnosticGroup(t, alice)

	staged, err := ag.Commit(alice.sig, alice.sig.PublicKey(), nil)
	if err != nil {
		t.Fatalf("sole-member empty commit: %v", err)
	}
	if staged.commit == nil || staged.commit.Path == nil {
		t.Fatal("empty commit carries no UpdatePath (RFC 9420 §12.4 requires one)")
	}
	if err := ag.MergeCommit(staged); err != nil {
		t.Fatalf("MergeCommit: %v", err)
	}
	if _, err := ag.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	bg := commitAndJoin(t, ag, alice, bob)[0]
	assertDiagnosticExportEqual(t, ag, bg)
	exchangeMessages(t, ag, alice, bg, bob)
}
