package group

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/openmls/go/framing"
	"github.com/openmls/go/treesync"
)

func TestDebugCommitPM(t *testing.T) {
	aliceGroup, bobGroup, alice, _ := makeTwoMemberGroups(t)

	charlie := newTestUser(t, "charlie-debug")
	if _, err := aliceGroup.AddMember(charlie.kp); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	sc, err := aliceGroup.Commit(alice.sigPriv, alice.sigPub, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	commitBody := sc.AuthenticatedContent.Content.Body.(framing.CommitBody)
	commit, _ := UnmarshalCommit(commitBody.Data)
	
	fmt.Printf("UpdatePath.Nodes count: %d\n", len(commit.Path.Nodes))
	for m, n := range commit.Path.Nodes {
		fmt.Printf("  Node[%d]: encKey=%d bytes, secrets=%d\n", m, len(n.EncryptionKey), len(n.EncryptedPathSecrets))
	}
	
	// Simulate what ProcessReceivedCommit does for the provisional tree
	proposals := make([]*Proposal, 0)
	proposalSenders := make([]LeafNodeIndex, 0)
	for _, por := range commit.Proposals {
		if por.Proposal != nil {
			proposals = append(proposals, por.Proposal)
			proposalSenders = append(proposalSenders, 0)
		}
	}
	sortProposalsByRFCOrder(proposals, proposalSenders)
	
	treeAfterProposals := bobGroup.RatchetTree.Clone()
	excluded := make(map[treesync.LeafIndex]bool)
	for _, p := range proposals {
		if p.Type == ProposalTypeAdd && p.Add != nil && p.Add.KeyPackage != nil && p.Add.KeyPackage.LeafNode != nil {
			leafData := *keyPackageLeafToTreeSync(p.Add.KeyPackage.LeafNode)
			addedIdx, _ := treeAfterProposals.AddLeaf(leafData)
			excluded[addedIdx] = true
		}
	}
	
	senderLeafIdx := treesync.LeafIndex(0)
	provTree := buildProvisionalTree(treeAfterProposals, senderLeafIdx, commit.Path, excluded)
	bobGCBytes := bobGroup.provisionalGroupContextBytesFromTree(provTree)
	
	fmt.Printf("Alice provisional GC (from Commit.createUpdatePath provisional):\n")
	// Alice's provisional GC was computed in createUpdatePath
	// Let's simulate it using alice's treeDiff state
	// We'll use the commit's UpdatePath to rebuild alice's provisional tree
	aliceTreeAfterProposals := aliceGroup.RatchetTree.Clone()
	aliceExcluded := make(map[treesync.LeafIndex]bool)
	for _, p := range proposals {
		if p.Type == ProposalTypeAdd && p.Add != nil && p.Add.KeyPackage != nil && p.Add.KeyPackage.LeafNode != nil {
			leafData := *keyPackageLeafToTreeSync(p.Add.KeyPackage.LeafNode)
			addedIdx, _ := aliceTreeAfterProposals.AddLeaf(leafData)
			aliceExcluded[addedIdx] = true
		}
	}
	aliceProvTree := buildProvisionalTree(aliceTreeAfterProposals, senderLeafIdx, commit.Path, aliceExcluded)
	aliceGCBytes := aliceGroup.provisionalGroupContextBytesFromTree(aliceProvTree)
	
	fmt.Printf("Bob prov GC (first 10 bytes): %x\n", bobGCBytes[:min2(10, len(bobGCBytes))])
	fmt.Printf("Alice prov GC (first 10 bytes): %x\n", aliceGCBytes[:min2(10, len(aliceGCBytes))])
	fmt.Printf("GC bytes match: %v\n", bytes.Equal(bobGCBytes, aliceGCBytes))
	fmt.Printf("Bob has MyLeafEncryptionKey: %v (%d bytes)\n", bobGroup.MyLeafEncryptionKey != nil, len(bobGroup.MyLeafEncryptionKey))
	fmt.Printf("Bob OwnLeafIndex: %d\n", bobGroup.OwnLeafIndex)
}

func min2(a, b int) int {
	if a < b { return a }
	return b
}
