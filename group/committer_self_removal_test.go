package group

import (
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/schedule"
	"github.com/thomas-vilte/mls-go/treesync"
)

// TestCommitCannotRemoveItsCommitter checks that a Commit must not remove its own committer (RFC 9420
// §12.2). Such a list is invalid, so the committer cannot create the Commit and a receiver rejects it. A
// member that leaves is removed by a Remove proposal that another member commits (see Client.LeaveGroup), so:
//   - the committer cannot create a Commit that removes its own leaf;
//   - a receiver rejects a Commit with a Remove of its committer, even when the signature and the
//     confirmation_tag match the tree that the removal produces, and the group is left unchanged.
func TestCommitCannotRemoveItsCommitter(t *testing.T) {
	t.Run("committer/commit_removing_own_leaf_is_refused", func(t *testing.T) {
		_, bob, _, bobPriv := setupTwoMemberGroup(t)
		sigPriv := ciphersuite.NewSignaturePrivateKey(bobPriv.SignatureKey)

		if _, err := bob.RemoveMember(bob.ownLeafIndex); err != nil {
			t.Fatalf("SETUP: RemoveMember(own leaf): %v", err)
		}
		epochBefore := bob.Epoch()
		staged, err := bob.Commit(sigPriv, sigPriv.PublicKey(), nil)
		if !errors.Is(err, ErrInvalidProposal) {
			t.Fatalf("Commit that removes the committer: err = %v, want ErrInvalidProposal (RFC 9420 §12.2)", err)
		}
		if staged != nil {
			t.Fatal("Commit that removes the committer returned a StagedCommit")
		}
		if bob.Epoch() != epochBefore {
			t.Fatalf("epoch after refused commit = %d, want %d", bob.Epoch().AsUint64(), epochBefore.AsUint64())
		}
	})

	t.Run("receiver/commit_removing_its_committer_is_rejected", func(t *testing.T) {
		alice, bob, _, bobPriv := setupTwoMemberGroup(t)
		sigPriv := ciphersuite.NewSignaturePrivateKey(bobPriv.SignatureKey)

		forged := selfRemoveCommit(t, bob, sigPriv)
		epochBefore := alice.Epoch()
		err := alice.ProcessReceivedCommit(forged, treesync.LeafIndex(bob.ownLeafIndex), alice.MyLeafEncryptionKey())
		if !errors.Is(err, ErrInvalidProposal) {
			t.Fatalf("Commit removing its committer: err = %v, want ErrInvalidProposal (RFC 9420 §12.2)", err)
		}
		if alice.Epoch() != epochBefore {
			t.Fatalf("epoch after rejected commit = %d, want %d", alice.Epoch().AsUint64(), epochBefore.AsUint64())
		}
	})
}

// selfRemoveCommit has committer build a Commit whose only proposal is a Remove of the committer's own
// leaf, carried by value, with the path field absent. The signature and the confirmation_tag are computed
// for the tree that the removal produces, the way a receiver builds it: the direct path of the removed leaf
// is blanked and the trailing blank leaves are truncated. A receiver can therefore refuse the Commit only
// because of the Remove itself (RFC 9420 §12.2).
func selfRemoveCommit(t *testing.T, committer *Group, sigPriv *ciphersuite.SignaturePrivateKey) *framing.AuthenticatedContent {
	t.Helper()
	cs := committer.cipherSuite

	commit := &Commit{Proposals: []ProposalOrRef{{Proposal: NewRemoveProposal(committer.ownLeafIndex)}}}
	ac := &framing.AuthenticatedContent{
		WireFormat: framing.WireFormatPublicMessage,
		Content: framing.FramedContent{
			GroupID: committer.groupID.AsSlice(),
			Epoch:   committer.epoch.AsUint64(),
			Sender:  framing.Sender{Type: framing.SenderTypeMember, LeafIndex: uint32(committer.ownLeafIndex)},
			Body:    framing.CommitBody{Data: commit.Marshal()},
		},
		GroupContext: committer.groupContext.Marshal(),
	}
	sig, err := ciphersuite.SignWithLabel(sigPriv, "FramedContentTBS", ac.MarshalTBS())
	if err != nil {
		t.Fatalf("SignWithLabel(self-remove commit): %v", err)
	}
	ac.Auth.Signature = sig

	cthi, err := framing.NewConfirmedTranscriptHashInput(ac)
	if err != nil {
		t.Fatalf("NewConfirmedTranscriptHashInput(self-remove commit): %v", err)
	}
	confirmedHash, err := cthi.Compute(cs, committer.interimTranscriptHash)
	if err != nil {
		t.Fatalf("confirmed transcript hash (self-remove commit): %v", err)
	}

	// The tree after the removal, built as processReceivedCommit builds it.
	treeAfter := committer.ratchetTree.Clone()
	for _, nodeIdx := range treeAfter.DirectPath(treesync.LeafIndex(committer.ownLeafIndex)) {
		treeAfter.BlankNode(nodeIdx)
	}
	treeAfter.TruncateTrailingBlanks()

	newGC := &GroupContext{
		Version:                 committer.groupContext.Version,
		CipherSuite:             committer.groupContext.CipherSuite,
		GroupID:                 committer.groupContext.GroupID,
		Epoch:                   NewGroupEpoch(committer.epoch.AsUint64() + 1),
		TreeHash:                treeAfter.TreeHash(),
		ConfirmedTranscriptHash: confirmedHash,
		Extensions:              committer.groupContext.Extensions,
	}
	newGCBytes := newGC.Marshal()
	ks := schedule.NewKeySchedule(cs, committer.epochSecrets.InitSecret.Clone())
	ks.SetCommitSecret(ciphersuite.ZeroSecretCS(cs))
	if _, err := ks.ComputeJoinerSecret(newGCBytes); err != nil {
		t.Fatalf("ComputeJoinerSecret(self-remove commit): %v", err)
	}
	if _, err := ks.ComputePskSecret(nil); err != nil {
		t.Fatalf("ComputePskSecret(self-remove commit): %v", err)
	}
	if _, err := ks.ComputeEpochSecret(newGCBytes); err != nil {
		t.Fatalf("ComputeEpochSecret(self-remove commit): %v", err)
	}
	epochSecrets, err := ks.DeriveEpochSecrets()
	if err != nil {
		t.Fatalf("DeriveEpochSecrets(self-remove commit): %v", err)
	}
	ac.Auth.ConfirmationTag = schedule.ComputeConfirmationTag(cs, epochSecrets.ConfirmationKey.AsSlice(), confirmedHash)
	return ac
}
