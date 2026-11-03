package group

import (
	"bytes"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/schedule"
	"github.com/thomas-vilte/mls-go/treesync"
)

// pathRuleExtensions returns the GroupContextExtensions payload used by the path rule tests. The type must
// be one the library can process, because a joiner refuses a GroupContext extension it does not support
// (RFC 9420 §13.4). application_id (0x0001) is one of them.
func pathRuleExtensions() []Extension {
	return []Extension{{Type: 0x0001, Data: []byte("path-rule")}}
}

// TestCommitRequiresPathForGroupContextExtensions checks the path rule of RFC 9420 §12.4: a Commit must carry
// an UpdatePath unless it covers at least one proposal and every proposal is add, psk or reinit. A
// GroupContextExtensions proposal requires a path, so:
//   - a receiver rejects a Commit with a GroupContextExtensions proposal and no path, even when the
//     signature and the confirmation_tag are valid, and it accepts the same change with a path;
//   - a sole-member group that commits a GroupContextExtensions proposal generates a path, and the
//     member it adds in that Commit joins and then follows the group.
func TestCommitRequiresPathForGroupContextExtensions(t *testing.T) {
	t.Run("receiver/gce_commit_without_path_is_rejected", func(t *testing.T) {
		alice, bob, alicePriv, _ := setupTwoMemberGroup(t)
		sigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)

		forged := pathlessGCECommit(t, alice, sigPriv, pathRuleExtensions())
		epochBefore := bob.Epoch()

		err := bob.ProcessReceivedCommit(forged, treesync.LeafIndex(alice.ownLeafIndex), bob.MyLeafEncryptionKey())
		if !errors.Is(err, ErrInvalidProposal) {
			t.Fatalf("GCE commit without UpdatePath: err = %v, want ErrInvalidProposal (RFC 9420 §12.4)", err)
		}
		if bob.Epoch() != epochBefore {
			t.Fatalf("epoch after rejected commit = %d, want %d", bob.Epoch().AsUint64(), epochBefore.AsUint64())
		}
	})

	// Control: the same GroupContextExtensions change, generated normally with its UpdatePath, is accepted.
	t.Run("receiver/gce_commit_with_path_is_accepted", func(t *testing.T) {
		alice, bob, alicePriv, _ := setupTwoMemberGroup(t)
		sigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)

		alice.proposals.AddProposal(NewGroupContextExtensionsProposal(pathRuleExtensions()), alice.ownLeafIndex)
		staged, err := alice.Commit(sigPriv, sigPriv.PublicKey(), nil)
		if err != nil {
			t.Fatalf("SETUP: creating GCE commit: %v", err)
		}
		if staged.commit == nil || staged.commit.Path == nil {
			t.Fatal("SETUP: GCE commit has no UpdatePath")
		}
		if err := alice.MergeCommit(staged); err != nil {
			t.Fatalf("MergeCommit: %v", err)
		}
		if err := bob.ProcessReceivedCommit(staged.AuthenticatedContent(), treesync.LeafIndex(alice.ownLeafIndex), bob.MyLeafEncryptionKey()); err != nil {
			t.Fatalf("GCE commit with UpdatePath rejected: %v", err)
		}
		if !bytes.Equal(alice.EpochAuthenticator(), bob.EpochAuthenticator()) {
			t.Fatal("epoch authenticators differ after the GCE commit")
		}
	})

	t.Run("sole_member/gce_commit_generates_path_and_other_member_accepts", func(t *testing.T) {
		aliceGroup, alicePriv := newSingleMemberGroup(t, "Alice")
		sigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)

		// Alice adds Bob and changes the GroupContext in the same Commit. The Add alone would not need
		// a path; the GroupContextExtensions proposal does.
		bobCred, _, err := credentials.GenerateCredentialWithKey([]byte("Bob"))
		if err != nil {
			t.Fatalf("GenerateCredentialWithKey(Bob): %v", err)
		}
		bobKP, bobPriv, err := keypackages.Generate(bobCred, keypackages.MLS128DHKEMP256)
		if err != nil {
			t.Fatalf("Generate KeyPackage(Bob): %v", err)
		}
		if _, err := aliceGroup.AddMember(bobKP); err != nil {
			t.Fatalf("AddMember(Bob): %v", err)
		}
		aliceGroup.proposals.AddProposal(NewGroupContextExtensionsProposal(pathRuleExtensions()), aliceGroup.ownLeafIndex)

		staged, err := aliceGroup.Commit(sigPriv, sigPriv.PublicKey(), nil)
		if err != nil {
			t.Fatalf("Commit(sole member, Add + GCE): %v", err)
		}
		if staged.commit == nil || staged.commit.Path == nil {
			t.Fatal("sole member commit covering a GroupContextExtensions proposal was generated with no UpdatePath (RFC 9420 §12.4)")
		}
		if err := aliceGroup.MergeCommit(staged); err != nil {
			t.Fatalf("MergeCommit(sole member): %v", err)
		}

		welcome, err := aliceGroup.CreateWelcomeWithOpts(
			[]*keypackages.KeyPackage{bobKP},
			sigPriv,
			WithJoinerSecret(staged.JoinerSecret()),
			WithStagedCommit(staged),
		)
		if err != nil {
			t.Fatalf("CreateWelcome: %v", err)
		}
		bobGroup, err := JoinFromWelcome(welcome, bobKP, bobPriv, nil)
		if err != nil {
			t.Fatalf("JoinFromWelcome: %v", err)
		}
		if !bytes.Equal(aliceGroup.EpochAuthenticator(), bobGroup.EpochAuthenticator()) {
			t.Fatal("Bob joined with an epoch authenticator different from Alice's")
		}

		// Bob must also accept a later Commit from Alice, which exercises the tree that the
		// sole-member UpdatePath produced.
		next, err := aliceGroup.Commit(sigPriv, sigPriv.PublicKey(), nil)
		if err != nil {
			t.Fatalf("Commit(next epoch): %v", err)
		}
		if err := aliceGroup.MergeCommit(next); err != nil {
			t.Fatalf("MergeCommit(next epoch): %v", err)
		}
		if err := bobGroup.ProcessReceivedCommit(next.AuthenticatedContent(), treesync.LeafIndex(aliceGroup.ownLeafIndex), bobGroup.MyLeafEncryptionKey()); err != nil {
			t.Fatalf("Bob rejected Alice's next commit: %v", err)
		}
		if !bytes.Equal(aliceGroup.EpochAuthenticator(), bobGroup.EpochAuthenticator()) {
			t.Fatal("epoch authenticators differ after Alice's next commit")
		}
	})

	// A GroupContextExtensions proposal alone, with no Add: the sole member's UpdatePath has no
	// parent nodes to encrypt to, and the new extensions must still take effect after the merge.
	t.Run("sole_member/gce_only_commit_generates_path", func(t *testing.T) {
		aliceGroup, alicePriv := newSingleMemberGroup(t, "Alice")
		sigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)

		aliceGroup.proposals.AddProposal(NewGroupContextExtensionsProposal(pathRuleExtensions()), aliceGroup.ownLeafIndex)
		staged, err := aliceGroup.Commit(sigPriv, sigPriv.PublicKey(), nil)
		if err != nil {
			t.Fatalf("Commit(sole member, GCE only): %v", err)
		}
		if staged.commit == nil || staged.commit.Path == nil {
			t.Fatal("sole member GCE-only commit was generated with no UpdatePath (RFC 9420 §12.4)")
		}
		if err := aliceGroup.MergeCommit(staged); err != nil {
			t.Fatalf("MergeCommit(sole member, GCE only): %v", err)
		}
		exts := aliceGroup.GroupContext().Extensions
		if len(exts) != 1 || exts[0].Type != 0x0001 || !bytes.Equal(exts[0].Data, []byte("path-rule")) {
			t.Fatalf("GroupContext extensions after GCE commit = %v, want the proposed application_id extension", exts)
		}
	})

	t.Run("sole_member/empty_commit_generates_path", func(t *testing.T) {
		aliceGroup, alicePriv := newSingleMemberGroup(t, "Alice")
		sigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)

		// RFC 9420 §12.4: a Commit that covers no proposal must carry a path, even with one member.
		staged, err := aliceGroup.Commit(sigPriv, sigPriv.PublicKey(), nil)
		if err != nil {
			t.Fatalf("Commit(sole member, empty): %v", err)
		}
		if staged.commit == nil || staged.commit.Path == nil {
			t.Fatal("sole member empty commit was generated with no UpdatePath (RFC 9420 §12.4)")
		}
		if err := aliceGroup.MergeCommit(staged); err != nil {
			t.Fatalf("MergeCommit(sole member, empty): %v", err)
		}
	})
}

// pathlessGCECommit has committer build a Commit whose only proposal is a GroupContextExtensions
// proposal, carried by value, with the path field absent. Everything the receiver checks apart from the
// path is valid: the signature, the confirmed transcript hash and the confirmation_tag. They are computed
// as CommitWithContext does, with commit_secret set to zero when there is no path (RFC 9420 §12.4.1).
// The tree does not change, so the new tree_hash is the committer's current one.
func pathlessGCECommit(t *testing.T, committer *Group, sigPriv *ciphersuite.SignaturePrivateKey, exts []Extension) *framing.AuthenticatedContent {
	t.Helper()
	cs := committer.cipherSuite

	commit := &Commit{Proposals: []ProposalOrRef{{Proposal: NewGroupContextExtensionsProposal(exts)}}}
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
		t.Fatalf("SignWithLabel(forged GCE commit): %v", err)
	}
	ac.Auth.Signature = sig

	cthi, err := framing.NewConfirmedTranscriptHashInput(ac)
	if err != nil {
		t.Fatalf("NewConfirmedTranscriptHashInput(forged GCE commit): %v", err)
	}
	confirmedHash, err := cthi.Compute(cs, committer.interimTranscriptHash)
	if err != nil {
		t.Fatalf("confirmed transcript hash (forged GCE commit): %v", err)
	}

	newGC := &GroupContext{
		Version:                 committer.groupContext.Version,
		CipherSuite:             committer.groupContext.CipherSuite,
		GroupID:                 committer.groupContext.GroupID,
		Epoch:                   NewGroupEpoch(committer.epoch.AsUint64() + 1),
		TreeHash:                committer.ratchetTree.TreeHash(),
		ConfirmedTranscriptHash: confirmedHash,
		Extensions:              exts,
	}
	newGCBytes := newGC.Marshal()
	ks := schedule.NewKeySchedule(cs, committer.epochSecrets.InitSecret.Clone())
	ks.SetCommitSecret(ciphersuite.ZeroSecretCS(cs))
	if _, err := ks.ComputeJoinerSecret(newGCBytes); err != nil {
		t.Fatalf("ComputeJoinerSecret(forged GCE commit): %v", err)
	}
	if _, err := ks.ComputePskSecret(nil); err != nil {
		t.Fatalf("ComputePskSecret(forged GCE commit): %v", err)
	}
	if _, err := ks.ComputeEpochSecret(newGCBytes); err != nil {
		t.Fatalf("ComputeEpochSecret(forged GCE commit): %v", err)
	}
	epochSecrets, err := ks.DeriveEpochSecrets()
	if err != nil {
		t.Fatalf("DeriveEpochSecrets(forged GCE commit): %v", err)
	}
	ac.Auth.ConfirmationTag = schedule.ComputeConfirmationTag(cs, epochSecrets.ConfirmationKey.AsSlice(), confirmedHash)
	return ac
}
