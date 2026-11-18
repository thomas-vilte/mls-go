package mls

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
)

// Under CacheNone, CommitPendingProposalsStaged writes nothing: the staged commit lives in the handle, which
// keeps a snapshot of the group. Another operation (ProcessCommit, SendMessage, ProposeAddMember) can write a
// newer state to the store before the handle is resolved. DiscardPendingCommit and ConfirmPendingCommit used
// to save the snapshot over that state. The tests below cover the epoch, the sender generation and the
// group that the snapshot would roll back or fork.

// newStagedCommitPair has alice create a group and invite bob, so both are in epoch 1. alice uses the default
// cache strategy (CacheNone). bobOpts configure bob.
func newStagedCommitPair(t *testing.T, bobOpts ...ClientOption) (alice, bob *Client, gid, bobGid []byte) {
	t.Helper()
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256

	var err error
	alice, err = NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	bob, err = NewClient([]byte("bob"), cs, bobOpts...)
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}
	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(bob): %v", err)
	}
	gid, err = alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	_, welcome, err := alice.InviteMember(ctx, gid, bobKP)
	if err != nil {
		t.Fatalf("InviteMember(bob): %v", err)
	}
	bobGid, err = bob.JoinGroup(ctx, welcome)
	if err != nil {
		t.Fatalf("JoinGroup(bob): %v", err)
	}
	return alice, bob, gid, bobGid
}

func groupEpochOf(t *testing.T, c *Client, gid []byte) uint64 {
	t.Helper()
	e, err := c.Epoch(context.Background(), gid)
	if err != nil {
		t.Fatalf("Epoch: %v", err)
	}
	return e
}

func groupExportOf(t *testing.T, c *Client, gid []byte) []byte {
	t.Helper()
	s, err := c.Export(context.Background(), gid, "pending-commit-test", []byte("probe"), 32)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	return s
}

// requireSameEpochAndSecrets checks that alice and bob are in the given epoch and export the same secret.
func requireSameEpochAndSecrets(t *testing.T, alice *Client, gid []byte, bob *Client, bobGid []byte, epoch uint64) {
	t.Helper()
	ea, eb := groupEpochOf(t, alice, gid), groupEpochOf(t, bob, bobGid)
	if ea != epoch || eb != epoch {
		t.Fatalf("epoch alice=%d bob=%d, want %d for both", ea, eb, epoch)
	}
	if !bytes.Equal(groupExportOf(t, alice, gid), groupExportOf(t, bob, bobGid)) {
		t.Fatalf("alice and bob export different secrets in epoch %d", epoch)
	}
}

// storedSenderSequence reads the sequence number of c's own leaf from the stored group state, without the
// cache. That number is the generation of the sender's content key. present is false when the leaf is not in the
// stored secret tree.
func storedSenderSequence(t *testing.T, c *Client, gid []byte) (seq uint64, present bool) {
	t.Helper()
	ctx := context.Background()
	own, err := c.OwnLeafIndex(ctx, gid)
	if err != nil {
		t.Fatalf("OwnLeafIndex: %v", err)
	}
	raw, err := c.store.LoadGroupState(ctx, group.NewGroupID(gid))
	if err != nil {
		t.Fatalf("store.LoadGroupState: %v", err)
	}
	var st group.StateData
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("unmarshal StateData: %v", err)
	}
	if st.SecretTree == nil {
		return 0, false
	}
	ls, ok := st.SecretTree.LeafStates[own]
	if !ok {
		return 0, false
	}
	return ls.SequenceNumber, true
}

// winningCommit has bob commit an update that alice then applies, so the stored state of alice moves to the
// next epoch while a handle staged before it is still pending.
func winningCommit(t *testing.T, alice *Client, gid []byte, bob *Client, bobGid []byte) {
	t.Helper()
	ctx := context.Background()
	commit, err := bob.SelfUpdate(ctx, bobGid)
	if err != nil {
		t.Fatalf("bob SelfUpdate: %v", err)
	}
	if err := alice.ProcessCommit(ctx, gid, commit); err != nil {
		t.Fatalf("alice ProcessCommit(winning commit): %v", err)
	}
	if got := groupEpochOf(t, alice, gid); got != 2 {
		t.Fatalf("stored epoch after the winning commit = %d, want 2", got)
	}
}

// TestDiscardPendingCommitKeepsWinningCommit checks that discarding a staged commit does not roll the stored
// epoch back over a commit that was applied after staging (RFC 9420 section 8.1: the epoch increments for each
// commit that is processed).
func TestDiscardPendingCommitKeepsWinningCommit(t *testing.T) {
	ctx := context.Background()
	alice, bob, gid, bobGid := newStagedCommitPair(t)

	handle, err := alice.CommitPendingProposalsStaged(ctx, gid)
	if err != nil {
		t.Fatalf("CommitPendingProposalsStaged: %v", err)
	}
	if got := groupEpochOf(t, alice, gid); got != 1 {
		t.Fatalf("staging wrote to the store: epoch = %d, want 1", got)
	}
	winningCommit(t, alice, gid, bob, bobGid)

	if err := alice.DiscardPendingCommit(ctx, handle); err != nil {
		t.Fatalf("DiscardPendingCommit: %v", err)
	}
	if got := groupEpochOf(t, alice, gid); got != 2 {
		t.Fatalf("stored epoch after Discard = %d, want 2 (bob is in epoch %d)", got, groupEpochOf(t, bob, bobGid))
	}
}

// TestDiscardPendingCommitKeepsSenderGeneration checks that discarding does not move the stored sender
// sequence number back to a generation that a message sent after staging already used (RFC 9420 sections 6.3.1
// and 9.2: reusing a generation reuses a key and nonce pair).
func TestDiscardPendingCommitKeepsSenderGeneration(t *testing.T) {
	ctx := context.Background()
	alice, _, gid, _ := newStagedCommitPair(t)

	handle, err := alice.CommitPendingProposalsStaged(ctx, gid)
	if err != nil {
		t.Fatalf("CommitPendingProposalsStaged: %v", err)
	}
	seqBefore, _ := storedSenderSequence(t, alice, gid)
	if _, err := alice.SendMessage(ctx, gid, []byte("m1")); err != nil {
		t.Fatalf("SendMessage(m1): %v", err)
	}
	seqAfterSend, present := storedSenderSequence(t, alice, gid)
	if !present || seqAfterSend <= seqBefore {
		t.Fatalf("SendMessage did not store the new sequence number: before=%d after=%d present=%v", seqBefore, seqAfterSend, present)
	}
	if err := alice.DiscardPendingCommit(ctx, handle); err != nil {
		t.Fatalf("DiscardPendingCommit: %v", err)
	}
	seqAfterDiscard, present := storedSenderSequence(t, alice, gid)
	if !present || seqAfterDiscard != seqAfterSend {
		t.Fatalf("stored sequence number after Discard = %d (present=%v), want %d: the next message would reuse the generation of m1",
			seqAfterDiscard, present, seqAfterSend)
	}
}

// TestMessageAfterDiscardedCommitIsAccepted checks that a receiver that keeps its state in memory accepts the
// message that follows a Discard. When the sender reused the generation of the previous message, the receiver
// refused it as a replay.
func TestMessageAfterDiscardedCommitIsAccepted(t *testing.T) {
	ctx := context.Background()
	alice, bob, gid, bobGid := newStagedCommitPair(t, WithCacheStrategy(CacheAlways))

	handle, err := alice.CommitPendingProposalsStaged(ctx, gid)
	if err != nil {
		t.Fatalf("CommitPendingProposalsStaged: %v", err)
	}
	ct1, err := alice.SendMessage(ctx, gid, []byte("m1"))
	if err != nil {
		t.Fatalf("SendMessage(m1): %v", err)
	}
	if err := alice.DiscardPendingCommit(ctx, handle); err != nil {
		t.Fatalf("DiscardPendingCommit: %v", err)
	}
	ct2, err := alice.SendMessage(ctx, gid, []byte("m2"))
	if err != nil {
		t.Fatalf("SendMessage(m2): %v", err)
	}

	for i, want := range []struct {
		ct   []byte
		text string
	}{{ct1, "m1"}, {ct2, "m2"}} {
		rx, err := bob.ReceiveMessage(ctx, bobGid, want.ct)
		if err != nil {
			t.Fatalf("bob ReceiveMessage(message %d): %v", i+1, err)
		}
		if string(rx.Plaintext) != want.text {
			t.Fatalf("message %d plaintext = %q, want %q", i+1, rx.Plaintext, want.text)
		}
	}
}

// TestConfirmPendingCommitRefusesStaleHandle checks that ConfirmPendingCommit refuses a handle staged before a
// winning commit was applied, with ErrStalePendingCommit and without writing. Merging the snapshot would write
// the old state back and fork the group. A Discard afterwards keeps the state of the winning commit.
func TestConfirmPendingCommitRefusesStaleHandle(t *testing.T) {
	ctx := context.Background()
	alice, bob, gid, bobGid := newStagedCommitPair(t)

	handle, err := alice.CommitPendingProposalsStaged(ctx, gid)
	if err != nil {
		t.Fatalf("CommitPendingProposalsStaged: %v", err)
	}
	winningCommit(t, alice, gid, bob, bobGid)

	if _, err := alice.ConfirmPendingCommit(ctx, handle); !errors.Is(err, ErrStalePendingCommit) {
		t.Fatalf("ConfirmPendingCommit(stale handle) = %v, want ErrStalePendingCommit", err)
	}
	if got := groupEpochOf(t, alice, gid); got != 2 {
		t.Fatalf("the refused Confirm wrote to the store: epoch = %d, want 2", got)
	}
	if err := alice.DiscardPendingCommit(ctx, handle); err != nil {
		t.Fatalf("DiscardPendingCommit after the refused Confirm: %v", err)
	}
	requireSameEpochAndSecrets(t, alice, gid, bob, bobGid, 2)
}

// TestConfirmPendingCommitRefusesHandleAfterStoredProposal checks that a proposal stored between staging and
// Confirm changes the stored state: Confirm refuses the handle, and the Discard that follows keeps the proposal
// for the next commit.
func TestConfirmPendingCommitRefusesHandleAfterStoredProposal(t *testing.T) {
	ctx := context.Background()
	alice, bob, gid, bobGid := newStagedCommitPair(t)
	carol, err := NewClient([]byte("carol"), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("NewClient(carol): %v", err)
	}
	carolKP, err := carol.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(carol): %v", err)
	}

	handle, err := alice.CommitPendingProposalsStaged(ctx, gid)
	if err != nil {
		t.Fatalf("CommitPendingProposalsStaged: %v", err)
	}
	if _, err := alice.ProposeAddMember(ctx, gid, carolKP); err != nil {
		t.Fatalf("ProposeAddMember between staging and Confirm: %v", err)
	}
	if _, err := alice.ConfirmPendingCommit(ctx, handle); !errors.Is(err, ErrStalePendingCommit) {
		t.Fatalf("ConfirmPendingCommit after a new proposal = %v, want ErrStalePendingCommit", err)
	}
	if err := alice.DiscardPendingCommit(ctx, handle); err != nil {
		t.Fatalf("DiscardPendingCommit: %v", err)
	}

	commit, _, err := alice.CommitPendingProposals(ctx, gid)
	if err != nil {
		t.Fatalf("CommitPendingProposals (it must include the kept proposal): %v", err)
	}
	if err := bob.ProcessCommit(ctx, bobGid, commit); err != nil {
		t.Fatalf("bob ProcessCommit(commit with the proposal): %v", err)
	}
	requireSameEpochAndSecrets(t, alice, gid, bob, bobGid, 2)
}

// TestConfirmPendingCommitAfterSendMerges checks that a message sent between staging and Confirm does not make
// the handle stale: the secret tree of the epoch is replaced when the commit is merged.
func TestConfirmPendingCommitAfterSendMerges(t *testing.T) {
	ctx := context.Background()
	alice, bob, gid, bobGid := newStagedCommitPair(t)

	handle, err := alice.CommitPendingProposalsStaged(ctx, gid)
	if err != nil {
		t.Fatalf("CommitPendingProposalsStaged: %v", err)
	}
	if _, err := alice.SendMessage(ctx, gid, []byte("m1")); err != nil {
		t.Fatalf("SendMessage between staging and Confirm: %v", err)
	}
	if _, err := alice.ConfirmPendingCommit(ctx, handle); err != nil {
		t.Fatalf("ConfirmPendingCommit after a message was sent: %v", err)
	}
	if err := bob.ProcessCommit(ctx, bobGid, handle.CommitBytes()); err != nil {
		t.Fatalf("bob ProcessCommit(confirmed commit): %v", err)
	}
	requireSameEpochAndSecrets(t, alice, gid, bob, bobGid, 2)
}

// TestConfirmPendingCommitAfterReceiveMerges checks that a message received between staging and Confirm changes
// only the secret tree of the epoch, so the commit stays valid.
func TestConfirmPendingCommitAfterReceiveMerges(t *testing.T) {
	ctx := context.Background()
	alice, bob, gid, bobGid := newStagedCommitPair(t)

	ct, err := bob.SendMessage(ctx, bobGid, []byte("hello"))
	if err != nil {
		t.Fatalf("bob SendMessage: %v", err)
	}
	handle, err := alice.CommitPendingProposalsStaged(ctx, gid)
	if err != nil {
		t.Fatalf("CommitPendingProposalsStaged: %v", err)
	}
	rx, err := alice.ReceiveMessage(ctx, gid, ct)
	if err != nil {
		t.Fatalf("alice ReceiveMessage between staging and Confirm: %v", err)
	}
	if string(rx.Plaintext) != "hello" {
		t.Fatalf("plaintext = %q, want \"hello\"", rx.Plaintext)
	}
	if _, err := alice.ConfirmPendingCommit(ctx, handle); err != nil {
		t.Fatalf("ConfirmPendingCommit after a message was received: %v", err)
	}
	if err := bob.ProcessCommit(ctx, bobGid, handle.CommitBytes()); err != nil {
		t.Fatalf("bob ProcessCommit(confirmed commit): %v", err)
	}
	requireSameEpochAndSecrets(t, alice, gid, bob, bobGid, 2)
}

// TestConfirmPendingCommitWithProposalStoredBeforeStaging checks that a proposal stored before staging does not
// make the handle stale: the fingerprint of the state is deterministic, so Confirm still merges the commit.
func TestConfirmPendingCommitWithProposalStoredBeforeStaging(t *testing.T) {
	ctx := context.Background()
	alice, bob, gid, bobGid := newStagedCommitPair(t)
	carol, err := NewClient([]byte("carol"), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("NewClient(carol): %v", err)
	}
	carolKP, err := carol.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(carol): %v", err)
	}
	if _, err := alice.ProposeAddMember(ctx, gid, carolKP); err != nil {
		t.Fatalf("ProposeAddMember before staging: %v", err)
	}

	handle, err := alice.CommitPendingProposalsStaged(ctx, gid)
	if err != nil {
		t.Fatalf("CommitPendingProposalsStaged: %v", err)
	}
	if _, err := alice.ConfirmPendingCommit(ctx, handle); err != nil {
		t.Fatalf("ConfirmPendingCommit with no change in between: %v", err)
	}
	if err := bob.ProcessCommit(ctx, bobGid, handle.CommitBytes()); err != nil {
		t.Fatalf("bob ProcessCommit(confirmed commit): %v", err)
	}
	requireSameEpochAndSecrets(t, alice, gid, bob, bobGid, 2)
}

// TestPersistGroupRefusesOlderSenderGeneration checks that persistGroup does not write a sender generation
// lower than the last one it wrote in the same epoch: a snapshot taken before m1 cannot make the sequence
// number that m1 used available again.
func TestPersistGroupRefusesOlderSenderGeneration(t *testing.T) {
	ctx := context.Background()
	alice, _, gid, _ := newStagedCommitPair(t)

	entry, old, err := alice.lockGroup(ctx, gid)
	if err != nil {
		t.Fatalf("lockGroup: %v", err)
	}
	entry.mu.Unlock()
	// old is the state before the message: the sender generation of its own leaf is 0.
	if _, err := alice.SendMessage(ctx, gid, []byte("m1")); err != nil {
		t.Fatalf("SendMessage(m1): %v", err)
	}

	entry.mu.Lock()
	err = alice.persistGroup(ctx, old, entry)
	entry.mu.Unlock()
	if !errors.Is(err, errSenderGenerationRewind) {
		t.Fatalf("persistGroup(snapshot from before m1) = %v, want errSenderGenerationRewind", err)
	}
	if seq, present := storedSenderSequence(t, alice, gid); !present || seq != 1 {
		t.Fatalf("the stored sender generation changed: seq=%d present=%v, want seq=1", seq, present)
	}
}

// TestPendingCommitWithoutInterleavedWrites checks the same sequences as the tests above when nothing writes
// between staging and the resolution of the handle: Discard keeps epoch 1 and the next commit of bob applies,
// messages after a Discard keep their order, and Confirm leaves both members in the same epoch.
func TestPendingCommitWithoutInterleavedWrites(t *testing.T) {
	t.Run("discard then a commit from bob", func(t *testing.T) {
		ctx := context.Background()
		alice, bob, gid, bobGid := newStagedCommitPair(t)
		handle, err := alice.CommitPendingProposalsStaged(ctx, gid)
		if err != nil {
			t.Fatalf("CommitPendingProposalsStaged: %v", err)
		}
		if err := alice.DiscardPendingCommit(ctx, handle); err != nil {
			t.Fatalf("DiscardPendingCommit: %v", err)
		}
		if got := groupEpochOf(t, alice, gid); got != 1 {
			t.Fatalf("epoch after Discard = %d, want 1", got)
		}
		winningCommit(t, alice, gid, bob, bobGid)
		requireSameEpochAndSecrets(t, alice, gid, bob, bobGid, 2)
	})

	t.Run("messages after a discard", func(t *testing.T) {
		ctx := context.Background()
		alice, bob, gid, bobGid := newStagedCommitPair(t, WithCacheStrategy(CacheAlways))
		seqBefore, _ := storedSenderSequence(t, alice, gid)
		handle, err := alice.CommitPendingProposalsStaged(ctx, gid)
		if err != nil {
			t.Fatalf("CommitPendingProposalsStaged: %v", err)
		}
		if err := alice.DiscardPendingCommit(ctx, handle); err != nil {
			t.Fatalf("DiscardPendingCommit: %v", err)
		}
		if seqAfter, _ := storedSenderSequence(t, alice, gid); seqAfter != seqBefore {
			t.Fatalf("Discard changed the stored sequence number: %d -> %d", seqBefore, seqAfter)
		}
		for _, text := range []string{"m1", "m2"} {
			ct, err := alice.SendMessage(ctx, gid, []byte(text))
			if err != nil {
				t.Fatalf("SendMessage(%s): %v", text, err)
			}
			rx, err := bob.ReceiveMessage(ctx, bobGid, ct)
			if err != nil {
				t.Fatalf("bob ReceiveMessage(%s): %v", text, err)
			}
			if string(rx.Plaintext) != text {
				t.Fatalf("plaintext = %q, want %q", rx.Plaintext, text)
			}
		}
	})

	t.Run("confirm", func(t *testing.T) {
		ctx := context.Background()
		alice, bob, gid, bobGid := newStagedCommitPair(t)
		handle, err := alice.CommitPendingProposalsStaged(ctx, gid)
		if err != nil {
			t.Fatalf("CommitPendingProposalsStaged: %v", err)
		}
		if _, err := alice.ConfirmPendingCommit(ctx, handle); err != nil {
			t.Fatalf("ConfirmPendingCommit: %v", err)
		}
		if err := bob.ProcessCommit(ctx, bobGid, handle.CommitBytes()); err != nil {
			t.Fatalf("bob ProcessCommit(confirmed commit): %v", err)
		}
		requireSameEpochAndSecrets(t, alice, gid, bob, bobGid, 2)
	})
}
