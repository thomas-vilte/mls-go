package mls

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/schedule"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

// commitWithBadConfirmationTag returns commit with one bit of its confirmation_tag flipped. The membership_tag
// covers the confirmation_tag (RFC 9420 §6.2), so it is recomputed with the membership key of bob's
// current epoch. The signature does not cover the tag and stays valid. The returned message therefore
// passes every check before the confirmation_tag check of MergeCommit.
func commitWithBadConfirmationTag(t *testing.T, bob *Client, groupID, commit []byte) []byte {
	t.Helper()
	msg, err := framing.UnmarshalMLSMessage(commit)
	if err != nil {
		t.Fatalf("UnmarshalMLSMessage: %v", err)
	}
	pm, ok := msg.AsPublic()
	if !ok {
		t.Fatal("SETUP: commit is not a PublicMessage")
	}
	if len(pm.Auth.ConfirmationTag) == 0 {
		t.Fatal("SETUP: commit has no confirmation tag")
	}

	g := loadGroupForTest(t, bob, groupID)
	cs := g.CipherSuite()
	membershipKey := g.EpochSecrets().MembershipKey
	gcBytes := g.GroupContext().Marshal()

	auth := pm.Auth
	auth.ConfirmationTag = append([]byte(nil), pm.Auth.ConfirmationTag...)
	auth.ConfirmationTag[0] ^= 0x01

	ct := pm.Content.ContentType()
	ac := &framing.AuthenticatedContent{
		WireFormat:   framing.WireFormatPublicMessage,
		Content:      pm.Content,
		Auth:         auth,
		GroupContext: gcBytes,
	}
	// TBM = FramedContentTBS || FramedContentAuthData, as framing computes it for the membership_tag.
	tbm := append(ac.MarshalTBS(), auth.Marshal(ct)...)
	tampered := &framing.PublicMessage{
		Content:       pm.Content,
		Auth:          auth,
		MembershipTag: schedule.ComputeMembershipTag(cs, membershipKey.AsSlice(), tbm),
	}
	// Setup check: the forged message must pass the membership check, so only the tag check can reject it.
	if err := tampered.VerifyMembershipTagWithContext(cs, membershipKey, gcBytes); err != nil {
		t.Fatalf("SETUP: tampered commit fails the membership check: %v", err)
	}
	return framing.NewMLSMessagePublic(tampered).Marshal()
}

// TestRejectedCommitLeavesClientGroupUnchanged checks that bob rejects a commit whose confirmation_tag is
// invalid and that the group is unchanged, so Alice's legitimate commit is still accepted afterwards. With
// CacheAlways the Client keeps the loaded group in memory between calls, so a rejected commit that left partial
// changes there would block the next commit (epoch mismatch).
func TestRejectedCommitLeavesClientGroupUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name     string
		strategy CacheStrategy
	}{
		{"CacheNone", CacheNone},
		{"CacheAlways", CacheAlways},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			alice, bob, gid := newTwoMemberClientGroup(t, memorystore.NewStore(), tc.strategy)

			// Alice's self-update is a valid commit for epoch 1. Bob has not processed it yet.
			commit, err := alice.SelfUpdate(ctx, gid)
			if err != nil {
				t.Fatalf("SelfUpdate: %v", err)
			}
			tampered := commitWithBadConfirmationTag(t, bob, gid, commit)

			before, err := loadGroupForTest(t, bob, gid).MarshalState()
			if err != nil {
				t.Fatalf("MarshalState before rejected commit: %v", err)
			}

			err = bob.ProcessCommit(ctx, gid, tampered)
			if !errors.Is(err, group.ErrConfirmationTagMismatch) {
				t.Fatalf("ProcessCommit(tampered) = %v, want ErrConfirmationTagMismatch", err)
			}

			after, err := loadGroupForTest(t, bob, gid).MarshalState()
			if err != nil {
				t.Fatalf("MarshalState after rejected commit: %v", err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("rejected commit changed the stored group state")
			}

			if err := bob.ProcessCommit(ctx, gid, commit); err != nil {
				t.Fatalf("ProcessCommit(legitimate) after rejected commit: %v", err)
			}
			if got := loadGroupForTest(t, bob, gid).Epoch().AsUint64(); got != 2 {
				t.Fatalf("epoch after legitimate commit = %d, want 2", got)
			}
		})
	}
}
