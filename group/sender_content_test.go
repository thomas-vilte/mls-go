package group

import (
	"errors"
	"fmt"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/treesync"
)

// forgeCommitSender copies ac with sender type st and a zero signature.
// The leaf index is preserved so the update path remains unchanged.
func forgeCommitSender(ac *framing.AuthenticatedContent, st framing.SenderType) *framing.AuthenticatedContent {
	forged := *ac
	forged.Content.Sender.Type = st
	forged.Content.Sender.SenderIndex = 0
	forged.Auth = framing.FramedContentAuthData{Signature: ciphersuite.NewSignature(make([]byte, 64))}
	return &forged
}

// newSenderTestCommit has bob commit a self-update, which carries an UpdatePath, and returns
// the staged commit without merging it on bob's side.
func newSenderTestCommit(t *testing.T, bobGroup *Group, bob *testUser) *StagedCommit {
	t.Helper()
	if _, err := bobGroup.SelfUpdate(bob.sigPriv); err != nil {
		t.Fatalf("SelfUpdate(bob): %v", err)
	}
	sc, err := bobGroup.Commit(bob.sigPriv, bob.sigPub, nil)
	if err != nil {
		t.Fatalf("Commit(bob): %v", err)
	}
	return sc
}

// newSenderTestPublicMessage builds a PublicMessage with sender type st and content type ct. The
// body is an application message, a Remove proposal or bob's commit, and the signature
// is all zeros, so only the sender/content matrix decides the outcome for disallowed
// pairs.
func newSenderTestPublicMessage(t *testing.T, aliceGroup, bobGroup *Group, bob *testUser, st framing.SenderType, ct framing.ContentType) *framing.PublicMessage {
	t.Helper()
	var body framing.FramedContentBody
	switch ct {
	case framing.ContentTypeApplication:
		body = framing.ApplicationData{Data: []byte("message")}
	case framing.ContentTypeProposal:
		removeProposal := &Proposal{Type: ProposalTypeRemove, Remove: &RemoveProposal{Removed: LeafNodeIndex(1)}}
		body = framing.ProposalBody{Data: ProposalMarshal(removeProposal)}
	case framing.ContentTypeCommit:
		body = newSenderTestCommit(t, bobGroup, bob).authenticatedContent.Content.Body
	}
	sender := framing.Sender{Type: st}
	if st == framing.SenderTypeMember {
		sender.LeafIndex = uint32(bobGroup.ownLeafIndex)
	}
	return &framing.PublicMessage{
		Content: framing.FramedContent{
			GroupID: aliceGroup.groupID.AsSlice(),
			Epoch:   aliceGroup.epoch.AsUint64(),
			Sender:  sender,
			Body:    body,
		},
		Auth: framing.FramedContentAuthData{Signature: ciphersuite.NewSignature(make([]byte, 64))},
	}
}

// TestSenderContentCompatibility checks the sender/content-type combinations
// required by RFC 9420 §6.1 before signature verification or state changes.
func TestSenderContentCompatibility(t *testing.T) {
	// Forged commits: relabelled senders are rejected before any state changes.
	forgedCommits := []struct {
		name string
		st   framing.SenderType
		want error
	}{
		{"external", framing.SenderTypeExternal, framing.ErrInvalidContentType},
		{"new_member_proposal", framing.SenderTypeNewMemberProposal, framing.ErrInvalidContentType},
		{"reserved", framing.SenderType(0), framing.ErrInvalidSenderType},
		{"unknown", framing.SenderType(5), framing.ErrInvalidSenderType},
	}
	for _, tc := range forgedCommits {
		t.Run("forged_commit/"+tc.name, func(t *testing.T) {
			aliceGroup, bobGroup, _, bob := makeTwoMemberGroups(t)
			forged := forgeCommitSender(newSenderTestCommit(t, bobGroup, bob).authenticatedContent, tc.st)
			err := aliceGroup.ProcessReceivedCommit(forged, treesync.LeafIndex(bobGroup.ownLeafIndex),
				aliceGroup.myLeafEncryptionKey,
			)
			if !errors.Is(err, tc.want) {
				t.Fatalf("ProcessReceivedCommit(sender %s) err = %v, want %v", tc.name, err, tc.want)
			}
			if got := aliceGroup.epoch.AsUint64(); got != 1 {
				t.Fatalf("alice epoch = %d after rejected commit, want 1", got)
			}
		})
	}

	// Control: a legitimate member commit is still accepted and advances the epoch.
	t.Run("control/member_commit", func(t *testing.T) {
		aliceGroup, bobGroup, _, bob := makeTwoMemberGroups(t)
		sc := newSenderTestCommit(t, bobGroup, bob)
		if err := bobGroup.MergeCommit(sc); err != nil {
			t.Fatalf("MergeCommit(bob): %v", err)
		}
		if err := aliceGroup.ProcessReceivedCommit(sc.authenticatedContent, treesync.LeafIndex(bobGroup.ownLeafIndex), aliceGroup.myLeafEncryptionKey); err != nil {
			t.Fatalf("ProcessReceivedCommit(member commit): %v", err)
		}
		if got := aliceGroup.epoch.AsUint64(); got != 2 {
			t.Fatalf("alice epoch = %d after member commit, want 2", got)
		}
	})

	// Control: an external commit (new_member_commit, RFC 9420 §12.4.3.2) is still accepted.
	t.Run("control/new_member_commit", func(t *testing.T) {
		alice := newTestUser(t, "alice")
		charlie := newTestUser(t, "charlie")
		groupID, err := NewGroupIDRandom()
		if err != nil {
			t.Fatalf("NewGroupIDRandom: %v", err)
		}
		aliceGroup, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, alice.kp, alice.priv)
		if err != nil {
			t.Fatalf("NewGroup(alice): %v", err)
		}
		groupInfo, err := aliceGroup.GetGroupInfo(alice.sigPriv)
		if err != nil {
			t.Fatalf("GetGroupInfo: %v", err)
		}
		_, staged, err := ExternalCommit(groupInfo, aliceGroup.cipherSuite, charlie.sigPriv, charlie.sigPub, nil, charlie.kp.LeafNode.Credential)
		if err != nil {
			t.Fatalf("ExternalCommit: %v", err)
		}
		if err := aliceGroup.ProcessReceivedCommit(staged.authenticatedContent, treesync.LeafIndex(0), alice.priv.EncryptionKey.Bytes()); err != nil {
			t.Fatalf("ProcessReceivedCommit(external commit): %v", err)
		}
	})

	// Matrix table (RFC 9420 §6.1): 4 sender types x 3 content types through
	// ProcessPublicMessage. Disallowed pairs must fail with the matrix error. Allowed pairs
	// may fail later (the signature is zero), but never with the matrix error.
	allowed := map[framing.SenderType]map[framing.ContentType]bool{
		framing.SenderTypeMember: {
			framing.ContentTypeApplication: true,
			framing.ContentTypeProposal:    true,
			framing.ContentTypeCommit:      true,
		},
		framing.SenderTypeExternal:          {framing.ContentTypeProposal: true},
		framing.SenderTypeNewMemberProposal: {framing.ContentTypeProposal: true},
		framing.SenderTypeNewMemberCommit:   {framing.ContentTypeCommit: true},
	}
	senders := []framing.SenderType{
		framing.SenderTypeMember,
		framing.SenderTypeExternal,
		framing.SenderTypeNewMemberProposal,
		framing.SenderTypeNewMemberCommit,
	}
	contents := []framing.ContentType{
		framing.ContentTypeApplication,
		framing.ContentTypeProposal,
		framing.ContentTypeCommit,
	}
	for _, st := range senders {
		for _, ct := range contents {
			t.Run(fmt.Sprintf("matrix/sender=%d/content=%d", st, ct), func(t *testing.T) {
				aliceGroup, bobGroup, _, bob := makeTwoMemberGroups(t)
				pm := newSenderTestPublicMessage(t, aliceGroup, bobGroup, bob, st, ct)
				err := aliceGroup.ProcessPublicMessage(pm)
				if allowed[st][ct] {
					if errors.Is(err, framing.ErrInvalidContentType) || errors.Is(err, framing.ErrInvalidSenderType) {
						t.Fatalf("allowed pair sender=%d content=%d rejected by the matrix: %v", st, ct, err)
					}
					return
				}
				if !errors.Is(err, framing.ErrInvalidContentType) {
					t.Fatalf("disallowed pair sender=%d content=%d err = %v, want framing.ErrInvalidContentType", st, ct, err)
				}
				if got := aliceGroup.epoch.AsUint64(); got != 1 {
					t.Fatalf("alice epoch = %d after rejected message, want 1", got)
				}
			})
		}
	}

	// Unknown sender types never reach signature verification or content processing.
	for _, st := range []framing.SenderType{framing.SenderType(0), framing.SenderType(5)} {
		for _, ct := range contents {
			t.Run(fmt.Sprintf("matrix/unknown_sender=%d/content=%d", st, ct), func(t *testing.T) {
				aliceGroup, bobGroup, _, bob := makeTwoMemberGroups(t)
				pm := newSenderTestPublicMessage(t, aliceGroup, bobGroup, bob, st, ct)
				if err := aliceGroup.ProcessPublicMessage(pm); !errors.Is(err, framing.ErrInvalidSenderType) {
					t.Fatalf("ProcessPublicMessage(sender=%d content=%d) err = %v, want framing.ErrInvalidSenderType", st, ct, err)
				}
			})
		}
	}
}
