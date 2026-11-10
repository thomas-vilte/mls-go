package group

import (
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
)

// newMemberProposalMessage builds a new_member_proposal PublicMessage that carries an Add of
// joiner's KeyPackage, with the outer signature made by signer. RFC 9420 §6.1: the TBS of a
// new_member_proposal has no GroupContext, and the signature key is the one in the LeafNode of
// the KeyPackage embedded in the Add. RFC 9420 §6.2: the message carries no membership_tag.
func newMemberProposalMessage(t *testing.T, g *Group, joiner *testUser, signer *ciphersuite.SignaturePrivateKey) *framing.PublicMessage {
	t.Helper()
	content := framing.FramedContent{
		GroupID: g.groupID.AsSlice(),
		Epoch:   g.epoch.AsUint64(),
		Sender:  framing.Sender{Type: framing.SenderTypeNewMemberProposal},
		Body:    framing.ProposalBody{Data: ProposalMarshal(NewAddProposal(joiner.kp))},
	}
	ac := &framing.AuthenticatedContent{
		WireFormat:   framing.WireFormatPublicMessage,
		Content:      content,
		GroupContext: g.groupContext.Marshal(),
	}
	sig, err := ciphersuite.SignWithLabel(signer, "FramedContentTBS", ac.MarshalTBS())
	if err != nil {
		t.Fatalf("SignWithLabel: %v", err)
	}
	return &framing.PublicMessage{
		Content: content,
		Auth:    framing.FramedContentAuthData{Signature: sig},
	}
}

// TestProcessPublicMessage_NewMemberProposal_OuterSignature checks the receive path: the outer signature of a
// new_member_proposal must verify with the KeyPackage key (RFC 9420 §6.1, §12.1.8) before the proposal is stored.
func TestProcessPublicMessage_NewMemberProposal_OuterSignature(t *testing.T) {
	t.Run("valid signature by the KeyPackage key is accepted", func(t *testing.T) {
		aliceGroup, _, _, _ := makeTwoMemberGroups(t)
		charlie := newTestUser(t, "charlie-nmp-valid")
		pm := newMemberProposalMessage(t, aliceGroup, charlie, charlie.sigPriv)

		before := len(aliceGroup.Proposals().Proposals)
		if err := aliceGroup.ProcessPublicMessage(pm); err != nil {
			t.Fatalf("ProcessPublicMessage(valid new_member_proposal): %v", err)
		}
		if got := len(aliceGroup.Proposals().Proposals); got != before+1 {
			t.Fatalf("stored proposals = %d, want %d", got, before+1)
		}
	})

	t.Run("signature by another member key is rejected and nothing is stored", func(t *testing.T) {
		aliceGroup, _, _, bob := makeTwoMemberGroups(t)
		charlie := newTestUser(t, "charlie-nmp-forged")
		pm := newMemberProposalMessage(t, aliceGroup, charlie, bob.sigPriv)

		before := len(aliceGroup.Proposals().Proposals)
		if err := aliceGroup.ProcessPublicMessage(pm); err == nil {
			t.Fatal("ProcessPublicMessage accepted a new_member_proposal not signed by its KeyPackage key")
		}
		if got := len(aliceGroup.Proposals().Proposals); got != before {
			t.Fatalf("rejected new_member_proposal was stored: %d proposals, want %d", got, before)
		}
	})

	t.Run("tampered signature is rejected and nothing is stored", func(t *testing.T) {
		aliceGroup, _, _, _ := makeTwoMemberGroups(t)
		charlie := newTestUser(t, "charlie-nmp-tampered")
		pm := newMemberProposalMessage(t, aliceGroup, charlie, charlie.sigPriv)
		sigBytes := pm.Auth.Signature.AsSlice()
		sigBytes[0] ^= 0xFF

		before := len(aliceGroup.Proposals().Proposals)
		if err := aliceGroup.ProcessPublicMessage(pm); err == nil {
			t.Fatal("ProcessPublicMessage accepted a new_member_proposal with a tampered signature")
		}
		if got := len(aliceGroup.Proposals().Proposals); got != before {
			t.Fatalf("rejected new_member_proposal was stored: %d proposals, want %d", got, before)
		}
	})
}
