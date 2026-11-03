package group

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
)

// sealPrivateMessage encrypts body as a PrivateMessage from leaf, signed with sigKey, under the epoch secrets of g.
// Every member holds the epoch's secret tree, so any member can produce content that passes the AEAD for any
// leaf. Only the signature ties the message to the leaf's owner.
func sealPrivateMessage(t *testing.T, g *Group, sigKey *ciphersuite.SignaturePrivateKey, leaf uint32, body framing.FramedContentBody) *framing.PrivateMessage {
	t.Helper()
	pm, err := framing.Encrypt(framing.EncryptParams{
		Content: framing.FramedContent{
			GroupID:           g.groupID.AsSlice(),
			Epoch:             g.epoch.AsUint64(),
			Sender:            framing.Sender{Type: framing.SenderTypeMember, LeafIndex: leaf},
			AuthenticatedData: []byte{},
			Body:              body,
		},
		SenderLeafIndex:  leaf,
		CipherSuite:      g.cipherSuite,
		SenderDataSecret: g.epochSecrets.SenderDataSecret,
		SecretTree:       g.secretTree,
		SigKey:           sigKey,
		GroupContext:     g.groupContext.Marshal(),
	})
	if err != nil {
		t.Fatalf("framing.Encrypt: %v", err)
	}
	return pm
}

// TestForgedSignatureDoesNotConsumeGeneration checks that a message with a valid AEAD and an invalid
// signature does not consume the generation of the honest message that follows it at the same generation.
// The receiver checks the signature before it records the generation and before the ratchet moves
// (RFC 9420 §6.1, §9.2).
func TestForgedSignatureDoesNotConsumeGeneration(t *testing.T) {
	t.Run("ReceiveApplicationMessage", func(t *testing.T) {
		aliceGroup, bobGroup, alice, bob := makeTwoMemberGroups(t)
		m0, err := aliceGroup.SendMessage([]byte("m0 from alice"), alice.sigPriv)
		if err != nil {
			t.Fatalf("alice SendMessage: %v", err)
		}
		forged := sealPrivateMessage(t, bobGroup, bob.sigPriv, uint32(aliceGroup.ownLeafIndex), framing.ApplicationData{Data: []byte("forged")})
		if _, _, _, err := bobGroup.ReceiveApplicationMessage(forged); err == nil {
			t.Fatalf("forged message with an invalid signature was accepted")
		}
		got, _, _, err := bobGroup.ReceiveApplicationMessage(m0)
		if err != nil {
			t.Fatalf("honest generation 0 refused after a forged message with the same generation: %v", err)
		}
		if !bytes.Equal(got, []byte("m0 from alice")) {
			t.Fatalf("plaintext = %q, want %q", got, "m0 from alice")
		}
	})

	t.Run("ReceiveMessage", func(t *testing.T) {
		aliceGroup, bobGroup, alice, bob := makeTwoMemberGroups(t)
		m0, err := aliceGroup.SendMessage([]byte("m0 from alice"), alice.sigPriv)
		if err != nil {
			t.Fatalf("alice SendMessage: %v", err)
		}
		forged := sealPrivateMessage(t, bobGroup, bob.sigPriv, uint32(aliceGroup.ownLeafIndex), framing.ApplicationData{Data: []byte("forged")})
		if _, err := bobGroup.ReceiveMessage(forged, aliceGroup.ownLeafIndex); err == nil {
			t.Fatalf("forged message with an invalid signature was accepted")
		}
		got, err := bobGroup.ReceiveMessage(m0, aliceGroup.ownLeafIndex)
		if err != nil {
			t.Fatalf("honest generation 0 refused after a forged message with the same generation: %v", err)
		}
		if !bytes.Equal(got, []byte("m0 from alice")) {
			t.Fatalf("plaintext = %q, want %q", got, "m0 from alice")
		}
	})

	// A Remove proposal in a PrivateMessage uses the handshake ratchet, so this subtest covers the path
	// that ProcessPrivateMessage takes for proposals and commits.
	t.Run("ProcessPrivateMessage", func(t *testing.T) {
		aliceGroup, bobGroup, alice, bob := makeTwoMemberGroups(t)
		remove := framing.ProposalBody{Data: ProposalMarshal(NewRemoveProposal(bobGroup.ownLeafIndex))}
		forged := sealPrivateMessage(t, bobGroup, bob.sigPriv, uint32(aliceGroup.ownLeafIndex), remove)
		if err := bobGroup.ProcessPrivateMessage(forged); err == nil {
			t.Fatalf("forged proposal with an invalid signature was accepted")
		}
		genuine := sealPrivateMessage(t, aliceGroup, alice.sigPriv, uint32(aliceGroup.ownLeafIndex), remove)
		if err := bobGroup.ProcessPrivateMessage(genuine); err != nil {
			t.Fatalf("honest handshake generation 0 refused after a forged message with the same generation: %v", err)
		}
	})

	// Control: the same exchange without a forged message must deliver every message.
	t.Run("control", func(t *testing.T) {
		aliceGroup, bobGroup, alice, _ := makeTwoMemberGroups(t)
		for _, text := range []string{"m0 from alice", "m1 from alice"} {
			pm, err := aliceGroup.SendMessage([]byte(text), alice.sigPriv)
			if err != nil {
				t.Fatalf("alice SendMessage(%q): %v", text, err)
			}
			got, err := bobGroup.ReceiveMessage(pm, aliceGroup.ownLeafIndex)
			if err != nil {
				t.Fatalf("ReceiveMessage(%q): %v", text, err)
			}
			if !bytes.Equal(got, []byte(text)) {
				t.Fatalf("plaintext = %q, want %q", got, text)
			}
		}
	})
}
