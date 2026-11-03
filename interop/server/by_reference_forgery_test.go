package main

import (
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/secrettree"
)

// forgedByReferenceMessage returns an MLSMessage carrying a PrivateMessage with a Remove proposal from leaf 0, signed
// with sigKey. Every member holds the epoch's encryption secret, so a fresh secret tree built from it seals the
// proposal at generation 0, the generation the receiver's tree opens it with.
func forgedByReferenceMessage(t *testing.T, g *group.Group, sigKey *ciphersuite.SignaturePrivateKey) []byte {
	t.Helper()
	cs := g.CipherSuite()
	tree, err := secrettree.NewTree(g.EpochSecrets().EncryptionSecret.Clone(), 1, cs)
	if err != nil {
		t.Fatalf("secrettree.NewTree: %v", err)
	}
	pm, err := framing.Encrypt(framing.EncryptParams{
		Content: framing.FramedContent{
			GroupID:           g.ID().AsSlice(),
			Epoch:             g.Epoch().AsUint64(),
			Sender:            framing.Sender{Type: framing.SenderTypeMember, LeafIndex: 0},
			AuthenticatedData: []byte{},
			Body:              framing.ProposalBody{Data: group.ProposalMarshal(group.NewRemoveProposal(0))},
		},
		SenderLeafIndex:  0,
		CipherSuite:      cs,
		SenderDataSecret: g.EpochSecrets().SenderDataSecret,
		SecretTree:       tree,
		SigKey:           sigKey,
		GroupContext:     g.GroupContext().Marshal(),
	})
	if err != nil {
		t.Fatalf("framing.Encrypt: %v", err)
	}
	return framing.NewMLSMessagePrivate(pm).Marshal()
}

// TestByReferenceProposalForgeryDoesNotConsumeGeneration checks the path that resolves a by-reference
// proposal sent as a PrivateMessage. A proposal with a valid AEAD and an invalid signature must be refused,
// and it must not consume the generation of the honest proposal that follows it at the same generation
// (RFC 9420 §6.1, §9.2).
func TestByReferenceProposalForgeryDoesNotConsumeGeneration(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	_, sigPriv, kp, privKeys, err := generateCredentialAndKeyPackage([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("generateCredentialAndKeyPackage(alice): %v", err)
	}
	_, forgerSig, _, _, err := generateCredentialAndKeyPackage([]byte("mallory"), cs)
	if err != nil {
		t.Fatalf("generateCredentialAndKeyPackage(mallory): %v", err)
	}
	g, err := group.NewGroup(group.NewGroupID([]byte("by-reference")), cs, kp, privKeys)
	if err != nil {
		t.Fatalf("group.NewGroup: %v", err)
	}

	forged := forgedByReferenceMessage(t, g, forgerSig)
	if _, _, _, err := extractByReferenceProposal(forged, g); err == nil {
		t.Fatalf("by-reference proposal with an invalid signature was accepted")
	}
	genuine := forgedByReferenceMessage(t, g, sigPriv)
	if _, _, _, err := extractByReferenceProposal(genuine, g); err != nil {
		t.Fatalf("honest by-reference proposal at generation 0 refused after a forged one: %v", err)
	}
}
