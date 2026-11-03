package main

import (
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
)

// TestByReferenceForgeryReportsSignature checks the reason of the rejection. A by-reference proposal sent as
// a PrivateMessage with a valid AEAD and an invalid signature must be refused with the signature error. The
// function used to fall back to parsing the MLSMessage bytes as a raw proposal, and it returned that parse
// error, which does not say that the signature was the cause. The honest proposal at the same generation
// must still be accepted.
func TestByReferenceForgeryReportsSignature(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	_, sigPriv, kp, privKeys, err := generateCredentialAndKeyPackage([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("generateCredentialAndKeyPackage(alice): %v", err)
	}
	_, forgerSig, _, _, err := generateCredentialAndKeyPackage([]byte("mallory"), cs)
	if err != nil {
		t.Fatalf("generateCredentialAndKeyPackage(mallory): %v", err)
	}
	g, err := group.NewGroup(group.NewGroupID([]byte("by-reference-reason")), cs, kp, privKeys)
	if err != nil {
		t.Fatalf("group.NewGroup: %v", err)
	}

	forged := forgedByReferenceMessage(t, g, forgerSig)
	_, _, _, err = extractByReferenceProposal(forged, g)
	var sigErr *group.ErrInvalidSignature
	if !errors.As(err, &sigErr) {
		t.Fatalf("extractByReferenceProposal(forged) err = %v, want the signature rejection (*group.ErrInvalidSignature)", err)
	}

	genuine := forgedByReferenceMessage(t, g, sigPriv)
	if _, _, _, err := extractByReferenceProposal(genuine, g); err != nil {
		t.Fatalf("honest by-reference proposal at generation 0 refused after a forged one: %v", err)
	}
}
