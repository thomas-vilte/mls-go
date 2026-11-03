//go:build diagnostics

package main

import (
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
)

// decryptForgedReason runs framing.Decrypt on the forged PrivateMessage with the same parameters as
// extractByReferenceProposal and returns its error. A rejected signature consumes no generation, so the
// call does not disturb the receiver.
func decryptForgedReason(t *testing.T, g *group.Group, forged []byte) error {
	t.Helper()
	msg, err := framing.UnmarshalMLSMessage(forged)
	if err != nil || msg.PrivateMessage == nil {
		t.Fatalf("SETUP: forged bytes are not a PrivateMessage: %v", err)
	}
	_, err = framing.Decrypt(msg.PrivateMessage, framing.DecryptParams{
		CipherSuite:      g.CipherSuite(),
		SenderDataSecret: g.EpochSecrets().SenderDataSecret,
		SecretTree:       g.SecretTree(),
		VerifySignature:  g.VerifySenderSignature,
		GroupContext:     g.GroupContext().Marshal(),
	})
	return err
}

// TestByReferenceForgeryIsRejectedOnSignature checks that the signature check is what rejects the forged
// by-reference proposal: framing.Decrypt with the handler's parameters must return *group.ErrInvalidSignature.
// The forged message has a valid AEAD, because it is sealed from a fresh tree built from the epoch's
// encryption secret.
func TestByReferenceForgeryIsRejectedOnSignature(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	_, _, kp, privKeys, err := generateCredentialAndKeyPackage([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("generateCredentialAndKeyPackage(alice): %v", err)
	}
	_, forgerSig, _, _, err := generateCredentialAndKeyPackage([]byte("mallory"), cs)
	if err != nil {
		t.Fatalf("generateCredentialAndKeyPackage(mallory): %v", err)
	}
	g, err := group.NewGroup(group.NewGroupID([]byte("forgery")), cs, kp, privKeys)
	if err != nil {
		t.Fatalf("group.NewGroup: %v", err)
	}

	forged := forgedByReferenceMessage(t, g, forgerSig)
	var sigErr *group.ErrInvalidSignature
	if err := decryptForgedReason(t, g, forged); !errors.As(err, &sigErr) {
		t.Fatalf("Decrypt of the forged by-reference proposal: err = %v, want *group.ErrInvalidSignature", err)
	}
}

// TestExtractByReferenceReportsSignatureReason checks that extractByReferenceProposal returns the signature
// error for the same forgery. The function used to fall back to parsing the MLSMessage bytes as a raw
// proposal when Decrypt failed, and its parse error hid the signature error.
func TestExtractByReferenceReportsSignatureReason(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	_, _, kp, privKeys, err := generateCredentialAndKeyPackage([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("generateCredentialAndKeyPackage(alice): %v", err)
	}
	_, forgerSig, _, _, err := generateCredentialAndKeyPackage([]byte("mallory"), cs)
	if err != nil {
		t.Fatalf("generateCredentialAndKeyPackage(mallory): %v", err)
	}
	g, err := group.NewGroup(group.NewGroupID([]byte("forgery-mask")), cs, kp, privKeys)
	if err != nil {
		t.Fatalf("group.NewGroup: %v", err)
	}

	forged := forgedByReferenceMessage(t, g, forgerSig)
	_, _, _, err = extractByReferenceProposal(forged, g)
	if err == nil {
		t.Fatal("forged by-reference proposal was accepted")
	}
	var sigErr *group.ErrInvalidSignature
	if !errors.As(err, &sigErr) {
		t.Errorf("extractByReferenceProposal hides the signature error; it returns %q", err.Error())
	}
}

// TestRepeatedForgeriesDoNotBurnGeneration checks that forgeries from three other keys at generation 0, each
// refused for its signature, do not prevent the honest proposal at generation 0 from being accepted.
func TestRepeatedForgeriesDoNotBurnGeneration(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	_, sigPriv, kp, privKeys, err := generateCredentialAndKeyPackage([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("generateCredentialAndKeyPackage(alice): %v", err)
	}
	g, err := group.NewGroup(group.NewGroupID([]byte("forgery-rep")), cs, kp, privKeys)
	if err != nil {
		t.Fatalf("group.NewGroup: %v", err)
	}

	for _, name := range []string{"mallory", "eve", "trudy"} {
		_, forgerSig, _, _, err := generateCredentialAndKeyPackage([]byte(name), cs)
		if err != nil {
			t.Fatalf("generateCredentialAndKeyPackage(%s): %v", name, err)
		}
		forged := forgedByReferenceMessage(t, g, forgerSig)
		var sigErr *group.ErrInvalidSignature
		if err := decryptForgedReason(t, g, forged); !errors.As(err, &sigErr) {
			t.Fatalf("forgery by %s: Decrypt err = %v, want *group.ErrInvalidSignature", name, err)
		}
	}

	genuine := forgedByReferenceMessage(t, g, sigPriv)
	if _, _, _, err := extractByReferenceProposal(genuine, g); err != nil {
		t.Fatalf("honest generation 0 refused after three forgeries: %v", err)
	}
}
