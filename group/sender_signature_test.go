package group

import (
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/treesync"
)

// TestVerifyLeafSignatureRejectsInvalidSenders checks every way a sender can be refused before its
// signature is verified (RFC 9420 §6.1).
func TestVerifyLeafSignatureRejectsInvalidSenders(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	tbs := []byte("tbs")

	t.Run("no_ratchet_tree", func(t *testing.T) {
		if err := verifyLeafSignature(nil, cs, 0, tbs, nil); !errors.Is(err, ErrRatchetTreeMissing) {
			t.Fatalf("err = %v, want ErrRatchetTreeMissing", err)
		}
	})

	t.Run("leaf_out_of_range", func(t *testing.T) {
		tree := treesync.NewRatchetTree(2, cs)
		var unknown *ErrUnknownMember
		if err := verifyLeafSignature(tree, cs, 2, tbs, nil); !errors.As(err, &unknown) || unknown.LeafIndex != 2 {
			t.Fatalf("err = %v, want ErrUnknownMember for leaf 2", err)
		}
	})

	t.Run("blank_leaf", func(t *testing.T) {
		tree := treesync.NewRatchetTree(2, cs)
		if err := verifyLeafSignature(tree, cs, 1, tbs, nil); !errors.Is(err, ErrSenderNotActive) {
			t.Fatalf("err = %v, want ErrSenderNotActive", err)
		}
	})

	t.Run("present_leaf_without_signature_key", func(t *testing.T) {
		tree := treesync.NewRatchetTree(2, cs)
		tree.Nodes[0] = treesync.Node{State: treesync.NodeStatePresent, LeafData: &treesync.LeafNodeData{}}
		if err := verifyLeafSignature(tree, cs, 0, tbs, nil); !errors.Is(err, ErrMissingSenderSignature) {
			t.Fatalf("err = %v, want ErrMissingSenderSignature", err)
		}
	})
}

// TestVerifySenderSignatureInvalidSignature checks that a member's signature over other content is
// refused with ErrInvalidSignature.
func TestVerifySenderSignatureInvalidSignature(t *testing.T) {
	aliceGroup, _, alice, _ := makeTwoMemberGroups(t)

	sig, err := ciphersuite.SignWithLabel(alice.sigPriv, "FramedContentTBS", []byte("signed content"))
	if err != nil {
		t.Fatalf("SignWithLabel: %v", err)
	}
	if err := aliceGroup.VerifySenderSignature(0, []byte("signed content"), sig); err != nil {
		t.Fatalf("VerifySenderSignature with a valid signature: %v", err)
	}
	var invalid *ErrInvalidSignature
	if err := aliceGroup.VerifySenderSignature(0, []byte("other content"), sig); !errors.As(err, &invalid) {
		t.Fatalf("err = %v, want ErrInvalidSignature", err)
	}
}
