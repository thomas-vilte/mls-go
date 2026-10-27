package framing_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/secrettree"
)

// TestDecryptRejectsExcessiveForwardDistance checks the generation jump limit
// through framing.Decrypt. Both sender branches share the epoch secrets and
// signing key, so the jump message is cryptographically valid. Rejecting it must
// preserve the receiver's ratchet and allow the next honest message to decrypt.
func TestDecryptRejectsExcessiveForwardDistance(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	rootBytes := bytes.Repeat([]byte{0x42}, 32)
	sdSecretBytes := bytes.Repeat([]byte{0x99}, 32)
	gcBytes := []byte("serialized-group-context")
	sigPriv, sigPub := makeSigKeyPair(t, cs)

	newTree := func() *secrettree.Tree {
		t.Helper()
		tree, err := secrettree.NewTree(ciphersuite.NewSecret(rootBytes), 2, cs)
		if err != nil {
			t.Fatalf("NewTree: %v", err)
		}
		return tree
	}
	legitTree := newTree() // legitimate sender of leaf 0
	jumpTree := newTree()  // sender branch for the excessive jump
	recvTree := newTree()  // receiver

	encrypt := func(tree *secrettree.Tree, data string) *framing.PrivateMessage {
		t.Helper()
		pm, err := framing.Encrypt(framing.EncryptParams{
			Content: framing.FramedContent{
				GroupID:           []byte("test-group-id"),
				Epoch:             1,
				Sender:            framing.Sender{Type: framing.SenderTypeMember, LeafIndex: 0},
				AuthenticatedData: []byte("aad"),
				Body:              framing.ApplicationData{Data: []byte(data)},
			},
			SenderLeafIndex:  0,
			CipherSuite:      cs,
			SenderDataSecret: ciphersuite.NewSecret(sdSecretBytes),
			SecretTree:       tree,
			SigKey:           sigPriv,
			GroupContext:     gcBytes,
		})
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", data, err)
		}
		return pm
	}
	decryptParams := framing.DecryptParams{
		CipherSuite:      cs,
		SenderDataSecret: ciphersuite.NewSecret(sdSecretBytes),
		SecretTree:       recvTree,
		SigPubKey:        sigPub,
		GroupContext:     gcBytes,
	}

	// Accept generation 0 before testing an excessive forward jump.
	legit0 := encrypt(legitTree, "first")
	if _, err := framing.Decrypt(legit0, decryptParams); err != nil {
		t.Fatalf("Decrypt(legitimate generation 0): %v", err)
	}

	// Generate 1100 filler messages, then keep the message at generation 1100.
	// It is 100 steps beyond the default forward window of 1000.
	const jumpGen = 1100
	for range jumpGen {
		encrypt(jumpTree, "filler")
	}
	jumpMessage := encrypt(jumpTree, "jump")

	start := time.Now()
	if _, err := framing.Decrypt(jumpMessage, decryptParams); err == nil {
		t.Fatalf("Decrypt(generation %d) succeeded, want rejection beyond the forward window", jumpGen)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("Decrypt(generation %d) rejected after %v, want < 50ms", jumpGen, elapsed)
	}

	recvLeaf, err := recvTree.LeafForIndex(0)
	if err != nil {
		t.Fatalf("LeafForIndex(0): %v", err)
	}
	if got := recvLeaf.CurrentGeneration(); got != 0 {
		t.Fatalf("receiver leaf moved to generation %d by the rejected message, want 0", got)
	}

	// Legitimate generation 1 from the same leaf still decrypts after the rejection.
	legit1 := encrypt(legitTree, "second")
	if _, err := framing.Decrypt(legit1, decryptParams); err != nil {
		t.Fatalf("Decrypt(legitimate generation 1) after rejected jump: %v", err)
	}
}
