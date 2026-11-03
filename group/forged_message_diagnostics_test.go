//go:build diagnostics

package group

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/secrettree"
)

// forgeFromFreshTree seals a message from a fresh secret tree built from the epoch's encryption secret. The
// forger's tree is not the receiver's tree: sealPrivateMessage seals with the receiver's own tree, and
// framing.Encrypt advances that tree's sequence number, which would be counted as a change by a
// rejected forgery.
func forgeFromFreshTree(t *testing.T, g *Group, sigKey *ciphersuite.SignaturePrivateKey, leaf uint32, body framing.FramedContentBody) *framing.PrivateMessage {
	t.Helper()
	tree, err := secrettree.NewTree(g.epochSecrets.EncryptionSecret, g.ratchetTree.NumLeaves, g.cipherSuite)
	if err != nil {
		t.Fatalf("secrettree.NewTree: %v", err)
	}
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
		SecretTree:       tree,
		SigKey:           sigKey,
		GroupContext:     g.groupContext.Marshal(),
	})
	if err != nil {
		t.Fatalf("framing.Encrypt: %v", err)
	}
	return pm
}

// TestForgedMessageFailsOnSignature checks the reason of the rejection. The forged application message is
// sealed with Bob's key but names Alice's leaf, so it has a valid AEAD and an invalid signature.
// TestForgedSignatureDoesNotConsumeGeneration asserts only err != nil, which any failure would satisfy.
func TestForgedMessageFailsOnSignature(t *testing.T) {
	aliceGroup, bobGroup, alice, bob := makeTwoMemberGroups(t)
	m0, err := aliceGroup.SendMessage([]byte("diagnostics m0"), alice.sigPriv)
	if err != nil {
		t.Fatalf("alice SendMessage: %v", err)
	}
	forged := forgeFromFreshTree(t, bobGroup, bob.sigPriv, uint32(aliceGroup.ownLeafIndex), framing.ApplicationData{Data: []byte("forged")})

	_, _, _, err = bobGroup.ReceiveApplicationMessage(forged)
	var sigErr *ErrInvalidSignature
	if !errors.As(err, &sigErr) {
		t.Fatalf("forged message rejected for another reason: err = %v, want *ErrInvalidSignature", err)
	}

	got, _, _, err := bobGroup.ReceiveApplicationMessage(m0)
	if err != nil {
		t.Fatalf("honest generation 0 refused after the forged one: %v", err)
	}
	if !bytes.Equal(got, []byte("diagnostics m0")) {
		t.Fatalf("plaintext = %q, want %q", got, "diagnostics m0")
	}
}

// leafMark holds the ratchet position of one leaf in the serialized secret tree.
type leafMark struct {
	Generation     uint32 `json:"generation"`
	SequenceNumber uint64 `json:"sequence_number"`
}

// ratchetDelta lists the differences between two serialized states that matter for the ratchet and the
// replay record. Top-level fields and secret-tree fields other than leaf_states must be byte-identical. A
// leaf entry that already existed must not move. A leaf entry created by the rejection is allowed only at
// generation 0 and sequence number 0, which is the lazy cache of LeafForIndex.
func ratchetDelta(t *testing.T, before, after []byte) []string {
	t.Helper()
	var a, b map[string]json.RawMessage
	if err := json.Unmarshal(before, &a); err != nil {
		t.Fatalf("state before: %v", err)
	}
	if err := json.Unmarshal(after, &b); err != nil {
		t.Fatalf("state after: %v", err)
	}
	var out []string
	for k := range a {
		if k != "secret_tree" && !bytes.Equal(a[k], b[k]) {
			out = append(out, k)
		}
	}
	var sa, sb map[string]json.RawMessage
	if err := json.Unmarshal(a["secret_tree"], &sa); err != nil {
		t.Fatalf("secret_tree before: %v", err)
	}
	if err := json.Unmarshal(b["secret_tree"], &sb); err != nil {
		t.Fatalf("secret_tree after: %v", err)
	}
	for k := range sa {
		if k != "leaf_states" && !bytes.Equal(sa[k], sb[k]) {
			out = append(out, "secret_tree."+k)
		}
	}
	var la, lb map[string]leafMark
	if sa["leaf_states"] != nil {
		if err := json.Unmarshal(sa["leaf_states"], &la); err != nil {
			t.Fatalf("leaf_states before: %v", err)
		}
	}
	if sb["leaf_states"] != nil {
		if err := json.Unmarshal(sb["leaf_states"], &lb); err != nil {
			t.Fatalf("leaf_states after: %v", err)
		}
	}
	for leaf, mark := range la {
		if lb[leaf] != mark {
			out = append(out, "leaf "+leaf+" moved")
		}
	}
	for leaf, mark := range lb {
		if _, existed := la[leaf]; !existed && (mark.Generation != 0 || mark.SequenceNumber != 0) {
			out = append(out, "leaf "+leaf+" created at a non-initial position")
		}
	}
	return out
}

// TestRejectedForgeryLeavesRatchetAndReplayRecordUnchanged checks the claim in the
// framing.Decrypt comment ("a message that fails authentication changes neither the replay record nor the
// ratchet") against the serialized state of Bob, the receiver.
func TestRejectedForgeryLeavesRatchetAndReplayRecordUnchanged(t *testing.T) {
	aliceGroup, bobGroup, alice, bob := makeTwoMemberGroups(t)
	m0, err := aliceGroup.SendMessage([]byte("diagnostics state"), alice.sigPriv)
	if err != nil {
		t.Fatalf("alice SendMessage: %v", err)
	}

	before, err := bobGroup.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState before forgery: %v", err)
	}
	forged := forgeFromFreshTree(t, bobGroup, bob.sigPriv, uint32(aliceGroup.ownLeafIndex), framing.ApplicationData{Data: []byte("forged")})
	if _, _, _, err := bobGroup.ReceiveApplicationMessage(forged); err == nil {
		t.Fatal("forged message was accepted")
	}
	after, err := bobGroup.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState after forgery: %v", err)
	}
	if delta := ratchetDelta(t, before, after); len(delta) > 0 {
		t.Fatalf("a rejected forgery changed the ratchet or replay record: %v", delta)
	}

	if _, _, _, err := bobGroup.ReceiveApplicationMessage(m0); err != nil {
		t.Fatalf("honest generation 0 refused: %v", err)
	}
}

// TestWrongSenderIndexIsRefusedWithoutConsumingGeneration checks that ReceiveMessage, called with the wrong
// sender index, refuses the honest message without consuming its generation, and accepts it with the right
// index. The ratchet comes from the sender data of the message, but the signature key comes from the
// caller's index.
func TestWrongSenderIndexIsRefusedWithoutConsumingGeneration(t *testing.T) {
	aliceGroup, bobGroup, alice, _ := makeTwoMemberGroups(t)
	pm, err := aliceGroup.SendMessage([]byte("diagnostics index"), alice.sigPriv)
	if err != nil {
		t.Fatalf("alice SendMessage: %v", err)
	}

	wrong := bobGroup.ownLeafIndex
	if wrong == aliceGroup.ownLeafIndex {
		t.Fatal("SETUP: test needs two distinct leaves")
	}
	if _, err := bobGroup.ReceiveMessage(pm, wrong); err == nil {
		t.Fatal("message accepted with another member's leaf index as the sender")
	}

	got, err := bobGroup.ReceiveMessage(pm, aliceGroup.ownLeafIndex)
	if err != nil {
		t.Fatalf("honest message refused after the wrong-index attempt: %v", err)
	}
	if !bytes.Equal(got, []byte("diagnostics index")) {
		t.Fatalf("plaintext = %q, want %q", got, "diagnostics index")
	}
}
