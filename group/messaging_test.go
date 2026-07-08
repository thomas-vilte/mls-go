package group

import (
	"bytes"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/treesync"
)

func tamperApplicationMessageSignature(t *testing.T, senderGroup *Group, pm *framing.PrivateMessage) *framing.PrivateMessage {
	t.Helper()

	ac, err := framing.Decrypt(pm, framing.DecryptParams{
		CipherSuite:      senderGroup.cipherSuite,
		SenderDataSecret: senderGroup.epochSecrets.SenderDataSecret,
		SecretTree:       senderGroup.secretTree,
		GroupContext:     senderGroup.groupContext.Marshal(),
	})
	if err != nil {
		t.Fatalf("Decrypt(sender): %v", err)
	}

	sig := ac.Auth.Signature.AsSlice()
	if len(sig) == 0 {
		t.Fatal("signature is empty")
	}
	sig[0] ^= 0xFF

	tampered, err := framing.Encrypt(framing.EncryptParams{
		AuthContent:      ac,
		SenderLeafIndex:  uint32(senderGroup.ownLeafIndex),
		CipherSuite:      senderGroup.cipherSuite,
		PaddingSize:      senderGroup.paddingSize,
		SenderDataSecret: senderGroup.epochSecrets.SenderDataSecret,
		SecretTree:       senderGroup.secretTree,
	})
	if err != nil {
		t.Fatalf("Encrypt(tampered): %v", err)
	}

	return tampered
}

// TestSendMessage_EmptyPayload verifies that SendMessage works with an empty payload.
func TestSendMessage_EmptyPayload(t *testing.T) {
	aliceGroup, _, alicePriv, _ := setupTwoMemberGroup(t)

	// Send an empty message. MLS allows this.
	aliceSigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)

	pm, err := aliceGroup.SendMessage([]byte{}, aliceSigPriv)
	if err != nil {
		t.Fatalf("SendMessage with empty payload should succeed: %v", err)
	}

	if pm == nil {
		t.Fatal("SendMessage should return non-nil PrivateMessage")
	}

	// Nota: no probamos el ReceiveMessage aquí porque requiere sincronización
	// Full secret synchronization between Alice and Bob is covered in integration_test.go.
}

// TestSendMessage_NilSignKey verifies that SendMessage fails with nil sigKey.
func TestSendMessage_NilSignKey(t *testing.T) {
	aliceGroup, _, _, _ := setupTwoMemberGroup(t)

	// Attempt to send with a nil signature key.
	_, err := aliceGroup.SendMessage([]byte("hola"), nil)
	if err == nil {
		t.Error("SendMessage should fail with nil signature key")
	}
}

func TestSendMessage_FailsWithPendingProposals(t *testing.T) {
	aliceGroup, _, alicePriv, _ := setupTwoMemberGroup(t)

	charlieCred, _, err := credentials.GenerateCredentialWithKey([]byte("Charlie-Pending"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(Charlie): %v", err)
	}
	charlieKP, _, err := keypackages.Generate(charlieCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage(Charlie): %v", err)
	}
	if _, err := aliceGroup.AddMember(charlieKP); err != nil {
		t.Fatalf("AddMember(Charlie): %v", err)
	}

	aliceSigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)
	if _, err := aliceGroup.SendMessage([]byte("blocked"), aliceSigPriv); err == nil {
		t.Fatal("SendMessage should fail when proposals are pending")
	}
	if _, err := aliceGroup.SendApplicationMessage([]byte("blocked"), []byte("aad"), aliceSigPriv); err == nil {
		t.Fatal("SendApplicationMessage should fail when proposals are pending")
	}
}

// TestReceiveMessage_WrongSender verifies that ReceiveMessage fails with invalid sender.
func TestReceiveMessage_WrongSender(t *testing.T) {
	aliceGroup, bobGroup, alicePriv, _ := setupTwoMemberGroup(t)

	// Alice sends a message.
	aliceSigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)

	pm, err := aliceGroup.SendMessage([]byte("hola bob"), aliceSigPriv)
	if err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}

	// Bob tries to receive with a non-existent sender index
	_, err = bobGroup.ReceiveMessage(pm, 9999)
	if err == nil {
		t.Error("ReceiveMessage should fail with out-of-bounds sender index")
	}
}

// TestSendMessage_WrongState verifies that SendMessage fails when the group is not operational.
func TestSendMessage_WrongState(t *testing.T) {
	// Create a group and force a non-operational state for the test.
	cred, _, err := credentials.GenerateCredentialWithKey([]byte("User"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey: %v", err)
	}

	kp, priv, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage: %v", err)
	}

	groupID, err := NewGroupIDRandom()
	if err != nil {
		t.Fatalf("NewGroupIDRandom: %v", err)
	}

	group, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kp, priv)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}

	// Force a non-operational state for the test.
	group.state = StateInactive

	// Attempt to send a message.
	sigPriv := ciphersuite.NewSignaturePrivateKey(priv.SignatureKey)
	_, err = group.SendMessage([]byte("hola"), sigPriv)
	if err == nil {
		t.Error("SendMessage should fail when group is not operational")
	}
}

// TestReceiveMessage_NilMessage verifies that ReceiveMessage fails with a nil message.
func TestReceiveMessage_NilMessage(t *testing.T) {
	_, bobGroup, _, _ := setupTwoMemberGroup(t)

	// Attempt to receive a nil message.
	_, err := bobGroup.ReceiveMessage(nil, 0)
	if err == nil {
		t.Error("ReceiveMessage should fail with nil message")
	}
}

// TestSendMessage_NoSecretTree verifies that SendMessage fails sin SecretTree
func TestSendMessage_NoSecretTree(t *testing.T) {
	aliceGroup, _, alicePriv, _ := setupTwoMemberGroup(t)

	// Corrupt the group by removing the SecretTree for the test.
	originalTree := aliceGroup.secretTree
	aliceGroup.secretTree = nil

	aliceSigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)
	_, err := aliceGroup.SendMessage([]byte("hola"), aliceSigPriv)
	if err == nil {
		t.Error("SendMessage should fail without SecretTree")
	}

	// Restaurar
	aliceGroup.secretTree = originalTree
}

// TestReceiveMessage_NoSecretTree verifies that ReceiveMessage fails sin SecretTree
func TestReceiveMessage_NoSecretTree(t *testing.T) {
	_, bobGroup, _, _ := setupTwoMemberGroup(t)

	// Corrupt the group by removing the SecretTree for the test.
	originalTree := bobGroup.secretTree
	bobGroup.secretTree = nil

	pm := &framing.PrivateMessage{}
	_, err := bobGroup.ReceiveMessage(pm, 0)
	if err == nil {
		t.Error("ReceiveMessage should fail without SecretTree")
	}

	// Restaurar
	bobGroup.secretTree = originalTree
}

func TestReceiveApplicationMessage_VerifiesSignature(t *testing.T) {
	aliceGroup, bobGroup, alice, _ := makeTwoMemberGroups(t)

	msg := []byte("hello bob")
	aad := []byte("aad")
	pm, err := aliceGroup.SendApplicationMessage(msg, aad, alice.sigPriv)
	if err != nil {
		t.Fatalf("SendApplicationMessage: %v", err)
	}

	got, gotAAD, senderLeafIdx, err := bobGroup.ReceiveApplicationMessage(pm)
	if err != nil {
		t.Fatalf("ReceiveApplicationMessage(valid): %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("plaintext = %q, want %q", got, msg)
	}
	if !bytes.Equal(gotAAD, aad) {
		t.Fatalf("authenticated data = %x, want %x", gotAAD, aad)
	}
	if senderLeafIdx != treesync.LeafIndex(aliceGroup.ownLeafIndex) {
		t.Fatalf("sender leaf index = %d, want %d", senderLeafIdx, aliceGroup.ownLeafIndex)
	}

	tampered := tamperApplicationMessageSignature(t, aliceGroup, pm)
	if _, _, _, err := bobGroup.ReceiveApplicationMessage(tampered); err == nil {
		t.Fatal("ReceiveApplicationMessage should fail with tampered signature")
	}
}

func TestReceiveApplicationMessage_OldEpochUsesHistoricalContext(t *testing.T) {
	aliceGroup, bobGroup, alice, _ := makeTwoMemberGroups(t)

	msg := []byte("message from previous epoch")
	aad := []byte("epoch1")
	pm, err := aliceGroup.SendApplicationMessage(msg, aad, alice.sigPriv)
	if err != nil {
		t.Fatalf("SendApplicationMessage: %v", err)
	}

	charlieCred, _, err := credentials.GenerateCredentialWithKey([]byte("Charlie-OldEpoch"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(Charlie): %v", err)
	}
	charlieKP, _, err := keypackages.Generate(charlieCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage(Charlie): %v", err)
	}

	if _, err := aliceGroup.AddMember(charlieKP); err != nil {
		t.Fatalf("AddMember(Charlie): %v", err)
	}
	stagedCommit, err := aliceGroup.Commit(alice.sigPriv, alice.sigPub, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := bobGroup.ProcessCommit(stagedCommit); err != nil {
		t.Fatalf("ProcessCommit(bob): %v", err)
	}
	if err := aliceGroup.MergeCommit(stagedCommit); err != nil {
		t.Fatalf("MergeCommit(alice): %v", err)
	}

	history, ok := bobGroup.epochHistory[1]
	if !ok {
		t.Fatal("epoch 1 not cached in EpochHistory")
	}
	if history.GroupContext == nil {
		t.Fatal("historical GroupContext is nil")
	}

	got, gotAAD, senderLeafIdx, err := bobGroup.ReceiveApplicationMessage(pm)
	if err != nil {
		t.Fatalf("ReceiveApplicationMessage(old epoch): %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("plaintext = %q, want %q", got, msg)
	}
	if !bytes.Equal(gotAAD, aad) {
		t.Fatalf("authenticated data = %x, want %x", gotAAD, aad)
	}
	if senderLeafIdx != treesync.LeafIndex(aliceGroup.ownLeafIndex) {
		t.Fatalf("sender leaf index = %d, want %d", senderLeafIdx, aliceGroup.ownLeafIndex)
	}
}

func TestVerifyPublicMessage_NewMemberCommit_VerifiesSignature(t *testing.T) {
	aliceGroup, _, alice, _ := makeTwoMemberGroups(t)
	charlie := newTestUser(t, "charlie-new-member-commit")

	groupInfo, err := aliceGroup.GetGroupInfo(alice.sigPriv)
	if err != nil {
		t.Fatalf("GetGroupInfo: %v", err)
	}

	_, stagedCommit, err := ExternalCommit(
		groupInfo,
		aliceGroup.cipherSuite,
		charlie.sigPriv,
		charlie.sigPub,
		nil,
		charlie.kp.LeafNode.Credential,
	)
	if err != nil {
		t.Fatalf("ExternalCommit: %v", err)
	}

	pm := &framing.PublicMessage{
		Content: stagedCommit.authenticatedContent.Content,
		Auth:    stagedCommit.authenticatedContent.Auth,
	}
	if err := aliceGroup.VerifyPublicMessage(pm); err != nil {
		t.Fatalf("VerifyPublicMessage(valid): %v", err)
	}

	sig := pm.Auth.Signature.AsSlice()
	if len(sig) == 0 {
		t.Fatal("signature is empty")
	}
	sig[0] ^= 0xFF
	if err := aliceGroup.VerifyPublicMessage(pm); err == nil {
		t.Fatal("VerifyPublicMessage should fail with tampered new member commit signature")
	}
}

// TestVerifyPublicMessage_NewMemberProposal_VerifiesSignature covers RFC 9420
// §6.1's new_member_proposal case: the signature key in the LeafNode of the
// KeyPackage embedded in the external Add proposal.
func TestVerifyPublicMessage_NewMemberProposal_VerifiesSignature(t *testing.T) {
	aliceGroup, _, _, _ := makeTwoMemberGroups(t)
	charlie := newTestUser(t, "charlie-new-member-proposal")

	addProposal := NewAddProposal(charlie.kp)
	content := framing.FramedContent{
		GroupID: aliceGroup.groupID.AsSlice(),
		Epoch:   aliceGroup.epoch.AsUint64(),
		Sender:  framing.Sender{Type: framing.SenderTypeNewMemberProposal},
		Body:    framing.ProposalBody{Data: ProposalMarshal(addProposal)},
	}
	ac := &framing.AuthenticatedContent{
		WireFormat:   framing.WireFormatPublicMessage,
		Content:      content,
		GroupContext: aliceGroup.groupContext.Marshal(),
	}
	sig, err := ciphersuite.SignWithLabel(charlie.sigPriv, "FramedContentTBS", ac.MarshalTBS())
	if err != nil {
		t.Fatalf("SignWithLabel: %v", err)
	}
	pm := &framing.PublicMessage{
		Content: content,
		Auth:    framing.FramedContentAuthData{Signature: sig},
	}

	if err := aliceGroup.VerifyPublicMessage(pm); err != nil {
		t.Fatalf("VerifyPublicMessage(valid new_member_proposal): %v", err)
	}

	sigBytes := pm.Auth.Signature.AsSlice()
	if len(sigBytes) == 0 {
		t.Fatal("signature is empty")
	}
	sigBytes[0] ^= 0xFF
	if err := aliceGroup.VerifyPublicMessage(pm); err == nil {
		t.Fatal("VerifyPublicMessage should fail with tampered new_member_proposal signature")
	}
}

// TestVerifyPublicMessage_NewMemberProposal_RejectsWrongProposalType verifies
// that a new_member_proposal MUST carry an Add proposal (RFC 9420 §6.1):
// any other proposal type is rejected before signature verification even runs.
func TestVerifyPublicMessage_NewMemberProposal_RejectsWrongProposalType(t *testing.T) {
	aliceGroup, _, _, bob := makeTwoMemberGroups(t)

	removeProposal := &Proposal{
		Type:   ProposalTypeRemove,
		Remove: &RemoveProposal{Removed: LeafNodeIndex(1)},
	}
	content := framing.FramedContent{
		GroupID: aliceGroup.groupID.AsSlice(),
		Epoch:   aliceGroup.epoch.AsUint64(),
		Sender:  framing.Sender{Type: framing.SenderTypeNewMemberProposal},
		Body:    framing.ProposalBody{Data: ProposalMarshal(removeProposal)},
	}
	ac := &framing.AuthenticatedContent{
		WireFormat:   framing.WireFormatPublicMessage,
		Content:      content,
		GroupContext: aliceGroup.groupContext.Marshal(),
	}
	sig, err := ciphersuite.SignWithLabel(bob.sigPriv, "FramedContentTBS", ac.MarshalTBS())
	if err != nil {
		t.Fatalf("SignWithLabel: %v", err)
	}
	pm := &framing.PublicMessage{
		Content: content,
		Auth:    framing.FramedContentAuthData{Signature: sig},
	}

	if err := aliceGroup.VerifyPublicMessage(pm); err == nil {
		t.Fatal("VerifyPublicMessage should reject a new_member_proposal that isn't an Add")
	}
}

// TestReceiveMessage_RejectsBlankSenderLeaf verifies RFC 9420 §6.1's signature
// verification MUST: a PrivateMessage claiming to be from a blank (removed)
// leaf must be rejected before any signature check is attempted — not
// silently accepted with signature verification skipped.
func TestReceiveMessage_RejectsBlankSenderLeaf(t *testing.T) {
	aliceGroup, _, alice, _ := makeTwoMemberGroups(t)
	bobLeafIdx := LeafNodeIndex(1)

	// Add a third member so removing bob leaves an in-bounds blank leaf
	// instead of one truncated away by TruncateTrailingBlanks (RFC §12.1.3).
	charlie := newTestUser(t, "charlie-blank-leaf")
	if _, err := aliceGroup.AddMember(charlie.kp); err != nil {
		t.Fatalf("AddMember(charlie): %v", err)
	}
	sc0, err := aliceGroup.Commit(alice.sigPriv, alice.sigPub, nil)
	if err != nil {
		t.Fatalf("Commit(add charlie): %v", err)
	}
	if err := aliceGroup.MergeCommit(sc0); err != nil {
		t.Fatalf("MergeCommit(add charlie): %v", err)
	}

	if _, err := aliceGroup.RemoveMember(bobLeafIdx); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	sc, err := aliceGroup.Commit(alice.sigPriv, alice.sigPub, nil)
	if err != nil {
		t.Fatalf("Commit(remove bob): %v", err)
	}
	if err := aliceGroup.MergeCommit(sc); err != nil {
		t.Fatalf("MergeCommit: %v", err)
	}

	if uint32(bobLeafIdx) >= aliceGroup.ratchetTree.NumLeaves {
		t.Fatalf("bob's leaf index %d should still be in tree bounds (NumLeaves=%d)", bobLeafIdx, aliceGroup.ratchetTree.NumLeaves)
	}
	leaf := aliceGroup.ratchetTree.GetLeaf(treesync.LeafIndex(bobLeafIdx))
	if leaf != nil && leaf.State == treesync.NodeStatePresent {
		t.Fatal("bob's leaf should be blank after removal")
	}

	// Any PrivateMessage will do: the blank-leaf check must reject before
	// decryption/signature verification is even attempted.
	aliceSigPriv := ciphersuite.NewSignaturePrivateKey(alice.priv.SignatureKey)
	pm, err := aliceGroup.SendMessage([]byte("hello"), aliceSigPriv)
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	_, err = aliceGroup.ReceiveMessage(pm, bobLeafIdx)
	if err == nil {
		t.Fatal("ReceiveMessage should reject a sender claiming to be a blank leaf")
	}
	if !errors.Is(err, ErrSenderNotActive) {
		t.Fatalf("error = %v, want ErrSenderNotActive", err)
	}
}

func TestSendMessage_UsesConfiguredPadding(t *testing.T) {
	aliceNoPad, _, alicePrivNoPad, _ := setupTwoMemberGroup(t)
	alicePad, _, alicePrivPad, _ := setupTwoMemberGroup(t)
	alicePad.SetPaddingSize(32)

	msg := []byte("short")
	pmNoPad, err := aliceNoPad.SendMessage(msg, ciphersuite.NewSignaturePrivateKey(alicePrivNoPad.SignatureKey))
	if err != nil {
		t.Fatalf("SendMessage(no padding): %v", err)
	}
	pmPad, err := alicePad.SendMessage(msg, ciphersuite.NewSignaturePrivateKey(alicePrivPad.SignatureKey))
	if err != nil {
		t.Fatalf("SendMessage(with padding): %v", err)
	}

	if len(pmPad.Ciphertext) <= len(pmNoPad.Ciphertext) {
		t.Fatalf("padded ciphertext len = %d, want > %d", len(pmPad.Ciphertext), len(pmNoPad.Ciphertext))
	}
}

func TestSendApplicationMessage_UsesConfiguredPadding(t *testing.T) {
	aliceNoPad, _, alicePrivNoPad, _ := setupTwoMemberGroup(t)
	alicePad, _, alicePrivPad, _ := setupTwoMemberGroup(t)
	alicePad.SetPaddingSize(32)

	msg := []byte("short")
	aad := []byte("aad")
	pmNoPad, err := aliceNoPad.SendApplicationMessage(msg, aad, ciphersuite.NewSignaturePrivateKey(alicePrivNoPad.SignatureKey))
	if err != nil {
		t.Fatalf("SendApplicationMessage(no padding): %v", err)
	}
	pmPad, err := alicePad.SendApplicationMessage(msg, aad, ciphersuite.NewSignaturePrivateKey(alicePrivPad.SignatureKey))
	if err != nil {
		t.Fatalf("SendApplicationMessage(with padding): %v", err)
	}

	if len(pmPad.Ciphertext) <= len(pmNoPad.Ciphertext) {
		t.Fatalf("padded ciphertext len = %d, want > %d", len(pmPad.Ciphertext), len(pmNoPad.Ciphertext))
	}
}
