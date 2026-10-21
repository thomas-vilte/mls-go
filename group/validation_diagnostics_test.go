//go:build diagnostics

package group

import (
	"bytes"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/extensions"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/internal/tls"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/treesync"
)

// Additional diagnostics for group input validation.

func panicValue(fn func()) (p any) {
	defer func() { p = recover() }()
	fn()
	return nil
}

// signedMemberProposal builds a PublicMessage from alice (leaf 0) with the given
// sender leaf index. The signature and membership tag are valid for alice's key, so
// only the sender index decides whether the verifier accepts it.
func signedMemberProposal(t *testing.T, aliceGroup *Group, alice *testUser, leaf uint32) *framing.PublicMessage {
	t.Helper()
	removeProposal := &Proposal{Type: ProposalTypeRemove, Remove: &RemoveProposal{Removed: LeafNodeIndex(1)}}
	content := framing.FramedContent{
		GroupID: aliceGroup.groupID.AsSlice(),
		Epoch:   aliceGroup.epoch.AsUint64(),
		Sender:  framing.Sender{Type: framing.SenderTypeMember, LeafIndex: leaf},
		Body:    framing.ProposalBody{Data: ProposalMarshal(removeProposal)},
	}
	pm, err := framing.NewPublicMessage(content, alice.sigPriv, aliceGroup.groupContext.Marshal(),
		aliceGroup.epochSecrets.MembershipKey, aliceGroup.cipherSuite)
	if err != nil {
		t.Fatalf("NewPublicMessage(leaf=%#x): %v", leaf, err)
	}
	return pm
}

// TestCipherSuiteSupportMatchesHashFunction checks all 65536 cipher suite values.
// Unsupported suites must have no hash function and keyPackageRef must reject them.
func TestCipherSuiteSupportMatchesHashFunction(t *testing.T) {
	kp, _ := newCipherSuiteTestKeyPackage(t)
	for v := range 1 << 16 {
		cs := ciphersuite.CipherSuite(v)
		if cs.IsSupported() != (cs.HashFunction() != nil) {
			t.Errorf("suite 0x%04x: IsSupported=%v but HashFunction nil=%v", v, cs.IsSupported(), cs.HashFunction() == nil)
		}
		if !cs.IsSupported() {
			if _, err := keyPackageRef(kp, cs); !errors.Is(err, ErrUnsupportedCipherSuite) {
				t.Errorf("keyPackageRef(0x%04x) err = %v, want ErrUnsupportedCipherSuite", v, err)
			}
		}
	}
}

// TestJoinFromWelcomeNilKeyPackage checks that a nil KeyPackage returns an error
// without panicking.
func TestJoinFromWelcomeNilKeyPackage(t *testing.T) {
	welcome, _ := newCipherSuiteTestWelcome(t, nil)
	var err error
	if p := panicValue(func() {
		_, err = JoinFromWelcomeWithContext(t.Context(), welcome, nil, nil, nil)
	}); p != nil {
		t.Errorf("JoinFromWelcomeWithContext(nil key package) panicked: %v", p)
	} else if err == nil {
		t.Errorf("JoinFromWelcomeWithContext(nil key package) returned nil error")
	} else {
		t.Logf("JoinFromWelcomeWithContext(nil key package) err = %v", err)
	}
}

// TestJoinFromWelcomeDifferentHashSuiteMismatch exercises a CS5 Welcome with
// a CS2 KeyPackage after a successful control join.
func TestJoinFromWelcomeDifferentHashSuiteMismatch(t *testing.T) {
	welcome, bob := newCipherSuiteTestWelcome(t, nil)
	if welcome.CipherSuite != ciphersuite.MLS128DHKEMP256 {
		t.Skipf("fixture suite is %#x", uint16(welcome.CipherSuite))
	}
	// Control: the unmodified welcome joins with bob's key package.
	if _, err := joinCipherSuiteTestWelcome(t, welcome, bob.kp, bob.priv); err != nil {
		t.Fatalf("control join: %v", err)
	}
	// Mutate the welcome suite to CS5 while the key package stays CS2.
	welcome.CipherSuite = ciphersuite.MLS256DHKEMP521AES256GCM
	_, err := joinCipherSuiteTestWelcome(t, welcome, bob.kp, bob.priv)
	if !errors.Is(err, ErrWelcomeCipherSuiteMismatch) {
		t.Errorf("join with welcome CS5 and key package CS2 err = %v, want ErrWelcomeCipherSuiteMismatch", err)
	}
}

// TestMemberSenderLeafIndexBounds verifies that member sender indices
// outside the current tree are rejected.
func TestMemberSenderLeafIndexBounds(t *testing.T) {
	aliceGroup, bobGroup, alice, _ := makeTwoMemberGroups(t)

	control := signedMemberProposal(t, aliceGroup, alice, 0)
	if err := bobGroup.VerifyPublicMessage(control); err != nil {
		t.Fatalf("control VerifyPublicMessage(leaf 0) = %v, want nil", err)
	}

	outOfRange := signedMemberProposal(t, aliceGroup, alice, 2)
	if err := bobGroup.VerifyPublicMessage(outOfRange); err == nil {
		t.Errorf("VerifyPublicMessage(leaf 2, tree has 2 leaves) accepted; want error")
	}

	wrapped := signedMemberProposal(t, aliceGroup, alice, 0x80000000)
	if err := bobGroup.VerifyPublicMessage(wrapped); err == nil {
		t.Errorf("VerifyPublicMessage(sender leaf 0x80000000, alias of leaf 0 by uint32 wrap) accepted alice's signature; want error")
	}
}

// TestReceivedCommitSenderLeafIndexBounds rejects sender indices
// that wrap onto an existing leaf.
func TestReceivedCommitSenderLeafIndexBounds(t *testing.T) {
	run := func(senderIdx treesync.LeafIndex) (procErr error, sameAuth bool, bobEpoch uint64, panicVal any) {
		aliceGroup, bobGroup, alice, _ := makeTwoMemberGroups(t)
		if _, err := aliceGroup.SelfUpdate(alice.sigPriv); err != nil {
			t.Fatalf("SelfUpdate(alice): %v", err)
		}
		sc, err := aliceGroup.Commit(alice.sigPriv, alice.sigPub, nil)
		if err != nil {
			t.Fatalf("Commit(alice): %v", err)
		}
		if err := aliceGroup.MergeCommit(sc); err != nil {
			t.Fatalf("MergeCommit(alice): %v", err)
		}
		panicVal = panicValue(func() {
			procErr = bobGroup.ProcessReceivedCommit(sc.authenticatedContent, senderIdx, bobGroup.myLeafEncryptionKey)
		})
		if procErr == nil && panicVal == nil {
			sameAuth = bytes.Equal(aliceGroup.EpochAuthenticator(), bobGroup.EpochAuthenticator())
		}
		return procErr, sameAuth, bobGroup.epoch.AsUint64(), panicVal
	}

	ctrlErr, ctrlSame, ctrlEpoch, ctrlPanic := run(0)
	if ctrlPanic != nil || ctrlErr != nil {
		t.Fatalf("control ProcessReceivedCommit(senderLeafIdx=0) panic=%v err=%v", ctrlPanic, ctrlErr)
	}
	if !ctrlSame || ctrlEpoch != 2 {
		t.Fatalf("control: epoch(bob)=%d, authenticators equal=%v", ctrlEpoch, ctrlSame)
	}

	wrapErr, wrapSame, wrapEpoch, wrapPanic := run(treesync.LeafIndex(0x80000000))
	if wrapPanic != nil {
		t.Errorf("ProcessReceivedCommit(senderLeafIdx=0x80000000) panicked: %v", wrapPanic)
		return
	}
	t.Logf("wrap case: err=%v epoch(bob)=%d authenticators equal=%v", wrapErr, wrapEpoch, wrapSame)
	if wrapErr == nil {
		t.Errorf("commit from alice (leaf 0) accepted with senderLeafIdx=0x80000000 (epoch %d, same authenticator=%v); want error", wrapEpoch, wrapSame)
	}
}

// TestPublicMessageRejectsRelabeledCommit checks that commits cannot bypass
// verification through a different sender type.
func TestPublicMessageRejectsRelabeledCommit(t *testing.T) {
	aliceGroup, bobGroup, _, bob := makeTwoMemberGroups(t)
	forgedSrc := newSenderTestCommit(t, bobGroup, bob).authenticatedContent
	for _, st := range []framing.SenderType{framing.SenderTypeExternal, framing.SenderTypeNewMemberProposal} {
		forged := forgeCommitSender(forgedSrc, st)
		pm := &framing.PublicMessage{Content: forged.Content, Auth: forged.Auth}
		var err error
		if p := panicValue(func() { err = aliceGroup.ProcessPublicMessage(pm) }); p != nil {
			t.Errorf("ProcessPublicMessage(commit relabelled %d) panicked: %v", st, p)
			continue
		}
		if err == nil {
			t.Errorf("ProcessPublicMessage(commit relabelled as sender %d) accepted", st)
		}
		if got := aliceGroup.epoch.AsUint64(); got != 1 {
			t.Fatalf("alice epoch = %d after relabelled commit, want 1", got)
		}
	}
}

// TestPublicMessageInvalidBodyAndSender rejects missing bodies and invalid
// sender metadata without panicking.
func TestPublicMessageInvalidBodyAndSender(t *testing.T) {
	aliceGroup, bobGroup, alice, _ := makeTwoMemberGroups(t)

	// Body nil: VerifyPublicMessage and ProcessPublicMessage must return an error.
	nilBody := &framing.PublicMessage{
		Content: framing.FramedContent{
			GroupID: aliceGroup.groupID.AsSlice(),
			Epoch:   aliceGroup.epoch.AsUint64(),
			Sender:  framing.Sender{Type: framing.SenderTypeMember, LeafIndex: 0},
		},
		Auth: framing.FramedContentAuthData{Signature: ciphersuite.NewSignature(make([]byte, 64))},
	}
	var verr, perr error
	if p := panicValue(func() { verr = bobGroup.VerifyPublicMessage(nilBody) }); p != nil {
		t.Errorf("VerifyPublicMessage(nil body) panicked: %v", p)
	} else if verr == nil {
		t.Errorf("VerifyPublicMessage(nil body) returned nil")
	}
	if p := panicValue(func() { perr = bobGroup.ProcessPublicMessage(nilBody) }); p != nil {
		t.Errorf("ProcessPublicMessage(nil body) panicked: %v", p)
	} else if perr == nil {
		t.Errorf("ProcessPublicMessage(nil body) returned nil")
	}

	// Emitter side: NewPublicMessage must refuse reserved and unknown sender types.
	for _, st := range []framing.SenderType{0, 5, 255} {
		content := framing.FramedContent{
			GroupID: aliceGroup.groupID.AsSlice(),
			Epoch:   aliceGroup.epoch.AsUint64(),
			Sender:  framing.Sender{Type: st},
			Body:    framing.ProposalBody{Data: []byte{0, 0}},
		}
		_, err := framing.NewPublicMessage(content, alice.sigPriv, aliceGroup.groupContext.Marshal(),
			aliceGroup.epochSecrets.MembershipKey, aliceGroup.cipherSuite)
		if !errors.Is(err, framing.ErrInvalidSenderType) {
			t.Errorf("NewPublicMessage(sender %d) err = %v, want ErrInvalidSenderType", st, err)
		}
	}

	// new_member_proposal whose proposal is a Remove (not an Add) must be rejected.
	removeBody := framing.ProposalBody{Data: ProposalMarshal(&Proposal{Type: ProposalTypeRemove, Remove: &RemoveProposal{Removed: 1}})}
	nmp := &framing.PublicMessage{
		Content: framing.FramedContent{
			GroupID: aliceGroup.groupID.AsSlice(),
			Epoch:   aliceGroup.epoch.AsUint64(),
			Sender:  framing.Sender{Type: framing.SenderTypeNewMemberProposal},
			Body:    removeBody,
		},
		Auth: framing.FramedContentAuthData{Signature: ciphersuite.NewSignature(make([]byte, 64))},
	}
	if p := panicValue(func() { verr = bobGroup.VerifyPublicMessage(nmp) }); p != nil {
		t.Errorf("VerifyPublicMessage(new_member_proposal remove) panicked: %v", p)
	} else if verr == nil {
		t.Errorf("VerifyPublicMessage(new_member_proposal with Remove) accepted")
	}

	// External sender index beyond the ExternalSenders extension (none in this group).
	ext := &framing.PublicMessage{
		Content: framing.FramedContent{
			GroupID: aliceGroup.groupID.AsSlice(),
			Epoch:   aliceGroup.epoch.AsUint64(),
			Sender:  framing.Sender{Type: framing.SenderTypeExternal, SenderIndex: 0xFFFFFFFF},
			Body:    removeBody,
		},
		Auth: framing.FramedContentAuthData{Signature: ciphersuite.NewSignature(make([]byte, 64))},
	}
	if p := panicValue(func() { verr = bobGroup.VerifyPublicMessage(ext) }); p != nil {
		t.Errorf("VerifyPublicMessage(external index 0xFFFFFFFF) panicked: %v", p)
	} else if verr == nil {
		t.Errorf("VerifyPublicMessage(external, no ExternalSenders extension) accepted")
	}
}

// TestKeyPackageRejectsReservedCredentialType rejects reserved credentials
// before they reach KeyPackage callers.
func TestKeyPackageRejectsReservedCredentialType(t *testing.T) {
	// The KeyPackage path with a type-0 credential on the leaf.
	kpBytes := newCredentialTestKeyPackage(t).Marshal()
	bad := keyPackageBytesWithCredentialType(t, kpBytes, 0)
	var parseErr error
	var kp *keypackages.KeyPackage
	if p := panicValue(func() {
		kp, parseErr = keypackages.UnmarshalKeyPackage(bad)
	}); p != nil {
		t.Fatalf("parsing KeyPackage with credential_type 0 panicked: %v", p)
	}
	if parseErr == nil {
		t.Errorf("KeyPackage with credential_type 0 parsed (kp=%v); want error", kp != nil)
	}
}

// TestPublicMessageRejectsNonexistentSenderProposal checks that a signed
// proposal with a nonexistent sender is rejected.
func TestPublicMessageRejectsNonexistentSenderProposal(t *testing.T) {
	aliceGroup, bobGroup, alice, _ := makeTwoMemberGroups(t)
	before := len(bobGroup.StoredProposals())
	wrapped := signedMemberProposal(t, aliceGroup, alice, 0x80000000)
	var err error
	if p := panicValue(func() { err = bobGroup.ProcessPublicMessage(wrapped) }); p != nil {
		t.Fatalf("ProcessPublicMessage(phantom sender) panicked: %v", p)
	}
	after := len(bobGroup.StoredProposals())
	t.Logf("ProcessPublicMessage(phantom sender 0x80000000) err=%v stored proposals before=%d after=%d", err, before, after)
	if err == nil {
		t.Errorf("ProcessPublicMessage accepted a proposal from non-existent sender leaf 0x80000000 (stored %d -> %d)", before, after)
	}
}

// TestNilCredentialMarshaling rejects serialized KeyPackages and Add proposals
// whose credentials are nil.
func TestNilCredentialMarshaling(t *testing.T) {
	kp := newCredentialTestKeyPackage(t)
	kp.LeafNode.Credential = nil

	if p := panicValue(func() { _ = kp.Verify(ciphersuite.MLS128DHKEMP256) }); p != nil {
		t.Fatalf("KeyPackage.Verify with nil credential panicked: %v", p)
	}
	var kpBytes []byte
	if p := panicValue(func() { kpBytes = kp.Marshal() }); p != nil {
		t.Fatalf("KeyPackage.Marshal with nil credential panicked: %v", p)
	}
	if _, err := keypackages.UnmarshalKeyPackage(kpBytes); err == nil {
		t.Errorf("KeyPackage marshaled with nil credential parses back; want fail-closed error")
	}

	add := &Proposal{Type: ProposalTypeAdd, Add: &AddProposal{KeyPackage: kp}}
	var propBytes []byte
	if p := panicValue(func() { propBytes = ProposalMarshal(add) }); p != nil {
		t.Fatalf("ProposalMarshal(add with nil credential) panicked: %v", p)
	}
	if _, err := UnmarshalProposal(propBytes); err == nil {
		t.Errorf("Add proposal with nil credential parses back; want fail-closed error")
	}
}

// TestExternalSendersRejectReservedCredentialType rejects an extension
// containing a sender with a reserved credential type.
func TestExternalSendersRejectReservedCredentialType(t *testing.T) {
	inner := tls.NewWriter()
	inner.WriteVLBytes(make([]byte, 32)) // signature_key
	inner.WriteUint16(0)                 // credential_type 0 (reserved)
	inner.WriteVLBytes(nil)              // empty body
	data := tls.NewWriter()
	data.WriteVLBytes(inner.Bytes()) // senders<V>
	var err error
	var ext *extensions.ExternalSendersExtension
	if p := panicValue(func() { ext, err = extensions.UnmarshalExternalSendersExtension(data.Bytes()) }); p != nil {
		t.Fatalf("UnmarshalExternalSendersExtension(type 0) panicked: %v", p)
	}
	if err == nil {
		t.Errorf("ExternalSenders with credential_type 0 accepted (senders=%d)", len(ext.Senders))
	}
}
