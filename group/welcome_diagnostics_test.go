//go:build diagnostics

package group

import (
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
)

// Additional diagnostics for cipher suite validation during Welcome processing.

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
