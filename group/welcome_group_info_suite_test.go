package group

import (
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// TestJoinFromWelcomeFailurePreservesGroupInfo checks that a suite mismatch
// preserves the caller's original GroupInfo.
func TestJoinFromWelcomeFailurePreservesGroupInfo(t *testing.T) {
	welcome, bob := newCipherSuiteTestWelcome(t, func(g *Group) {
		g.groupContext.CipherSuite = ciphersuite.MLS128DHKEMX25519
	})
	// The committer's Welcome already carries a GroupInfo. The join decodes its own copy,
	// so a failed join must leave the field pointing at the original value.
	original := welcome.GroupInfo
	if _, err := joinCipherSuiteTestWelcome(t, welcome, bob.kp, bob.priv); !errors.Is(err, ErrWelcomeCipherSuiteMismatch) {
		t.Fatalf("JoinFromWelcome err = %v, want ErrWelcomeCipherSuiteMismatch", err)
	}
	if welcome.GroupInfo != original {
		t.Fatal("the failed join replaced welcome.GroupInfo with the decoded copy")
	}
}

// TestJoinFromWelcomeSuccessSetsGroupInfo checks that a successful join records
// the GroupInfo on the caller's Welcome.
func TestJoinFromWelcomeSuccessSetsGroupInfo(t *testing.T) {
	welcome, bob := newCipherSuiteTestWelcome(t, nil)
	if _, err := joinCipherSuiteTestWelcome(t, welcome, bob.kp, bob.priv); err != nil {
		t.Fatalf("JoinFromWelcome(valid) err = %v", err)
	}
	if welcome.GroupInfo == nil {
		t.Fatal("a successful join did not record the GroupInfo on the Welcome")
	}
}
