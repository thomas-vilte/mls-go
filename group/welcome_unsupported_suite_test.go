package group

import (
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// TestJoinFromWelcomeUnknownCipherSuite verifies that an unknown Welcome cipher
// suite returns an error without panicking.
func TestJoinFromWelcomeUnknownCipherSuite(t *testing.T) {
	welcome, bob := newCipherSuiteTestWelcome(t, nil)
	welcome.CipherSuite = ciphersuite.CipherSuite(0xFFFF)

	if _, err := joinCipherSuiteTestWelcome(t, welcome, bob.kp, bob.priv); err == nil {
		t.Fatal("JoinFromWelcome with an unknown Welcome cipher suite returned no error")
	}
}
