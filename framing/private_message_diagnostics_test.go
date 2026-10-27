//go:build diagnostics

package framing_test

import (
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/framing"
)

// TestDecryptForgedMessagePreservesGeneration checks that a rejected signature
// does not cause the honest message at the same generation to be treated as a replay.
func TestDecryptForgedMessagePreservesGeneration(t *testing.T) {
	env := newDecryptionOrderTestEnv(t)
	forged := env.seal(t, env.forgerTree, env.forgerPriv, "forged")
	honest := env.seal(t, env.legitTree, env.legitPriv, "honest")

	if _, err := framing.Decrypt(forged, env.decrypt); !errors.Is(err, framing.ErrVerificationFailed) {
		t.Fatalf("forged message: err = %v, want ErrVerificationFailed", err)
	}
	if _, err := framing.Decrypt(honest, env.decrypt); err != nil {
		t.Errorf("honest generation 0 rejected after a forged message with the same generation: %v", err)
	}
}

// TestDecryptInOrderTrafficBeyondForwardWindow checks that 1500 messages
// delivered in order are accepted with the default forward limit of 1000.
func TestDecryptInOrderTrafficBeyondForwardWindow(t *testing.T) {
	env := newDecryptionOrderTestEnv(t)
	msgs := make([]*framing.PrivateMessage, 0, 1500)
	for range 1500 {
		msgs = append(msgs, env.seal(t, env.legitTree, env.legitPriv, "m"))
	}
	for i, pm := range msgs {
		if _, err := framing.Decrypt(pm, env.decrypt); err != nil {
			t.Fatalf("in-order message %d: %v", i, err)
		}
	}
}
