package framing_test

import (
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
)

// TestDecryptRejectsReplayedMessage checks that a message whose generation was already processed is
// refused (RFC 9420 §9.2).
func TestDecryptRejectsReplayedMessage(t *testing.T) {
	env := newDecryptionOrderTestEnv(t)
	pm := env.seal(t, env.legitTree, env.legitPriv, "once")

	if _, err := framing.Decrypt(pm, env.decrypt); err != nil {
		t.Fatalf("first Decrypt: %v", err)
	}
	if _, err := framing.Decrypt(pm, env.decrypt); !errors.Is(err, framing.ErrDecryptionFailed) {
		t.Fatalf("replayed message: err = %v, want ErrDecryptionFailed", err)
	}
}

// TestDecryptRejectsTamperedCiphertextWithoutConsumingGeneration checks that a message that fails the AEAD
// check leaves the ratchet where it was, so the honest message of that generation still decrypts.
func TestDecryptRejectsTamperedCiphertextWithoutConsumingGeneration(t *testing.T) {
	env := newDecryptionOrderTestEnv(t)
	honest := env.seal(t, env.legitTree, env.legitPriv, "honest")
	tampered := *honest
	tampered.Ciphertext = append([]byte(nil), honest.Ciphertext...)
	tampered.Ciphertext[0] ^= 0xFF

	if _, err := framing.Decrypt(&tampered, env.decrypt); !errors.Is(err, framing.ErrDecryptionFailed) {
		t.Fatalf("tampered message: err = %v, want ErrDecryptionFailed", err)
	}
	if gen := env.receiverLeaf(t).CurrentGeneration(); gen != 0 {
		t.Fatalf("tampered message moved the ratchet to generation %d, want 0", gen)
	}
	if _, err := framing.Decrypt(honest, env.decrypt); err != nil {
		t.Fatalf("honest message after a tampered one: %v", err)
	}
}

// TestDecryptVerifySignatureCallback checks that VerifySignature is called with the sender leaf index
// after decrypting, that its error is returned, and that a rejected message does not consume the
// generation.
func TestDecryptVerifySignatureCallback(t *testing.T) {
	env := newDecryptionOrderTestEnv(t)
	pm := env.seal(t, env.legitTree, env.legitPriv, "hello")

	rejected := errors.New("sender not allowed")
	var gotLeaf uint32 = 99
	params := env.decrypt
	params.SigPubKey = nil
	params.VerifySignature = func(leafIndex uint32, tbs []byte, sig *ciphersuite.Signature) error {
		gotLeaf = leafIndex
		if len(tbs) == 0 || sig == nil {
			t.Errorf("callback got tbs of %d bytes and signature %v", len(tbs), sig)
		}
		return rejected
	}
	if _, err := framing.Decrypt(pm, params); !errors.Is(err, rejected) {
		t.Fatalf("Decrypt with a rejecting callback: err = %v, want the callback error", err)
	}
	if gotLeaf != 0 {
		t.Fatalf("callback leaf index = %d, want 0", gotLeaf)
	}
	if gen := env.receiverLeaf(t).CurrentGeneration(); gen != 0 {
		t.Fatalf("rejected message moved the ratchet to generation %d, want 0", gen)
	}

	params.VerifySignature = func(uint32, []byte, *ciphersuite.Signature) error { return nil }
	if _, err := framing.Decrypt(pm, params); err != nil {
		t.Fatalf("Decrypt with an accepting callback: %v", err)
	}
}
