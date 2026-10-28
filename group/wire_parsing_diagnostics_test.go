//go:build diagnostics

package group

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/internal/tls"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// Additional diagnostics for the parsers of the group package.

// encodeDiagnosticGroupSecrets encodes GroupSecrets with a joiner_secret, an optional<PathSecret> with the
// given presence octet and an empty psks<V>.
func encodeDiagnosticGroupSecrets(presence uint8, withPath bool) []byte {
	w := tls.NewWriter()
	w.WriteVLBytes(bytes.Repeat([]byte{0x11}, 32))
	w.WriteUint8(presence)
	if withPath {
		w.WriteVLBytes(bytes.Repeat([]byte{0x22}, 32))
	}
	w.WriteVLBytes(nil)
	return w.Bytes()
}

// TestGroupSecretsPresenceOctetOutOfRange checks that a presence octet other than 0 or 1 is refused as
// malformed instead of being read as absent (RFC 9420 §2.1.1).
func TestGroupSecretsPresenceOctetOutOfRange(t *testing.T) {
	if _, err := UnmarshalGroupSecrets(encodeDiagnosticGroupSecrets(0, false)); err != nil {
		t.Fatalf("control presence=0: %v", err)
	}
	if _, err := UnmarshalGroupSecrets(encodeDiagnosticGroupSecrets(1, true)); err != nil {
		t.Fatalf("control presence=1: %v", err)
	}
	if _, err := UnmarshalGroupSecrets(encodeDiagnosticGroupSecrets(2, false)); err == nil {
		t.Errorf("UnmarshalGroupSecrets accepted optional<PathSecret> presence octet 2 (RFC 9420 §2.1.1 requires rejection)")
	}
}

// TestTopLevelParsersRejectTrailingBytes checks that the top-level parsers of the group package refuse bytes
// after the structure.
func TestTopLevelParsersRejectTrailingBytes(t *testing.T) {
	tail := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	gc := &GroupContext{
		Version:                 keypackages.MLS10,
		CipherSuite:             ciphersuite.MLS128DHKEMP256,
		GroupID:                 NewGroupID([]byte("parse-group")),
		Epoch:                   NewGroupEpoch(3),
		TreeHash:                bytes.Repeat([]byte{0x33}, 32),
		ConfirmedTranscriptHash: bytes.Repeat([]byte{0x44}, 32),
	}
	removeWriter := tls.NewWriter()
	removeWriter.WriteUint16(uint16(ProposalTypeRemove))
	removeWriter.WriteUint32(1)

	cases := []struct {
		name  string
		data  []byte
		parse func([]byte) error
	}{
		{"UnmarshalProposal(remove)", removeWriter.Bytes(), func(b []byte) error {
			_, err := UnmarshalProposal(b)
			return err
		}},
		{"UnmarshalGroupContext", gc.Marshal(), func(b []byte) error {
			_, err := UnmarshalGroupContext(b)
			return err
		}},
		{"UnmarshalCommit(control, ya rechazaba)", []byte{0x00, 0x00}, func(b []byte) error {
			_, err := UnmarshalCommit(b)
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.parse(c.data); err != nil {
				t.Fatalf("control: parse(valid) = %v", err)
			}
			withTail := append(append([]byte{}, c.data...), tail...)
			if err := c.parse(withTail); err == nil {
				t.Errorf("%s accepted 4 trailing bytes", c.name)
			}
		})
	}
}

// TestWelcomeRejectsTruncatedSecretEntry checks that a Welcome whose secrets list ends in a truncated entry is
// an error instead of a shorter list.
func TestWelcomeRejectsTruncatedSecretEntry(t *testing.T) {
	entries := tls.NewWriter()
	// A complete entry: new_member, kem_output, ciphertext.
	entries.WriteVLBytes([]byte{0xA1, 0xA2})
	entries.WriteVLBytes([]byte{0xB1})
	entries.WriteVLBytes([]byte{0xC1})
	// A truncated entry: new_member only.
	entries.WriteVLBytes([]byte{0xA3})

	w := tls.NewWriter()
	w.WriteUint16(uint16(ciphersuite.MLS128DHKEMP256))
	w.WriteVLBytes(entries.Bytes())
	w.WriteVLBytes([]byte{0x01})

	if _, err := UnmarshalWelcome(w.Bytes()); err == nil {
		t.Errorf("UnmarshalWelcome accepted a secrets vector whose last entry is truncated")
	}
}

// TestGroupSecretsRejectsReservedAndUndefinedPSKTypes checks that a reserved (0) or undefined PSKType is not
// read as an external PSK (RFC 9420 §8.4).
func TestGroupSecretsRejectsReservedAndUndefinedPSKTypes(t *testing.T) {
	build := func(pskType uint8) []byte {
		psk := tls.NewWriter()
		psk.WriteUint8(pskType)
		psk.WriteVLBytes([]byte{0xAB})
		psk.WriteVLBytes([]byte{0xCD})
		w := tls.NewWriter()
		w.WriteVLBytes(bytes.Repeat([]byte{0x11}, 32))
		w.WriteUint8(0)
		w.WriteVLBytes(psk.Bytes())
		return w.Bytes()
	}
	if _, err := UnmarshalGroupSecrets(build(1)); err != nil {
		t.Fatalf("control psktype=external: %v", err)
	}
	for _, ty := range []uint8{0, 3, 7} {
		if _, err := UnmarshalGroupSecrets(build(ty)); err == nil {
			t.Errorf("UnmarshalGroupSecrets accepted psktype %d (RFC 9420 §8.4 defines only reserved, external and resumption)", ty)
		}
	}
}
