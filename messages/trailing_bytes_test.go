package messages_test

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/internal/tls"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/messages"
)

// TestMessageParsersRejectTrailingAndMalformedData checks that UnmarshalWelcome and UnmarshalGroupInfo refuse
// bytes after the structure, and that a truncated entry in the Welcome secrets vector is an error. Each
// mutated input follows a control that parses.
func TestMessageParsersRejectTrailingAndMalformedData(t *testing.T) {
	trailing := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	t.Run("Welcome/trailing_bytes", func(t *testing.T) {
		secrets := []messages.EncryptedGroupSecrets{{
			KeyPackageHash: bytes.Repeat([]byte{0x01}, 32),
			EncryptedKey:   bytes.Repeat([]byte{0x02}, 65),
			Ciphertext:     bytes.Repeat([]byte{0x03}, 48),
		}}
		data, err := messages.NewWelcome(uint16(ciphersuite.MLS128DHKEMP256), secrets, []byte{0x04, 0x05}).Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if _, err := messages.UnmarshalWelcome(data); err != nil {
			t.Fatalf("control: valid Welcome rejected: %v", err)
		}
		mutated := append(append([]byte(nil), data...), trailing...)
		if _, err := messages.UnmarshalWelcome(mutated); err == nil {
			t.Error("UnmarshalWelcome accepted 4 trailing bytes")
		}
	})

	t.Run("Welcome/truncated_secret_entry", func(t *testing.T) {
		entry := tls.NewWriter()
		entry.WriteVLBytes(bytes.Repeat([]byte{0x01}, 32))
		entry.WriteVLBytes(bytes.Repeat([]byte{0x02}, 65))
		entry.WriteVLBytes(bytes.Repeat([]byte{0x03}, 48))
		valid := entry.Bytes()

		build := func(secrets []byte) []byte {
			w := tls.NewWriter()
			w.WriteUint16(uint16(ciphersuite.MLS128DHKEMP256))
			w.WriteVLBytes(secrets)
			w.WriteVLBytes([]byte{0x04, 0x05})
			return w.Bytes()
		}

		if _, err := messages.UnmarshalWelcome(build(valid)); err != nil {
			t.Fatalf("control: valid Welcome rejected: %v", err)
		}
		// A length prefix of 63 with no data behind it, appended after a valid entry.
		truncated := append(append([]byte(nil), valid...), 0x3F)
		if _, err := messages.UnmarshalWelcome(build(truncated)); err == nil {
			t.Error("UnmarshalWelcome dropped a truncated secrets entry without an error")
		}
	})

	t.Run("GroupInfo/trailing_bytes", func(t *testing.T) {
		gi := &messages.GroupInfo{
			GroupContext: &messages.GroupContext{
				Version:                 keypackages.MLS10,
				CipherSuite:             ciphersuite.CipherSuite(0x0002),
				GroupID:                 group.NewGroupID([]byte{0x00, 0x01, 0x02, 0x03}),
				Epoch:                   group.NewGroupEpoch(5),
				TreeHash:                bytes.Repeat([]byte{0xAA}, 32),
				ConfirmedTranscriptHash: bytes.Repeat([]byte{0xBB}, 32),
				Extensions:              []messages.Extension{},
			},
			Extensions:      []messages.Extension{},
			ConfirmationTag: bytes.Repeat([]byte{0xCC}, 32),
			Signer:          0,
			Signature:       []byte{0x01, 0x02, 0x03},
		}
		data := gi.Marshal()
		if _, err := messages.UnmarshalGroupInfo(data); err != nil {
			t.Fatalf("control: valid GroupInfo rejected: %v", err)
		}
		mutated := append(append([]byte(nil), data...), trailing...)
		if _, err := messages.UnmarshalGroupInfo(mutated); err == nil {
			t.Error("UnmarshalGroupInfo accepted 4 trailing bytes")
		}
	})
}
