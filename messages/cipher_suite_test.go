package messages_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/messages"
)

// unsupportedCipherSuites includes unregistered values and the unimplemented CS4.
var unsupportedCipherSuites = []uint16{0x0080, 0x0000, 0xFFFF, 0x0004}

// TestUnmarshalUnsupportedCipherSuite checks that Welcome and GroupInfo parsers
// reject unsupported cipher suites.
func TestUnmarshalUnsupportedCipherSuite(t *testing.T) {
	t.Parallel()

	for _, cs := range unsupportedCipherSuites {
		t.Run(fmt.Sprintf("UnmarshalWelcome/cs=0x%04x", cs), func(t *testing.T) {
			data, err := messages.NewWelcome(cs, nil, []byte{}).Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if _, err := messages.UnmarshalWelcome(data); !errors.Is(err, ciphersuite.ErrUnsupportedSuite) {
				t.Fatalf("UnmarshalWelcome err = %v, want ciphersuite.ErrUnsupportedSuite", err)
			}
		})

		t.Run(fmt.Sprintf("UnmarshalGroupInfo/cs=0x%04x", cs), func(t *testing.T) {
			// 64-byte hashes: Nh is 64 for CS4, so a shorter value would fail the Nh
			// length check before the suite is looked at.
			gi := &messages.GroupInfo{
				GroupContext: &messages.GroupContext{
					Version:                 keypackages.MLS10,
					CipherSuite:             ciphersuite.CipherSuite(cs),
					GroupID:                 group.NewGroupID([]byte("group")),
					Epoch:                   group.NewGroupEpoch(0),
					TreeHash:                make([]byte, 64),
					ConfirmedTranscriptHash: make([]byte, 64),
					Extensions:              []messages.Extension{},
				},
				Extensions:      []messages.Extension{},
				ConfirmationTag: make([]byte, 64),
				Signature:       []byte{0x01},
			}
			if _, err := messages.UnmarshalGroupInfo(gi.Marshal()); !errors.Is(err, ciphersuite.ErrUnsupportedSuite) {
				t.Fatalf("UnmarshalGroupInfo err = %v, want ciphersuite.ErrUnsupportedSuite", err)
			}
		})
	}

	// Control: a supported suite still parses.
	t.Run("control/supported-suite", func(t *testing.T) {
		data, err := messages.NewWelcome(uint16(ciphersuite.MLS128DHKEMP256), nil, []byte{}).Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if _, err := messages.UnmarshalWelcome(data); err != nil {
			t.Fatalf("UnmarshalWelcome(supported) err = %v", err)
		}
	})
}
