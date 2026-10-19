package mls

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
)

// TestClientJoinUnsupportedCipherSuite verifies that join operations reject
// unsupported cipher suites without panicking.
func TestClientJoinUnsupportedCipherSuite(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	cs := ciphersuite.MLS128DHKEMP256

	alice, err := NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	t.Cleanup(func() { _ = alice.Close() })
	bob, err := NewClient([]byte("bob"), cs)
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}
	t.Cleanup(func() { _ = bob.Close() })
	charlie, err := NewClient([]byte("charlie"), cs)
	if err != nil {
		t.Fatalf("NewClient(charlie): %v", err)
	}
	t.Cleanup(func() { _ = charlie.Close() })
	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	groupInfo, err := alice.GroupInfo(ctx, groupID)
	if err != nil {
		t.Fatalf("GroupInfo: %v", err)
	}

	for _, suite := range []uint16{0x0080, 0x0000, 0xFFFF} {
		t.Run(fmt.Sprintf("JoinGroup/cs=0x%04x", suite), func(t *testing.T) {
			if _, err := bob.FreshKeyPackageBytes(t.Context()); err != nil {
				t.Fatalf("FreshKeyPackageBytes: %v", err)
			}
			// 4 bytes: cipher_suite, empty secrets<V>, empty encrypted_group_info<V>.
			welcome := []byte{byte(suite >> 8), byte(suite), 0x00, 0x00}
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("JoinGroup panicked: %v", r)
					}
				}()
				if _, err := bob.JoinGroup(t.Context(), welcome); !errors.Is(err, group.ErrUnsupportedCipherSuite) {
					t.Fatalf("JoinGroup err = %v, want group.ErrUnsupportedCipherSuite", err)
				}
			}()
		})
	}

	// Control: the genuine GroupInfo, with its own cipher suite, must still be accepted.
	t.Run("ExternalJoin/control", func(t *testing.T) {
		if _, _, err := charlie.ExternalJoin(t.Context(), groupInfo); err != nil {
			t.Fatalf("ExternalJoin(genuine GroupInfo): %v", err)
		}
	})

	for _, suite := range []uint16{0x0080, 0x0000, 0xFFFF} {
		t.Run(fmt.Sprintf("ExternalJoin/cs=0x%04x", suite), func(t *testing.T) {
			// GroupInfo starts with version (2 bytes) followed by cipher_suite (2 bytes).
			patched := bytes.Clone(groupInfo)
			patched[2], patched[3] = byte(suite>>8), byte(suite)
			if _, _, err := charlie.ExternalJoin(t.Context(), patched); !errors.Is(err, group.ErrUnsupportedCipherSuite) {
				t.Fatalf("ExternalJoin err = %v, want group.ErrUnsupportedCipherSuite", err)
			}
		})
	}
}
