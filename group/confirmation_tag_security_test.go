package group

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/treesync"
)

func TestProcessReceivedCommit_ConfirmationTagSecurity(t *testing.T) {
	tests := []struct {
		name      string
		tamperTag bool
	}{
		{
			name: "valid_commit_is_accepted",
		},
		{
			name:      "invalid_tag_does_not_expose_secrets",
			tamperTag: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alice, bob, alicePriv, _ := setupTwoMemberGroup(t)
			oldEpoch := bob.Epoch().AsUint64()

			sigPriv := ciphersuite.NewSignaturePrivateKey(
				alicePriv.SignatureKey,
			)

			staged, err := alice.Commit(sigPriv, sigPriv.PublicKey(), nil)
			if err != nil {
				t.Fatalf("SETUP: creating commit: %v", err)
			}
			if staged.commit == nil || staged.commit.Path == nil {
				t.Fatal("SETUP: expected a commit with an UpdatePath")
			}
			if len(staged.commit.Proposals) != 0 {
				t.Fatal("SETUP: expected a commit without proposals")
			}
			if staged.authenticatedContent == nil {
				t.Fatal("SETUP: missing authenticated content")
			}

			ac := *staged.authenticatedContent
			sender := treesync.LeafIndex(ac.Content.Sender.LeafIndex)

			var initSecret, commitSecret []byte

			if tt.tamperTag {
				initSecret = append(
					[]byte(nil),
					bob.epochSecrets.InitSecret.AsSlice()...,
				)
				defer secureZeroBytes(initSecret)

				provisionalTree := buildProvisionalTree(
					bob.ratchetTree,
					sender,
					staged.commit.Path,
					bob.cipherSuite,
				)
				provisionalContext := bob.provisionalGroupContextBytesFromTree(
					provisionalTree,
					nil,
				)

				rootSecret, err := bob.decryptPathSecret(
					provisionalTree,
					sender,
					staged.commit.Path,
					bob.MyLeafEncryptionKey(),
					provisionalContext,
					nil,
				)
				if err != nil {
					t.Fatalf("SETUP: decrypting path secret: %v", err)
				}

				commitSecret = append([]byte(nil), rootSecret.AsSlice()...)
				secureZeroSecret(rootSecret)
				defer secureZeroBytes(commitSecret)

				if len(initSecret) != bob.cipherSuite.HashLength() {
					t.Fatal("SETUP: unexpected init_secret length")
				}
				if len(commitSecret) != bob.cipherSuite.HashLength() {
					t.Fatal("SETUP: unexpected commit_secret length")
				}
				if len(ac.Auth.ConfirmationTag) == 0 {
					t.Fatal("SETUP: missing confirmation tag")
				}

				ac.Auth.ConfirmationTag = append(
					[]byte(nil),
					ac.Auth.ConfirmationTag...,
				)
				ac.Auth.ConfirmationTag[0] ^= 0x01
			}

			err = bob.ProcessReceivedCommit(
				&ac,
				sender,
				bob.MyLeafEncryptionKey(),
			)

			if !tt.tamperTag {
				if err != nil {
					t.Fatalf("valid commit rejected: %v", err)
				}
				if got := bob.Epoch().AsUint64(); got != oldEpoch+1 {
					t.Fatalf("epoch = %d, want %d", got, oldEpoch+1)
				}
				return
			}

			if err == nil {
				t.Fatal("commit with an invalid confirmation tag was accepted")
			}

			message := err.Error()

			for _, secret := range []struct {
				name  string
				value []byte
			}{
				{name: "init_secret", value: initSecret},
				{name: "commit_secret", value: commitSecret},
			} {
				if bytes.Contains([]byte(message), secret.value) {
					t.Errorf("error exposes %s as raw bytes", secret.name)
				}

				encoded := hex.EncodeToString(secret.value)
				if strings.Contains(strings.ToLower(message), encoded) {
					t.Errorf("error exposes %s in hex", secret.name)
				}
			}

			for _, field := range []string{
				"initSecret",
				"commitSecret",
				"init_secret",
				"commit_secret",
			} {
				if strings.Contains(message, field) {
					t.Errorf("error contains secret field %q", field)
				}
			}

			if !errors.Is(err, ErrConfirmationTagMismatch) {
				t.Errorf(
					"error does not wrap ErrConfirmationTagMismatch; got %T",
					err,
				)
			}
		})
	}
}
