// Package mls is the module root for github.com/thomas-vilte/mls-go.
//
// The implementation is organized into subpackages:
//
//   - ciphersuite: HPKE, HKDF, AEAD, signatures, and hash references
//   - credentials: MLS credentials
//   - extensions: MLS extension types and helpers
//   - framing: MLSMessage, PublicMessage, and PrivateMessage framing
//   - group: group lifecycle, proposals, commits, and Welcome handling
//   - keypackages: KeyPackage generation and validation
//   - schedule: MLS key schedule and exporter support
//   - secrettree: per-sender secret tree ratchets
//   - treesync: ratchet tree and TreeKEM helpers
//
// The recommended entry point for most applications is Client, which provides a
// higher-level "bytes in, bytes out" API over the lower-level group package.
//
// A minimal high-level flow looks like this:
//
//	alice, err := mls.NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	bob, err := mls.NewClient([]byte("bob"), ciphersuite.MLS128DHKEMP256)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	ctx := context.Background()
//
//	bobKeyPackage, err := bob.FreshKeyPackageBytes(ctx)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	groupID, err := alice.CreateGroup(ctx)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	_, welcome, err := alice.InviteMember(ctx, groupID, bobKeyPackage)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	if _, err := bob.JoinGroup(ctx, welcome); err != nil {
//		log.Fatal(err)
//	}
//
//	msg, err := alice.SendMessage(ctx, groupID, []byte("hello bob"))
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	received, err := bob.ReceiveMessage(ctx, groupID, msg)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	_ = received.Plaintext
//
// For a full low-level example, see ./examples/basic_chat.
// For the high-level Client flow, see ./examples/basic_chat_v2.
//
// Applications that need direct protocol control can still use the group,
// keypackages, framing, and related subpackages directly.
//
// References:
//
//   - RFC 9420: https://www.rfc-editor.org/rfc/rfc9420
//   - RFC 9180: https://www.rfc-editor.org/rfc/rfc9180
package mls
