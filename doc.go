// Package mls is the top-level entry point for github.com/thomas-vilte/mls-go,
// a pure-Go implementation of Messaging Layer Security per [RFC 9420].
//
// # Architecture
//
// The library has two layers. Most applications only need the high-level Client:
//
//	┌─────────────────────────────────────────────────────────────┐
//	│                    mls (root package)                       │
//	│                                                             │
//	│  Client — thread-safe, bytes-in/bytes-out, persistent state │
//	│    • CreateGroup / JoinGroup / InviteMember / RemoveMember  │
//	│    • SendMessage / ReceiveMessage                           │
//	│    • CommitPendingProposalsStaged / Confirm / Discard       │
//	└──────────────────────────┬──────────────────────────────────┘
//	                           │ uses
//	┌──────────────────────────▼──────────────────────────────────┐
//	│                    group (subpackage)                       │
//	│                                                             │
//	│  Group — low-level RFC 9420 state machine                   │
//	│    • Proposals, Commits, Welcome, UpdatePath                │
//	│    • Ratchet tree (treesync), Key schedule (schedule)       │
//	│    • Secret tree (secrettree), Message framing (framing)    │
//	└─────────────────────────────────────────────────────────────┘
//
// # Supported Cipher Suites (RFC 9420 §17.1)
//
//	┌─────┬────────────────────────────────────────────────────────┐
//	│ ID  │ Cipher Suite Name                                      │
//	├─────┼────────────────────────────────────────────────────────┤
//	│  1  │ MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519    (CS1) │
//	│  2  │ MLS_128_DHKEMP256_AES128GCM_SHA256_P256          (CS2) │
//	│  3  │ MLS_128_DHKEMX25519_CHACHA20POLY1305_Ed25519     (CS3) │
//	│  5  │ MLS_256_DHKEMP521_AES256GCM_SHA512_P521          (CS5) │
//	└─────┴────────────────────────────────────────────────────────┘
//	CS4 (X448/Ed448) requires golang.org/x/crypto — not yet in stdlib.
//
// # Quick Start
//
//	alice, _ := mls.NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256)
//	bob,   _ := mls.NewClient([]byte("bob"),   ciphersuite.MLS128DHKEMP256)
//
//	ctx      := context.Background()
//	bobKP, _ := bob.FreshKeyPackageBytes(ctx)
//	groupID, _ := alice.CreateGroup(ctx)
//	_, welcome, _ := alice.InviteMember(ctx, groupID, bobKP)
//	bob.JoinGroup(ctx, welcome)
//
//	ct, _  := alice.SendMessage(ctx, groupID, []byte("hello"))
//	msg, _ := bob.ReceiveMessage(ctx, groupID, ct)
//	// msg.Plaintext == []byte("hello")
//
// # Delivery Service (DS) Conflict Safety — Staged Commits (RFC 9420 §14)
//
// When multiple members commit concurrently, the DS selects one. Use the staged
// API so only the accepted commit advances local state:
//
//	handle, _  := alice.CommitPendingProposalsStaged(ctx, groupID)
//	// ... wait for DS to accept or reject ...
//	welcome, _ := alice.ConfirmPendingCommit(ctx, handle)   // DS accepted
//	// — or —
//	alice.DiscardPendingCommit(ctx, handle)                  // DS rejected → rollback
//
// # Extensibility Hooks
//
// The Client supports three pluggable hooks for application policy:
//
//	mls.NewClient(identity, cs,
//	    // 1. Custom extension types (RFC 9420 §13):
//	    mls.WithExtensionHandler(myExtension{}),
//
//	    // 2. Custom credential validators (RFC 9420 §5.2):
//	    mls.WithCredentialHandler(0xFF01, myVCHandler{}),
//
//	    // 3. Proposal policy (membership rules beyond the RFC):
//	    mls.WithProposalPolicy(adminOnlyRemovePolicy{}),
//	)
//
// # Storage
//
// By default, Client stores group state in memory (lost on restart). For durable
// state, provide a [GroupStorage] + [KeyStore] backend:
//
//	store, err := file.New("/var/lib/myapp/mls")
//	client, err := mls.NewClient(identity, cs,
//	    mls.WithStorage(store, store),
//	)
//
// # Logging
//
// Client emits structured logs via [log/slog]. INFO logs cover lifecycle events
// (group created/joined, member invited/removed). WARN logs cover all error
// paths. DEBUG logs trace individual commit and message processing steps:
//
//	client, err := mls.NewClient(identity, cs,
//	    mls.WithLogger(slog.Default()),
//	)
//
// # Subpackages
//
//   - [github.com/thomas-vilte/mls-go/group]: low-level RFC 9420 group state machine
//   - [github.com/thomas-vilte/mls-go/ciphersuite]: HPKE, HKDF, AEAD, signatures
//   - [github.com/thomas-vilte/mls-go/credentials]: BasicCredential and X.509
//   - [github.com/thomas-vilte/mls-go/extensions]: extension types (§13)
//   - [github.com/thomas-vilte/mls-go/framing]: MLSMessage wire format (§6)
//   - [github.com/thomas-vilte/mls-go/keypackages]: KeyPackage generation (§10)
//   - [github.com/thomas-vilte/mls-go/schedule]: key schedule and MLS-Exporter (§8)
//   - [github.com/thomas-vilte/mls-go/secrettree]: per-sender secret tree ratchets (§9)
//   - [github.com/thomas-vilte/mls-go/treesync]: ratchet tree and TreeKEM (§7)
//   - [github.com/thomas-vilte/mls-go/storage]: pluggable storage backends
//
// # References
//
//   - RFC 9420 (MLS): https://www.rfc-editor.org/rfc/rfc9420
//   - RFC 9180 (HPKE): https://www.rfc-editor.org/rfc/rfc9180
//   - IANA MLS Registry: https://www.iana.org/assignments/mls/mls.xhtml
//
// [RFC 9420]: https://www.rfc-editor.org/rfc/rfc9420
package mls
