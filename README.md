# mls-go

[![Go Reference](https://pkg.go.dev/badge/github.com/thomas-vilte/mls-go.svg)](https://pkg.go.dev/github.com/thomas-vilte/mls-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/thomas-vilte/mls-go)](https://goreportcard.com/report/github.com/thomas-vilte/mls-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Pure Go implementation of Messaging Layer Security (MLS) per [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420).

**Current status:** `v1.2.0` — stable, interop-verified.

## Why This Exists

I needed an RFC 9420-compliant MLS library in Go with no CGO dependency. The existing options either required C bindings or were incomplete. So I built this from scratch, testing interoperability against [mlspp](https://github.com/cisco/mlspp) and [OpenMLS](https://github.com/openmls/openmls) to make sure the implementation is correct.

Use it if you need group key exchange in Go: encrypted messaging, E2EE group chats, audio/video call encryption (DAVE protocol), or any protocol that needs a standard group ratchet.

## Overview

The library is organized around the RFC 9420 spec:

Main packages:

| Package           | Purpose                                                         |
|-------------------|-----------------------------------------------------------------|
| `mls` (root)      | High-level thread-safe `Client` API                             |
| `group`           | Low-level group lifecycle, commits, proposals, Welcome          |
| `keypackages`     | KeyPackage generation, validation, and lifetime options         |
| `credentials`     | BasicCredential and X.509 credential support                    |
| `ciphersuite`     | AEAD, HPKE, HKDF, signatures, hash references                   |
| `extensions`      | Extension types (ExternalSenders, RequiredCapabilities, …)      |
| `framing`         | MLSMessage, PublicMessage, PrivateMessage wire format           |
| `schedule`        | Key schedule and MLS-Exporter (RFC 9420 §8)                     |
| `secrettree`      | Per-sender secret tree ratchets                                 |
| `treesync`        | Ratchet tree and TreeKEM                                        |
| `storage`         | Pluggable storage interfaces + file, memory, encrypted backends |
| `testing/mlstest` | Testing helpers for MLS scenarios                               |

## What Works

Core RFC 9420 protocol:

- Group lifecycle: create, join (Welcome + External Join), leave
- Proposals: Add, Update, Remove, PSK, ReInit — with commit and Welcome
- Message protection: PrivateMessage (encrypted) and PublicMessage (signed)
- Post-compromise security: UpdatePath with parent-hash verification
- External Senders (RFC §12.1.8.1)
- Staged commits via `CommitPendingProposalsStaged` / `ConfirmPendingCommit` (RFC §14)
- State serialization with nonce-safe SecretTree counters
- Full LeafNode validation: lifetime, capabilities, extensions, credential types
- Per-generation replay protection — duplicate generation numbers rejected
- AEAD nonce counter limit enforced (2³²−1 per sender per epoch)
- Welcome join validates ratchet_tree structure and PSK availability

All the boring validation stuff from the RFC is implemented too (varint encodings, required_capabilities checks, parent-hash chain verification, etc.). The interop tests verify correctness against mlspp and OpenMLS.

## Interoperability

Tested against other MLS implementations via Docker:

| Target        | Suites  | Result                                                   |
|---------------|---------|----------------------------------------------------------|
| mls-go self   | 1, 2, 3 | 21/21 PASS                                               |
| mlspp cross   | 1, 2, 3 | 21/21 PASS                                               |
| OpenMLS cross | 1, 2, 3 | 12/12 PASS (subset; sequential mode required)            |

Scenarios: `welcome_join`, `application`, `commit`, `external_join`, `external_proposals`, `reinit`, `branch`.

### OpenMLS Note

OpenMLS cross-interop is **experimental** and limited to a subset of configs
(`welcome_join`, `application`, `external_join`, `deep_random`). The OpenMLS
Docker image tracks upstream HEAD without a pinned revision, so results can
drift after upstream changes. If the OpenMLS cross suite fails, check whether
the error originates from the OpenMLS interop client (e.g. key-store lookup
failures) before assuming a regression in mls-go.

See `interop/README.md` for details on the supported subset and known
unimplemented OpenMLS handlers.

## Quick Start

The recommended entry point is the `mls.Client` API.

```go
package main

import (
    "context"
    "fmt"
    "log"

    mls "github.com/thomas-vilte/mls-go"
    "github.com/thomas-vilte/mls-go/ciphersuite"
)

func main() {
    ctx := context.Background()
    cs := ciphersuite.MLS128DHKEMP256

    alice, err := mls.NewClient([]byte("alice"), cs)
    if err != nil {
        log.Fatal(err)
    }
    bob, err := mls.NewClient([]byte("bob"), cs)
    if err != nil {
        log.Fatal(err)
    }

    bobKP, _ := bob.FreshKeyPackageBytes(ctx)
    groupID, _ := alice.CreateGroup(ctx)
    _, welcome, _ := alice.InviteMember(ctx, groupID, bobKP)
    bob.JoinGroup(ctx, welcome)

    ciphertext, _ := alice.SendMessage(ctx, groupID, []byte("hello"))
    msg, _ := bob.ReceiveMessage(ctx, groupID, ciphertext)
    fmt.Println(string(msg.Plaintext)) // hello
}
```

## Client API

```go
// Identity
client.Epoch(ctx, groupID)          // current epoch number
client.OwnLeafIndex(ctx, groupID)   // my position in the ratchet tree
client.ListMembers(ctx, groupID)    // active members with identity + signing key

// Membership
client.CreateGroup(ctx)
client.InviteMember(ctx, groupID, memberKPBytes)        // → commit, welcome
client.JoinGroup(ctx, welcomeBytes)                     // → groupID
client.ExternalJoin(ctx, groupInfoBytes)                // → groupID, commit
client.RemoveMember(ctx, groupID, memberIdentity)       // → commit
client.LeaveGroup(ctx, groupID)                         // local-only state cleanup

// Proposals (batch flow)
client.ProposeAddMember(ctx, groupID, memberKPBytes)    // → signed PublicMessage
client.ProposeRemoveMember(ctx, groupID, memberIdentity)
client.CommitPendingProposals(ctx, groupID)             // → commit, welcome (auto-merge)
client.CancelPendingProposals(ctx, groupID)             // discard without committing

// RFC §14 staged commit (DS conflict-safe)
handle, _  := client.CommitPendingProposalsStaged(ctx, groupID) // generate only, no state change
welcome, _ := client.ConfirmPendingCommit(ctx, handle)          // DS accepted → merge + welcome
_           = client.DiscardPendingCommit(ctx, handle)          // DS rejected → rollback

// Maintenance
client.SelfUpdate(ctx, groupID)                         // rotate leaf encryption key

// Messaging
client.SendMessage(ctx, groupID, plaintext)                         // → ciphertext
client.SendMessage(ctx, groupID, plaintext, mls.WithAAD(aad))       // with authenticated data
client.ReceiveMessage(ctx, groupID, ciphertext)                     // → ReceivedMessage

// Crypto material
client.Export(ctx, groupID, label, context, length)     // MLS-Exporter
client.EpochAuthenticator(ctx, groupID)
client.GroupInfo(ctx, groupID)                          // signed GroupInfo bytes

// Process incoming
client.ProcessCommit(ctx, groupID, commitBytes)
```

### Options

```go
mls.NewClient(identity, cs,
    mls.WithStorage(groupStorage, keyStore),       // durable storage
    mls.WithCredentialValidator(validator),         // allowlist / cert policy
    mls.WithX509Credential(certDER, privKey),       // X.509 instead of Basic
    mls.WithPaddingSize(32),                        // AEAD padding in bytes
    mls.WithCacheStrategy(mls.CacheAlways),         // keep state in memory
    mls.WithEventHandler(func(e mls.GroupEvent) {  // lifecycle callbacks
        // EventMemberJoined, EventMemberRemoved, EventEpochAdvanced,
        // EventMessageReceived, EventSelfUpdated
    }),
)
```

## KeyPackage Options

```go
// Default: now-1h / now+83d (interop-safe margin)
kp, priv, err := keypackages.Generate(credWithKey, cs)

// Custom window
kp, priv, err := keypackages.Generate(credWithKey, cs,
    keypackages.WithLifetime(notBefore, notAfter))

// No expiry (not_before=0, not_after=2^64-1)
kp, priv, err := keypackages.Generate(credWithKey, cs,
    keypackages.InfiniteLifetime())
```

## Low-Level API

For advanced use cases (custom wire protocol, external commits, group inspection) use `group.Group` directly:

```go
g, err := group.NewGroup(groupID, cs, kp, kpPriv, group.WithExtensions(extensions))
g.Export("My App v1", senderIDBytes, 16)         // derive sender key
g.EpochAuthenticator()                           // authentication tag
g.RevokeProposal(ref)                            // remove in-flight proposal
g.MarshalState() / group.UnmarshalGroupState()   // persist / restore
```

## Storage

```go
// In-memory (tests / demos)
store := memorystore.NewStore()

// File-backed (durable)
store, err := filestore.NewStore("/var/lib/myapp/mls")

// Encrypted file-backed (recommended for production)
encStore, err := storage.NewEncryptedStore(store, encryptionKey)

client, err := mls.NewClient(identity, cs, mls.WithStorage(encStore, encStore))
```

## Build And Test

```bash
go build ./...
go test ./...
go test -race ./...
golangci-lint run ./...
```

## Interop Tests

```bash
# Build the server image after local changes
docker compose -f docker/docker-compose.yml build mls-go

# Self-interop (all suites in parallel, ~8 min)
./docker/run-interop.sh self

# Cross-interop against mlspp
./docker/run-interop.sh cross

# Cross-interop against OpenMLS
CROSS_TARGET=openmls ./docker/run-interop.sh cross

# Single suite
SUITES="2" ./docker/run-interop.sh self

# Stress mode (includes deep_random, takes longer)
RUN_STRESS=1 ./docker/run-interop.sh self
```

## Security

See [SECURITY.md](SECURITY.md) for deployment caveats, state encryption guidance, and known limitations.

## Integration Guide

See [INTEGRATION.md](INTEGRATION.md) for storage patterns, delivery service architecture, and multi-device considerations.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All code, comments, errors, tests, and docs must be in English.

## License

MIT. See [LICENSE](LICENSE).
