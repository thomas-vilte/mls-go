# Integration Guide

## Recommended Architecture

For most applications, treat `mls.Client` as the device-local MLS state machine.

Each device should own:

- one `Client`
- one durable `GroupStorage`
- one durable `KeyStore`
- one transport binding to your delivery service

The delivery service is responsible for fan-out only. It does not need access to MLS plaintext.

## Storage

Recommended production shape:

1. `storage/file.NewStore(...)` or a custom database-backed `GroupStorage`
2. wrap group-state persistence with `storage.NewEncryptedStore(...)`
3. inject the resulting storage into `mls.NewClient(..., mls.WithStorage(gs, ks))`

Notes:

- `GroupStorage` persists serialized group state blobs
- `KeyStore` persists signature private keys and leaf encryption private keys
- the default in-memory store is fine for tests and demos, not for durable deployments

## Delivery Service Patterns

Typical application flow:

1. sender creates a proposal, commit, welcome, or application message locally
2. sender uploads the resulting wire bytes to the delivery service
3. recipients download bytes in group order
4. recipients call the matching `Client` method locally

Recommended message classes to fan out:

- proposal `PublicMessage`s
- commit `PublicMessage`s or `PrivateMessage`s
- `Welcome` messages for new members
- application `PrivateMessage`s

## Ordering

Best results come from processing commit messages in delivery order per group.

Application messages may arrive out of order across epochs. The low-level group implementation keeps epoch history to support that case, but only if local state has been preserved.

## Multiple Devices Per User

This library treats each MLS leaf as one participant instance.

In practice that means:

- one human user with three devices should usually appear as three MLS members
- your application must decide how identities are named and mapped to devices
- the library does not provide cross-device identity orchestration by itself

## External Join

For large groups, external join avoids sending a per-member `Welcome`.

Suggested flow:

1. an existing member publishes `GroupInfo`
2. the joiner calls `Client.ExternalJoin(...)`
3. existing members process the returned commit with `ProcessCommit(...)`

## Proposal-Then-Commit Flow

For batched membership changes:

1. call `ProposeAddMember(...)` or `ProposeRemoveMember(...)`
2. distribute the signed proposal if your application wants a proposal phase
3. call `CommitPendingProposals(...)` once

This is more efficient than committing after every single change.

To abort a pending batch without committing, call `CancelPendingProposals(...)`.

## Group State Inspection

The `Client` exposes read-only accessors that avoid the need to drop to the low-level `group.Group` API for common queries:

```go
epoch, err := client.Epoch(ctx, groupID)
leafIdx, err := client.OwnLeafIndex(ctx, groupID)
members, err := client.ListMembers(ctx, groupID)
epochAuth, err := client.EpochAuthenticator(ctx, groupID)
secret, err := client.Export(ctx, groupID, label, context, length)
```

## Credential Validation

If your application needs an allowlist, enterprise identity policy, or certificate policy, inject a `CredentialValidator` with `mls.WithCredentialValidator(...)`.

The validator is applied in the high-level client flows that admit new credentials, including invite and join paths.

## Suggested Server Model

Keep the server dumb:

- store opaque MLS bytes
- fan them out by group/channel
- never parse plaintext application messages
- optionally index metadata your app already knows outside MLS

That keeps MLS as a true end-to-end layer.
