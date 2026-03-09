# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> See also `AGENTS.md` for full coding style, naming conventions, error handling patterns, and testing guidelines. This file focuses on architectural context and things most likely to trip up an AI agent.

## Commands

```bash
go build ./...              # Build everything
go test ./...               # Run all tests
go test -race ./...         # Run with race detector (required before PRs)
go test ./group/ -run TestWelcomeRoundTrip -v   # Run a single test
go test ./schedule/... -run TestKeyScheduleInteropVectors -v  # Interop vectors
go fmt ./... && go vet ./...
```

No Makefile, no CI, no external dependencies — stdlib only.

## Architecture

This is a pure-Go implementation of RFC 9420 (MLS). The `openmls/` subdirectory is a Rust reference implementation git submodule — **never modify it**.

### Data flow for the core protocol loop

```
keypackages.Generate()          → KeyPackage + KeyPackagePrivateKeys
group.NewGroup()                → Group (epoch 0, key schedule initialized)
  └─ schedule.NewKeySchedule()  → KeySchedule (init_secret = 0^Nh)
  └─ treesync.NewRatchetTree()  → RatchetTree (single leaf)

group.AddMember(kp)             → Proposal{Add}
group.Commit(sigPrivKey, ...)   → StagedCommit
  └─ builds UpdatePath (TreeKEM encryption along direct path)
  └─ advances KeySchedule: joiner_secret → member_secret → epoch_secret → EpochSecrets
  └─ returns StagedCommit with PrecomputedEpochSecrets

group.CreateWelcome(kps, joinerSecret, ...)  → Welcome
  └─ encrypts GroupSecrets (joiner_secret + path_secret) per recipient HPKE key
  └─ encrypts GroupInfo with welcome_secret = DeriveSecret(member_secret, "welcome")

JoinFromWelcome(welcome, kp, privKeys)  → Group
  └─ decrypts GroupSecrets, sets joiner_secret directly via SetJoinerSecret()
  └─ runs ComputePskSecret + ComputeEpochSecret + DeriveEpochSecrets

group.MergeCommit(staged)       → advances the Group to next epoch
group.SendMessage(data, sigKey) → PrivateMessage (AEAD via secret tree)
group.ReceiveMessage(pm, idx)   → []byte
```

### Key Schedule (RFC 9420 §8) — Critical correctness details

The key schedule in `schedule/schedule.go` must follow this exact sequence:

```
1. intermediate  = HKDF-Extract(init_secret, commit_secret)
2. joiner_secret = ExpandWithLabel(intermediate, "joiner", GroupContext, Nh)
   → ComputeJoinerSecret(groupContext []byte)

3. member_secret = HKDF-Extract(joiner_secret, psk_secret)
   → ComputePskSecret(psks) or SetPskSecretDirect(psk)

4. welcome_secret = DeriveSecret(member_secret, "welcome")  ← empty context
   → ComputeWelcomeSecret()

5. epoch_secret  = ExpandWithLabel(member_secret, "epoch", GroupContext, Nh)
   → ComputeEpochSecret(groupContext []byte)

6. All epoch secrets = DeriveSecret(epoch_secret, label)
   → DeriveEpochSecrets()
```

`ComputeJoinerSecret` requires the **new epoch's GroupContext** bytes, which means GroupContext must be computed *before* starting the key schedule. See `external_commit.go` for an example of the correct ordering.

### TLS encoding (`internal/tls`) — Critical correctness detail

RFC 9420 §3.5 uses its own variable-length integer (MLS varint), **not ULEB128**:
- 0–63 → 1 byte (same as ULEB128)
- 64–16383 → 2 bytes: `[0x40 | (v>>8), v & 0xFF]` ← differs from ULEB128 for 64–127
- 16384+ → 4 bytes with high 2 bits = `10`

All variable-length vectors (`WriteVLBytes`/`ReadVLBytes`) use this encoding. Using the wrong encoding silently produces wrong KDFLabel → wrong `ExpandWithLabel` outputs for any context ≥ 64 bytes (including GroupContext).

### Package responsibilities

| Package | RFC 9420 section | Notes |
|---------|-----------------|-------|
| `internal/tls` | §3.5 | Wire format only; not public API |
| `ciphersuite` | §5.1 | P256/AES128GCM/SHA256 only (cs=2); others unsupported |
| `schedule` | §8 | Key schedule state machine; use `SetJoinerSecret` for Welcome receivers |
| `treesync` | §7 | Ratchet tree; `DirectPath`, `Copath`, `Resolution` for TreeKEM |
| `secrettree` | §9 | Per-sender/generation AEAD keys from encryption_secret |
| `framing` | §6 | `PrivateMessage` encrypt/decrypt; `AuthenticatedContent` |
| `keypackages` | §10 | `Generate()` is the entry point for creating a new member identity |
| `group` | §11–12 | Main API; `Group` struct owns all state |

### GroupContext and epoch advancement

`GroupContext` in `group/group_context.go` is the wire-encoded blob passed to key derivations. It must be serialized (`Marshal()`) fresh at each step where it changes. In `MergeCommit`, the group context is mutated in-place (`IncrementEpoch`, `UpdateTreeHash`, `UpdateConfirmedTranscriptHash`) **before** the key schedule runs, so `g.GroupContext.Marshal()` at that point correctly represents the new epoch.

### Proposal handling flow

Proposals are stored in `g.Proposals` (a `ProposalStore`) with the sender's leaf index. On `Commit()`:
1. `FilterProposalsForCommit()` validates and orders proposals (Add before Remove before Update, per RFC §12.2)
2. Each proposal is applied to a **cloned** tree (`treeDiff`)
3. An UpdatePath is generated for the committer's direct path
4. `MergeCommit()` applies the same proposals to the real group tree and advances the epoch

`ProcessReceivedCommit()` is the receiver path: it decrypts the UpdatePath using the receiver's HPKE key and calls `MergeCommit`.

## Interop test vectors

RFC-compliant test vectors live in `testdata/mls-interop-testvectors/test-vectors/`. Currently only `key-schedule.json` is present (from [mlswg/mls-implementations](https://github.com/mlswg/mls-implementations)).

The interop test (`schedule/interop_test.go`) uses `SetPskSecretDirect` to inject the raw psk_secret from the vector directly, bypassing PSK computation. This is intentional — the vectors provide the raw PSK input, not the member_secret.

## Known implementation gaps

- Only cipher suite 2 (MLS128DHKEMP256 / P256+AES128GCM+SHA256) is supported
- PSKs in `MergeCommit` (receiver path) are not resolved from proposals — caller must pass them
- `NewGroupFromReInit` is incomplete (uses empty GroupContext for joiner_secret)
- Received `AuthenticatedContent` signatures are not verified on commit/proposal messages
- The ratchet tree is never truncated after member removals
- `PublicMessage` processing is not implemented
