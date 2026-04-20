# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.2.x   | ✅        |
| 1.1.x   | ❌        |
| 1.0.x   | ❌        |
| < 1.0.0 | ❌        |

Security fixes go into the latest minor version only.

## Reporting a vulnerability

**Don't open a public issue for security bugs.**

Email: **viltetomas2003@gmail.com**

Include a description of the issue, steps to reproduce, and the potential impact. I'll respond within 7 days with an assessment and a timeline. If a fix is needed, we can coordinate disclosure before going public.

## Current limitations

These are known gaps, not vulnerabilities. They are documented here because the project is still pre-1.0 and these edges matter:

- Secret zeroing in Go is best-effort. mls-go overwrites sensitive byte slices and uses `runtime.KeepAlive()` / `SecureZero()` patterns to reduce dead-store elimination, but the Go runtime may still copy or move data before zeroing. This means in-memory secret erasure is a mitigation, not a hard guarantee equivalent to `mlock`-backed secure memory.
- `NewGroupFromReInit` still needs a tighter review of its `joiner_secret` derivation path
- `new_member_proposal` PublicMessages do not yet verify the outer message signature independently
- Application message padding defaults to zero unless `Group.PaddingSize` is configured explicitly
- `LeaveGroup` in the high-level `Client` performs a local state cleanup only; it does not broadcast a self-remove commit to other members. Use `RemoveMember` with the caller's own identity if a broadcast removal is required.

Recent fixes:

- Received `AuthenticatedContent` signatures are now verified for application messages, commits, and supported PublicMessage flows
- PSKs are resolved in the commit receiver path
- Ratchet trees are truncated after member removals
- `PublicMessage` processing is implemented
- **RFC 9420 §2.1.2**: MLS varint reader now rejects non-minimal encodings to preserve canonical wire format for hashed protocol objects
- **RFC 9420 §7.3**: LeafNode extensions must be declared in the node's capabilities; validated on Add/Update receive
- **RFC 9420 §7.9.2 / §12.4.3.1**: `JoinFromWelcome` verifies the parent-hash chain for the GroupInfo signer leaf; `MergeCommit` verifies it when an UpdatePath is present
- **RFC 9420 §9.2**: old HPKE leaf private key is zeroed when an Update proposal replaces the sender's leaf
- **RFC 9420 §11.1**: `required_capabilities` extension is validated against all current members' declared capabilities before accepting a commit
- **RFC 9420 §11.3**: Resumption PSK with `usage=reinit` is rejected unless a ReInit proposal is present in the same commit
- **RFC 9420 §12.1.8**: External senders are restricted to allowed proposal types (add, remove, psk, reinit, group_context_extensions)
- **RFC 9420 §12.4**: `SendMessage` and `SendApplicationMessage` now reject application data while valid proposals are pending
- **RFC 9420 §12.4.2**: received UpdatePath public keys are verified against the path secrets derived during commit processing
- **RFC 9420 §12.4.3.1**: credential type of incoming Add/Update proposals is checked against all current members' capability declarations
- **RFC 9420 §12.4.3.3**: `UnmarshalTreeFromExtension` rejects ratchet_tree extensions whose last serialized node is blank
- **RFC 9420 §15.2**: AEAD nonce counter limit (2³²−1) is enforced per sender per epoch; `SendMessage` returns an error if the limit is reached
- **Welcome join**: every non-blank LeafNode in the received ratchet_tree is structurally validated; `unmerged_leaves` entries are checked for validity and subtree containment; missing PSK store or missing PSK entry returns an explicit error instead of silently failing
- **RFC 9420 §9.2 / §15.2**: per-generation replay protection — `MarkGenerationUsed` tracks processed generations per sender; duplicate generation numbers are rejected with an explicit error
- **RFC 9420 §13.4**: joining a group via Welcome now verifies that mls-go supports every extension present in the GroupContext; unsupported extensions cause the join to fail rather than silently proceeding with unknown group semantics

These limitations do not break the normal encrypted group flow, but they do reduce assurance on specific edge cases.

## Threat model

mls-go implements the core MLS security properties from RFC 9420, assuming the application preserves local private state correctly and delivers protocol messages coherently.

### Security properties provided

- Confidentiality of application messages against parties that are not current group members
- Forward secrecy across epochs: removed members cannot decrypt future epochs
- Post-compromise security after recovery: if a compromised member performs a fresh update and the attacker later loses access, future epochs regain confidentiality
- Authentication of commits, proposals, and application messages according to the credential and signature model used by the group
- Integrity of ratchet-tree evolution, transcript hashes, and confirmation tags through RFC 9420 validation

### Assumptions

- The Delivery Service (DS) is untrusted for message contents, but is assumed to provide eventual delivery of protocol messages
- Applications are responsible for durable storage of local group state if they need to survive restarts or support out-of-order delivery across epochs
- Applications are responsible for protecting signature private keys, HPKE private keys, and serialized group state at rest
- Credential validation is only as strong as the application's configured trust model (`BasicCredential`, X.509 validation, or application-specific policy)

### Delivery Service compromise

A malicious or compromised DS can:

- Drop, delay, replay, reorder, or equivocate on delivered messages
- Observe metadata visible outside MLS ciphertexts
- Cause availability failures or force clients into conflict resolution paths

A malicious or compromised DS cannot, by itself:

- Forge valid member-authenticated commits or application messages
- Read protected application plaintext without also compromising member key material
- Bypass transcript-hash, confirmation-tag, or ratchet-tree validation performed by clients

### Storage compromise

If an attacker obtains persisted group state or live process memory containing MLS state, they may gain access to:

- Epoch secrets
- Secret tree state
- Leaf private keys
- Enough local state to continue operating as that member

In practice, compromise of serialized state should be treated as compromise of that local member. `MarshalState()` is a serialization helper, not a secure storage format.

### Member compromise

If a member device is compromised, the attacker can act as that member and decrypt traffic available to that member for the epochs covered by the compromised state.

MLS post-compromise security is not instantaneous:

- If the attacker keeps access to the compromised device, they keep access
- If the attacker loses access, confidentiality is only restored after fresh updates or commits advance the group into new epochs derived from uncompromised secrets

### Out of scope / not guaranteed

mls-go does not by itself provide:

- Deniability beyond the base MLS protocol properties
- Metadata protection against the Delivery Service or network observers
- Reliable ordering or exactly-once delivery
- Secure persistence, HSM integration, `mlock`, or OS-level secret isolation
- Protection against compromise of the host runtime, debugger access, or full memory disclosure

## Constant-time comparison audit

A targeted audit was performed for `bytes.Equal` uses in production code.

Current classification:

- `group/state.go`
  - GroupID equality during restored-state validation: public identifier, not secret
  - TreeHash equality during restored-state validation: public integrity value, not secret
- `group/welcome.go`
  - Matching `key_package_ref` / encrypted group secrets entry: public protocol lookup
  - Ratchet tree hash equality: public integrity value from GroupInfo
  - Matching leaf encryption public keys in the ratchet tree: public key lookup
- `messages/messages.go`
  - Matching `KeyPackageHash` in Welcome secrets: public protocol lookup
- `group/group.go`
  - GroupID equality on received commit path: public identifier
  - Signature public key matching in tree/proposals: public key lookup
  - HPKE public key equality checks for UpdatePath validation: public key consistency checks
  - Proposal reference equality in the proposal store: public hash/reference lookup

No currently-audited production use of `bytes.Equal` was identified as a comparison of secret key material, MAC tags, confirmation tags, or membership tags.

Secret/MAC comparisons continue to use constant-time helpers:

- `ciphersuite.EqualCT()`
- `subtle.ConstantTimeCompare`

## Cryptographic foundation

mls-go uses:

- Go standard library crypto (`crypto/aes`, `crypto/ecdh`, `crypto/ed25519`, `crypto/hpke`)
- `golang.org/x/crypto` for ChaCha20-Poly1305
- RFC 9420, RFC 9180, RFC 5869 as specification

No custom crypto implementations. All primitives come from audited libraries.

## Recommendations for users

- Always use the latest version
- Validate `KeyPackage`s before trusting them — don't skip `Validate()`
- Protect private keys with secure storage; clear them from memory after use
- Do not persist raw `MarshalState()` output in plaintext; wrap your `GroupStorage` with `storage.NewEncryptedStore(...)` or encrypt state externally
- Prefer `storage/file` or your own durable `GroupStorage` implementation over the default in-memory store for any non-test deployment
- Call `SelfUpdate` periodically if your application expects long-lived memberships and wants fresh leaf encryption keys
- Keep the full local group state durable; if you lose it, you cannot safely continue decrypting future epochs for that device
- Treat each persisted group state as highly sensitive secret material: it includes epoch secrets, tree state, and enough data to continue as that member
- No external security audit has been performed. For applications handling highly sensitive data, consider commissioning an audit before deploying.

## State handling

`MarshalState()` is intentionally a serialization helper, not a secure storage format.

- It contains epoch secrets and private state in plaintext bytes
- It is suitable for tests, debugging, or as an input to an encrypted storage layer
- It must not be written to disk, object storage, or databases without encryption at rest

Recommended patterns:

1. Use `storage/file.NewStore(...)` for a durable on-disk backend.
2. Wrap that store with `storage.NewEncryptedStore(...)` before persisting group state.
3. Keep signature private keys and leaf private keys in an application-controlled secret store if your deployment requires stronger isolation.

## Operational notes

- `Client` is safe for concurrent use, but group state is still logically sequential per group epoch. If your application processes multiple network events for the same group, serialize them in delivery order when possible.
- `group.Group` itself is not safe for concurrent use without external synchronization.
- Messages may arrive out of order across epochs; the low-level receiver supports epoch history for that case, but applications still need durable state to benefit from it.
