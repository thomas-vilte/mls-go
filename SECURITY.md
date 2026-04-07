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
