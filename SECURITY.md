# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | ✅        |
| < 0.3.0 | ❌        |

This is beta software. Security fixes go into the latest minor version only.

## Reporting a vulnerability

**Don't open a public issue for security bugs.**

Email: **viltetomas2003@gmail.com**

Include a description of the issue, steps to reproduce, and the potential impact. I'll respond within 7 days with an assessment and a timeline. If a fix is needed, we can coordinate disclosure before going public.

## Current limitations

These are known gaps, not vulnerabilities. They are documented here because the project is still pre-1.0 and these edges matter:

- `NewGroupFromReInit` still needs a tighter review of its `joiner_secret` derivation path
- `new_member_proposal` PublicMessages do not yet verify the outer message signature independently
- Application message padding defaults to zero unless `Group.PaddingSize` is configured explicitly

Recent fixes:

- Received `AuthenticatedContent` signatures are now verified for application messages, commits, and supported PublicMessage flows
- PSKs are resolved in the commit receiver path
- Ratchet trees are truncated after member removals
- `PublicMessage` processing is implemented

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
- This is beta software — not recommended for production handling sensitive data until v1.0.0

For production use today, consider evaluating a mature MLS implementation that has already completed an external security review.
