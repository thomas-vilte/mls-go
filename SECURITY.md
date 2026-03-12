# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✅        |
| < 0.2.0 | ❌        |

This is beta software. Security fixes go into the latest minor version only.

## Reporting a vulnerability

**Don't open a public issue for security bugs.**

Email: **viltetomas2003@gmail.com**

Include a description of the issue, steps to reproduce, and the potential impact. I'll respond within 7 days with an assessment and a timeline. If a fix is needed, we can coordinate disclosure before going public.

## Current limitations

These are known gaps, not vulnerabilities — they're documented and expected for v0.2.0:

- Received `AuthenticatedContent` signatures not verified (commits/proposals from peers)
- PSKs not resolved in the commit receiver path
- `NewGroupFromReInit` uses empty GroupContext for joiner_secret derivation
- Ratchet tree not truncated after member removals
- `PublicMessage` processing not implemented

None of these affect the confidentiality of encrypted messages in the normal group flow. They do limit the security guarantees on edge cases.

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

For production use today, consider [other implementation]() (Go, production-ready).
