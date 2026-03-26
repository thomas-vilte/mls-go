# mls-go

[![Go Reference](https://pkg.go.dev/badge/github.com/thomas-vilte/mls-go.svg)](https://pkg.go.dev/github.com/thomas-vilte/mls-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/thomas-vilte/mls-go)](https://goreportcard.com/report/github.com/thomas-vilte/mls-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Pure Go implementation of Messaging Layer Security (MLS) per RFC 9420.

**62 Go files | 13 packages | 3 cipher suites | 0 CGO dependencies | 74% coverage**

---

## What is this?

mls-go is a native Go implementation of [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html) — the MLS protocol. This is a pure Go project with zero CGO dependencies.

MLS is the industry standard for end-to-end encrypted group messaging, used by Matrix, Cisco Webex, and others. The hard part is key management: every time someone joins or leaves, keys rotate — without tgoing the server. MLS solves this with a ratchet tree (TreeKEM).

**Current status:** Beta (v0.2.0). API may change before v1.0.0.

---

## Why this exists

I needed MLS for a Go project. There's no native implementation. So I built mls-go. It's not complete, but it works. If you need MLS in Go without CGO, this might help.

---

## What works (v0.2.0)

**Cipher suites:**
- CS1: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` ✅
- CS2: `MLS_128_DHKEMP256_AES128GCM_SHA256_P256` ✅
- CS3: `MLS_256_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` ✅

**Protocol:**
- Group creation and lifecycle
- Add/Update/Remove proposals
- Commit with UpdatePath (TreeKEM)
- Welcome messages — create and process (JoinFromWelcome)
- Key schedule per RFC 9420 §8
- Secret tree with per-sender ratchet (RFC 9420 §9)
- PrivateMessage encrypt/decrypt
- PublicMessage framing
- Extensions: ApplicationID, ExternalPub, RatchetTree, LastResort
- TLS presentation language encoder/decoder (RFC 9420 §3.5)

**Interoperability (CS2):**
- Key schedule vectors ✅
- Crypto basics vectors ✅
- TreeKEM vectors (11/11) ✅
- Secret tree vectors ✅
- Message protection vectors ✅
- Welcome vectors ✅
- Passive client commit vectors (13/13) ✅

---

## What doesn't work yet

Being honest:

- PSKs in the commit receiver path — proposals with PSK type are parsed but not resolved
- `NewGroupFromReInit` is incomplete (empty GroupContext for joiner_secret)
- Received `AuthenticatedContent` signatures not verified on commit/proposal messages
- Ratchet tree not truncated after member removals
- PublicMessage processing not implemented
- CS4–CS7 not planned (CS1/2/3 cover all practical use cases)

---

## Project structure

```
mls-go/
├── ciphersuite/     # AEAD, HPKE, HKDF, signatures — CS1/CS2/CS3
├── credentials/     # Basic credentials + key generation
├── extensions/      # Group extensions framework
├── framing/         # PublicMessage, PrivateMessage, MLSMessage
├── group/           # Group lifecycle, proposals, commits
├── keypackages/     # KeyPackage generation and validation
├── messages/        # Welcome, Commit, Proposal types
├── schedule/        # Key schedule (RFC 9420 §8)
├── secrettree/      # Secret tree for per-sender encryption
├── treesync/        # Ratchet tree, TreeKEM
├── interop/         # Interoperability helpers
└── internal/tls/    # TLS presentation language codec
```

---

## Testing

```bash
# All tests
go test ./...

# Race detector + coverage
go test -race -cover ./...

# Specific package
go test ./group/... -v

# Interop vectors
go test ./schedule/... -run TestKeyScheduleInteropVectors -v
go test ./group/... -run TestPassiveClientCommitVectors -v
```

## Interoperability

Interop is meant to run through Docker.

That is deliberate. Keeping the Go server, `mlspp`, and the test runner inside the same Docker setup avoids the usual local-machine problems: mismatched toolchains, missing packages, old binaries, and "it works here" surprises.

If you want interop results, use one of these:

```bash
# Self-interop: mls-go vs mls-go
./docker/run-interop.sh self

# Cross-interop: mls-go vs mlspp
./docker/run-interop.sh cross

# Both
./docker/run-interop.sh all
```

Handy variants:

```bash
# Run one config only
./docker/run-interop.sh cross external_proposals

# Run one suite only
SUITES=2 ./docker/run-interop.sh self

# Include deep_random in cross runs
RUN_STRESS=1 ./docker/run-interop.sh cross
```

More detail lives in `interop/README.md`.

---

## Roadmap

### v0.3.0

- [ ] PSK resolution in commit receiver path
- [ ] `NewGroupFromReInit` — complete implementation
- [ ] Verify received `AuthenticatedContent` signatures
- [ ] Ratchet tree truncation after removals
- [ ] PublicMessage processing

### v1.0.0

- [ ] Stable API
- [ ] Full RFC 9420 compliance
- [ ] Security audit
- [ ] Examples and documentation

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All code, comments, and docs must be in English.

---

## Support

- **Issues:** [GitHub Issues](https://github.com/thomas-vilte/mls-go/issues)
- **Email:** viltetomas2003@gmail.com

---

## License

MIT — see [LICENSE](LICENSE).

---

## Acknowledgments

- [RFC 9420](https://datatracker.ietf.org/doc/html/rfc9420) — MLS Protocol
- [RFC 9180](https://datatracker.ietf.org/doc/html/rfc9180) — HPKE
- [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) — HKDF
