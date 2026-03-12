# mls-go

[![Go Reference](https://pkg.go.dev/badge/github.com/thomas-vilte/mls-go.svg)](https://pkg.go.dev/github.com/thomas-vilte/mls-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/thomas-vilte/mls-go)](https://goreportcard.com/report/github.com/thomas-vilte/mls-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Pure Go implementation of Messaging Layer Security (MLS) per RFC 9420.

**122 Go files | 13 packages | 3 cipher suites | 0 CGO dependencies**

---

## What is this?

mls-go brings MLS (Messaging Layer Security) to Go without CGO or external dependencies.

MLS is the industry standard for end-to-end encrypted group messaging. Used by Matrix, Signal, Cisco Webex. It solves the hardest problem in group E2EE: managing keys as members join/leave, without trusting the server.

**Current status:** Beta (v0.2.0). Actively developed. API may change until v1.0.0.

---

## Why this exists

I needed MLS for a Go project. Looked around - no native implementation. Only option was CGO bindings to Rust (openmls/openmls). That means: Rust toolchain, cross-compilation headaches, larger attack surface.

So I started building mls-go. Not perfect, not complete. But it's pure Go. And it works.

If you need MLS in Go without CGO, maybe this helps.

---

## What works (v0.2.0)

**Cipher suites:**
- CS1: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001) ✅
- CS2: MLS_128_DHKEMP256_AES128GCM_SHA256_P256 (0x0002) ✅
- CS3: MLS_256_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 (0x0003) ✅

**Crypto:**
- AEAD: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- Signatures: ECDSA (P-256), Ed25519
- HPKE: DHKEM (P-256, X25519) per RFC 9180
- HKDF: Per RFC 5869
- Hash: SHA-256, SHA-384, SHA-512

**Protocol:**
- Group creation and lifecycle
- Add/Update/Remove proposals
- Welcome messages (create and process)
- Key schedule (RFC 9420 §8)
- Secret tree with per-sender encryption
- Message framing (PublicMessage, PrivateMessage)
- Encryption/decryption
- Extensions (ApplicationID, ExternalPub, RatchetTree, LastResort)
- TLS presentation language encoder/decoder

**Testing:**
- All tests passing
- Race detector clean
- Interoperability with OpenMLS Rust (partial)
- RFC test vectors for crypto

---

## What doesn't work yet

Being honest here:

- Commit/Proposal lifecycle incomplete (UpdatePath needs work)
- TreeKEM operations partial
- External senders not implemented
- Cipher suites CS4-CS7 not done
- Full RFC 9420 compliance - still working on it

If you need production-ready today, use [OpenMLS](https://github.com/openmls/openmls) with CGO bindings. They're mature. We're not.

But if you can wait and want pure Go, stick around.

---

## Comparison

| | mls-go | OpenMLS + CGO |
|---|--------|---------------|
| **Language** | Pure Go | Rust (CGO from Go) |
| **Build** | `go build` | Need Rust toolchain |
| **Cross-compile** | Easy | Complex |
| **Binary** | Single static | Dynamic + Rust runtime |
| **Attack surface** | Minimal | CGO + Rust stdlib |
| **Status** | Beta v0.2.0 | Production |
| **Community** | 1 maintainer | Active community |
| **Maturity** | Learning in public | Years of development |

**Trade-off:** They're production. We're beta. But if you need pure Go, there's no other option.

---

## Project structure

```
mls-go/
├── ciphersuite/     # Crypto: AEAD, HPKE, HKDF, signatures (80%+ coverage)
├── credentials/     # Basic, X509 credentials (75%+ coverage)
├── extensions/      # Group extensions framework
├── framing/         # PublicMessage, PrivateMessage, MLSMessage (70%+ coverage)
├── group/           # Group lifecycle, proposals, commits (60%+ coverage)
├── keypackages/     # KeyPackage generation/validation (75%+ coverage)
├── messages/        # Welcome, Commit, Proposal types
├── schedule/        # Key schedule implementation (80%+ coverage)
├── secrettree/      # Secret tree for encryption keys (70%+ coverage)
├── treesync/        # Tree synchronization
├── interop/         # Interoperability tests with OpenMLS Rust
└── internal/tls/    # TLS presentation language encoder/decoder
```

13 packages, 122 Go files, ~8000 lines of code.

---

## Use cases

### Matrix Go clients

Dendrite, Gomuks, and other Matrix clients in Go can use MLS without CGO. No Rust toolchain needed.

### Enterprise messaging

Build secure communication platforms with real E2EE. MLS handles forward secrecy, post-compromise security, member changes.

### IoT

Resource-constrained devices need group encryption. Pure Go means smaller binaries, easier deployment.

### Custom protocols

Building something new? MLS is a solid foundation. mls-go is generic - not tied to any specific protocol.

---

## Technical details

### Cipher suite architecture

Each cipher suite bundles:
- KEM (Key Encapsulation Method)
- KDF (Key Derivation Function)
- AEAD (Authenticated Encryption)
- Hash function
- Signature scheme

```
CS1 (0x0001): X25519 → AES-128-GCM → SHA-256 → Ed25519
CS2 (0x0002): P-256  → AES-128-GCM → SHA-256 → ECDSA
CS3 (0x0003): X25519 → ChaCha20    → SHA-256 → Ed25519
```

See `ciphersuite/ciphersuite.go` for implementation.

### Key schedule (RFC 9420 §8)

```
init_secret → [commit_secret] → epoch_secret
                          ↓
              sender_data_secret, encryption_secret, ...
```

Each epoch derives fresh keys. Forward secrecy from ratcheting.

### Secret tree (RFC 9420 §8.6)

```
        [root_secret]
             |
    +--------+--------+
    |                 |
[parent_secret]   [parent_secret]
    |                 |
[leaf_secret]     [leaf_secret]
```

Each sender encrypts using their leaf secret. Recipients derive from their tree position.

---

## Testing

```bash
# All tests
go test ./...

# Race detector + coverage
go test -race -cover ./...

# Specific packages
go test ./ciphersuite/... -v
go test ./group/... -v
go test ./interop/... -v
```

### Coverage

| Package | Coverage | Notes |
|---------|----------|-------|
| ciphersuite | 80%+ | RFC test vectors, fuzzing |
| schedule | 80%+ | Key derivation |
| credentials | 75%+ | Basic, X509 |
| keypackages | 75%+ | Generation, validation |
| framing | 70%+ | Message roundtrip |
| secrettree | 70%+ | Tree operations |
| group | 60%+ | Lifecycle, interop |

---

## Roadmap

### Q2 2026 - v0.3.0

- [ ] Complete TreeKEM
- [ ] Full Commit/Proposal lifecycle
- [ ] External senders
- [ ] All 3 cipher suites in interop

### Q3 2026 - v0.4.0

- [ ] Production-ready API
- [ ] RFC 9420 compliance
- [ ] Better documentation

### Q4 2026 - v1.0.0

- [ ] Stable API
- [ ] Security audit
- [ ] Production deployments

This is the plan. Might change. Building this while learning MLS myself - things take time.

---

## Why this matters

Go ecosystem has no native MLS. Projects wanting MLS must use CGO to Rust or Python. That adds complexity: toolchain issues, build problems, larger attack surface.

mls-go solves this. Not perfect, not complete. But pure Go.

**Enables:**
- Matrix Go clients without Rust
- Enterprise messaging in pure Go
- IoT devices with group E2EE
- Custom protocols on solid foundation

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

**Important:** All code, comments, documentation must be in English. International library.

Areas I need help:
- TreeKEM implementation
- Additional cipher suites
- External senders
- Documentation and examples

If you know MLS or crypto, contributions welcome. I'm learning as I go.

---

## Support

- **Issues:** [GitHub Issues](https://github.com/thomas-vilte/mls-go/issues)
- **Email:** viltetomas2003@gmail.com
- **Documentation:** [pkg.go.dev](https://pkg.go.dev/github.com/thomas-vilte/mls-go) (pending indexing)

I'm one maintainer. Response might take time. But I'll get back to you.

---

## License

MIT License - see [LICENSE](LICENSE).

---

## Acknowledgments

- [OpenMLS](https://github.com/openmls/openmls) - Rust implementation I'm learning from
- [RFC 9420](https://datatracker.ietf.org/doc/html/rfc9420) - MLS Protocol
- [RFC 9180](https://datatracker.ietf.org/doc/html/rfc9180) - HPKE
- [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) - HKDF

---

**Built for the Go ecosystem.**

No CGO. No Rust. Just Go.

*Work in progress. Contributions welcome.*
