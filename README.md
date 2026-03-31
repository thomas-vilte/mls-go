# mls-go

[![Go Reference](https://pkg.go.dev/badge/github.com/thomas-vilte/mls-go.svg)](https://pkg.go.dev/github.com/thomas-vilte/mls-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/thomas-vilte/mls-go)](https://goreportcard.com/report/github.com/thomas-vilte/mls-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Pure Go implementation of Messaging Layer Security (MLS) per [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420).

**Current status:** beta, `v0.3.0`.

The implementation covers the main MLS group flow, the currently targeted cipher suites, and Docker-based interoperability with `mls-go`, `mlspp`, and the subset of OpenMLS scenarios that upstream currently supports.

## Overview

This repository is a native Go MLS implementation with no CGO dependency. The main packages are:

- `ciphersuite`: AEAD, HPKE, HKDF, signatures, hash references
- `credentials`: MLS credentials
- `extensions`: extension types and helpers
- `framing`: MLSMessage, PublicMessage, PrivateMessage
- `group`: group lifecycle, commits, proposals, Welcome handling
- `keypackages`: KeyPackage generation and validation
- `schedule`: key schedule and exporter support
- `secrettree`: per-sender secret tree ratchets
- `treesync`: ratchet tree and TreeKEM helpers
- `interop`: interop helpers and Docker test infrastructure

## What Works

- Group creation
- Add / Update / Remove proposals
- Commit generation and processing
- Welcome creation and join-from-Welcome flows
- PrivateMessage protection for application data
- PublicMessage handling for proposal and commit flows used by the current group implementation
- Secret tree and key schedule support per RFC 9420 sections 8 and 9
- Cipher suites:
  - `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
  - `MLS_128_DHKEMP256_AES128GCM_SHA256_P256`
  - `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`

## Known Gaps

The project is not `v1.0.0` yet. Known gaps and caveats are tracked in `SECURITY.md` and in the remaining roadmap work. In particular:

- the public API is still settling
- some protocol paths need more review before calling the library stable
- documentation and example coverage still lag behind the implementation in a few places

## Quick Start

The recommended entry point is the root `mls.Client` API.

```go
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

bobKP, err := bob.FreshKeyPackageBytes(ctx)
if err != nil {
	log.Fatal(err)
}
groupID, err := alice.CreateGroup(ctx)
if err != nil {
	log.Fatal(err)
}
_, welcome, err := alice.InviteMember(ctx, groupID, bobKP)
if err != nil {
	log.Fatal(err)
}
if _, err := bob.JoinGroup(ctx, welcome); err != nil {
	log.Fatal(err)
}
```

Useful starting points:

- `examples/basic_chat_v2/main.go`
- `examples/basic_chat/main.go`
- `client_test.go`
- `group/integration_test.go`

Higher-level `Client` flows now include:

- invite + join by Welcome
- batched proposal-before-commit flows
- sender identity on received messages
- AAD support
- external join via `ExternalJoin`
- pluggable storage via `WithStorage`

## Build And Test

```bash
go build ./...
go test ./...
go test -race ./...
go vet ./...
```

## Interoperability

Interop is Docker-first on purpose. The repository ships a Compose setup that keeps the Go server, cross-interop targets, and test runner in a consistent environment.

Rebuild the `mls-go` image after local code changes:

```bash
docker compose -f docker/docker-compose.yml build mls-go
```

Then run interop per suite to avoid long tool timeouts:

```bash
SUITES="1" ./docker/run-interop.sh self
SUITES="2" ./docker/run-interop.sh self
SUITES="3" ./docker/run-interop.sh self
```

Cross-interop examples:

```bash
./docker/run-interop.sh cross
CROSS_TARGET=openmls ./docker/run-interop.sh cross
```

Current practical status:

- `mls-go` self-interop passes the supported scenario matrix on suites `1`, `2`, and `3`
- `mlspp` cross-interop passes the supported scenario matrix on suites `1`, `2`, and `3`
- `OpenMLS` cross-interop passes the subset that upstream currently implements here: `welcome_join`, `application`, `external_join`, and `deep_random`

The unsupported OpenMLS scenarios are upstream limitations in the reference interop client, not hidden failures on the Go side.

## Roadmap

Before `v1.0.0`, the remaining work is mainly:

- API cleanup and stabilization
- documentation polish and maintained examples
- broader test, fuzz, and benchmark coverage
- closing the remaining documented protocol and security gaps

See also:

- `SECURITY.md` for deployment caveats and storage guidance
- `INTEGRATION.md` for application integration patterns

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All code, comments, errors, tests, and docs must be in English.

## License

MIT. See [LICENSE](LICENSE).
