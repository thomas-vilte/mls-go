# AGENTS.md — Coding Agent Guide for mls-go

This file provides guidance for AI coding agents (and human contributors) working in this repository.

## Project Overview

`github.com/openmls/go` is a pure Go implementation of the MLS (Message Layer Security) protocol
per [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420). It has **zero external dependencies**;
only the Go standard library is used. The `openmls/` directory is a Rust reference implementation
submodule — do not modify it.

```
module github.com/openmls/go
go 1.23.0
toolchain go1.24.5
```

Key packages:

| Package        | Purpose                                                     |
|----------------|-------------------------------------------------------------|
| `ciphersuite/` | AES-GCM, ECDSA, HPKE, HKDF, SHA-256 crypto primitives      |
| `credentials/` | MLS credentials (Basic, X509) — RFC 9420 §5.3               |
| `extensions/`  | Group extensions (ApplicationID, ExternalPub, RatchetTree)  |
| `framing/`     | PublicMessage, PrivateMessage, MLSMessage framing            |
| `group/`       | Group lifecycle (create, proposals, commits, members)        |
| `internal/tls` | TLS presentation language encoder/decoder (internal only)   |
| `key_packages/`| KeyPackage generation and validation — RFC 9420 §10         |
| `messages/`    | Welcome, Commit, Proposal, GroupInfo message types          |
| `schedule/`    | MLS Key Schedule — RFC 9420 §8                              |
| `secret_tree/` | Secret tree for per-sender encryption keys                  |
| `treesync/`    | Ratchet tree synchronization protocol                       |

---

## Build / Lint / Test Commands

```bash
# Build the entire project
go build ./...

# Run all tests
go test ./...

# Run all tests with verbose output and coverage
go test -cover -v ./...

# Run tests with race detector (always do this before submitting)
go test -race ./...

# Run a single test by name
go test ./ciphersuite/ -run TestHKDF_RFC5869_TestCase1 -v
go test ./group/ -run TestGroupCreation -v
go test ./framing/... -run TestFramedContent_ApplicationData_RoundTrip -v

# Run a subtest
go test ./framing/... -run TestFramedContent_ContentType/Application -v

# Run all tests in one package
go test ./group/ -v

# Format code (required before committing)
go fmt ./...

# Vet code
go vet ./...

# Run linter (if golangci-lint is available)
golangci-lint run

# Run fuzz tests
go test -fuzz=FuzzAEAD   -fuzztime=30s ./ciphersuite/
go test -fuzz=FuzzHKDF   -fuzztime=30s ./ciphersuite/
go test -fuzz=FuzzSecret -fuzztime=30s ./ciphersuite/

# Run benchmarks
go test -bench=. -benchmem ./ciphersuite/
go test -bench=BenchmarkHKDF_Extract -benchmem ./ciphersuite/
```

There is no Makefile. There are no CI workflows. All verification is done via standard `go` tooling.

---

## Code Style Guidelines

### General Rules

- **No external dependencies.** Do not add any. Use only `stdlib`.
- Code must pass `go fmt`, `go vet`, and `go build ./...` without errors.
- Always run `go test -race ./...` before submitting a change.
- Comments on exported symbols must be valid godoc (start with the symbol name).
- Cite the relevant RFC 9420 section in comments when implementing protocol logic (e.g., `// RFC 9420 §8.1`).

### Import Organization

Two groups, separated by a blank line: stdlib first, then internal project packages.
No third-party group exists (zero external deps).

```go
import (
    "crypto/ecdsa"
    "crypto/rand"
    "errors"
    "fmt"

    "github.com/openmls/go/credentials"
    "github.com/openmls/go/internal/tls"
)
```

Use import aliases only when necessary to avoid ambiguity:

```go
import (
    keypackages "github.com/openmls/go/key_packages"
)
```

### Naming Conventions

| Concept               | Convention                                           | Example                                   |
|-----------------------|------------------------------------------------------|-------------------------------------------|
| Exported types        | `PascalCase`                                         | `CipherSuite`, `GroupEpoch`, `KeyPackage` |
| Exported constants    | `PascalCase`                                         | `ContentTypeApplication`, `SenderTypeMember` |
| Unexported fields/fns | `camelCase`                                          | `initSecret`, `commitSecret`              |
| Constructors          | `New` prefix                                         | `NewGroup()`, `NewHKDF()`                 |
| Key generation        | `Generate` prefix                                    | `Generate()`, `GenerateCredentialWithKey()` |
| Unmarshal functions   | `Unmarshal` prefix                                   | `UnmarshalFramedContent()`, `UnmarshalKeyPackage()` |
| Accessors             | Descriptive suffix                                   | `AsSlice()`, `AsUint64()`                 |
| Sentinel errors       | `Err` prefix, package-namespaced message             | `ErrInvalidKeyLength`                     |

### Types

- Every protocol identifier gets a named integer type, never a bare `int`:
  ```go
  type ContentType uint8
  type CipherSuite uint16
  type GroupEpoch  uint64
  ```
- Implement `String()` on all enum-like types for readable output.
- Use `[]byte` for all opaque binary data (keys, group IDs, signatures, credentials).
- Use struct pointers for mutable state (`*Group`, `*KeySchedule`, `*Secret`).
- Use interfaces for polymorphic protocol content (e.g., `FramedContentBody` with
  `ApplicationData`, `ProposalBody`, `CommitBody` implementations).

### Error Handling

Three patterns, used in combination:

**1. Sentinel errors** — declare at package level for caller comparison:
```go
var (
    ErrAeadDecryption    = errors.New("ciphersuite: AEAD decryption failed")
    ErrInvalidKeyLength  = errors.New("ciphersuite: invalid key length")
    ErrInvalidSignature  = errors.New("ciphersuite: invalid signature")
)
```

**2. Contextual wrapping** — for call-chain context with `%w`:
```go
return nil, fmt.Errorf("computing joiner secret: %w", err)
return nil, fmt.Errorf("signing LeafNode: %w", err)
```

**3. Early returns** — standard Go idiom; never use `panic` for protocol errors:
```go
secret, err := ks.initSecret.HKDFExtract(commitSecret)
if err != nil {
    return nil, fmt.Errorf("HKDF extract failed: %w", err)
}
```

Do not swallow errors. Do not use `panic` for recoverable conditions.
Error messages follow the pattern `"packagename: description of what failed"`.

---

## Testing Guidelines

### Test Package Convention

- **White-box (internal) tests** — same package name, for testing unexported internals:
  ```go
  package ciphersuite   // file: ciphersuite_test.go
  package group         // file: group_test.go
  ```
- **Black-box (external) tests** — `_test` suffix, for testing the public API:
  ```go
  package framing_test       // file: framing_test.go
  package extensions_test    // file: extensions_integration_test.go
  ```

### Test Naming

```
Test<Type>_<Method>                      → TestCipherSuite_IsSupported
Test<Type>_<Method>_<Case>              → TestFramedContent_ApplicationData_RoundTrip
Test<Function>_RFC<N>_TestCase<N>       → TestHKDF_RFC5869_TestCase1
TestGroup<Action>                        → TestGroupCreation, TestGroupAddMember
Fuzz<Target>                            → FuzzAEAD, FuzzHKDF
Benchmark<Type>_<Method>                → BenchmarkHKDF_Extract
```

### Test Patterns

**Table-driven tests** for multi-case scenarios:
```go
tests := []struct {
    name string
    body framing.FramedContentBody
    want framing.ContentType
}{
    {"Application", framing.ApplicationData{Data: []byte{}}, framing.ContentTypeApplication},
}
for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) { ... })
}
```

**RFC test vectors** for crypto correctness using `encoding/hex`:
```go
func TestHKDF_RFC5869_TestCase1(t *testing.T) {
    ikm, _ := hex.DecodeString("0b0b0b0b...")
    // ...
}
```

**Roundtrip serialization tests** for all marshal/unmarshal implementations:
```go
data := fc.Marshal()
fc2, err := framing.UnmarshalFramedContent(data)
// verify all fields equal
```

**Security/negative tests** for invalid inputs, wrong keys, and tampered data:
```go
func TestAEAD_WrongKey(t *testing.T) { ... }
func TestAEAD_TamperedData(t *testing.T) { ... }
```

**Nil-safety tests** for any type with pointer receivers:
```go
func TestSecret_NilSafety(t *testing.T) {
    var nilSecret *Secret
    if nilSecret.AsSlice() != nil { t.Error(...) }
}
```

### Assertions

- Use `t.Fatalf` when the test cannot continue (nil pointer would panic, setup fails).
- Use `t.Errorf` for field-level assertion failures where the test can continue checking.
- Prefer specific failure messages: `t.Errorf("AsSlice() = %v, want %v", got, want)`.

---

## Protocol Implementation Notes

- All wire format encoding/decoding goes through `internal/tls` — the TLS presentation
  language encoder from RFC 8446 §3. Do not implement custom serialization elsewhere.
- When implementing a new message type, provide both `Marshal()` and `Unmarshal<Type>()`
  functions and a corresponding roundtrip test.
- Keep each package focused on a single RFC 9420 section or concept.
- The `internal/tls` package is not part of the public API — do not reference it from
  outside this module.
