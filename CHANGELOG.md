# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]


## [v1.3.0] - 2026-04-22

[v1.3.0]: https://github.com/thomas-vilte/mls-go/compare/v1.2.1...v1.3.0

In this release, we have significantly expanded the protocol's capabilities by adding full support for Cipher Suite 5 and implementing robust credential management policies. We also focused on refining the developer experience through a unified API and the adoption of the functional options pattern for core methods.

### 🛡️ Security & Protocol

- We added full support for Cipher Suite 5 to expand cryptographic compatibility and security options.
- We implemented proposal policies and custom credential handlers to give developers finer control over group membership and authentication.
- We introduced best-effort secret zeroing to enhance memory security by clearing sensitive data when no longer needed.
- We added credential management and policy enforcement to ensure stricter adherence to group security protocols.

### 🔧 Developer Experience

- We adopted the functional options pattern for core methods to provide a more flexible and idiomatic Go API.
- We standardized error handling with specific types to make error recovery more predictable and easier to debug.
- We unified the message sending API to streamline how applications interact with the group messaging lifecycle.
- We decoupled MLS client operations to improve modularity and reduce internal complexity.

### 🚀 Performance & Infrastructure

- We parallelized HPKE encryption to significantly improve performance during high-volume cryptographic operations.
- We introduced a reference implementation for a delivery service to provide a clear blueprint for protocol integration.
- We added new configuration options to control GroupInfo and Welcome extensions for better protocol customization.

### 🐛 Bug Fixes

- We fixed a bug where leaf encryption keys were not correctly preserved after a MergeCommit operation.
- We improved group stability by separating replay windows and deferring tree truncation until necessary.

### ⚠️ Breaking Changes

- Removed deprecated welcome options API.
- Unified message sending API and added new error types, which may require updates to existing call sites.
- Refactored core methods to use the functional options pattern, changing several method signatures.

In this release, we focused on performance, API ergonomics, and error handling. The headline change is parallel HPKE encryption during commit path construction, which significantly reduces commit latency in large groups.

### ⚡ Performance

- We parallelized HPKE encryption of path secrets in `createUpdatePath`, one goroutine per filtered copath level. Tree derivation and mutation remain sequential to preserve data-race safety. For large groups, this converts an O(log N) sequential chain of HPKE Seal operations into a parallel fan-out.
- We parameterized the benchmark suite with `members={2, 10, 50, 100, 500}` sub-benchmarks for `Commit`, `SendMessage`, `ReceiveMessage`, and `JoinFromWelcome`, making scaling curves comparable with `benchstat`.

### ✨ API

- We added `group.WithAAD(aad)` as a functional option on `Group.SendMessage`, and `mls.WithAAD(aad)` on `Client.SendMessage`. The standalone `SendMessageWithAAD` methods are deprecated but remain as shims for backward compatibility.

### 🔧 Error handling

- We added five new sentinel errors to `group/errors.go`: `ErrNoPendingCommit`, `ErrNotACommit`, `ErrMissingAuthenticatedContent`, `ErrUnknownProposalRef`, and `ErrOwnLeafNotFound`. Callers can now distinguish these failure modes with `errors.Is`.
- We replaced anonymous `fmt.Errorf` calls in `group/group.go` with existing sentinel errors (`ErrGroupNotOperational`, `ErrNilLeafNode`, `ErrNilSignaturePrivateKey`), improving observability for downstream applications.

## [v1.2.1] - 2026-04-12

[v1.2.1]: https://github.com/thomas-vilte/mls-go/compare/v1.2.0...v1.2.1

In this patch release, we focused on improving the stability of state restoration and commit management. We also enhanced the developer experience by cleaning up the codebase and standardizing documentation.

### 🛡️ Stability & Reliability

- We fixed an issue where the proposal by-reference index was not correctly rebuilt during state restoration.
- We resolved bugs affecting staged commit rollbacks and proposal references to ensure consistent state management.

### 🔧 Developer Experience

- We improved codebase maintainability by translating all comments to English and removing unnecessary boilerplate.

## [v1.2.0] - 2026-04-07

[v1.2.0]: https://github.com/thomas-vilte/mls-go/compare/v1.1.0...v1.2.0

In this release, we focused on achieving strict compliance with the RFC 9420 specification for Messaging Layer Security. We introduced a staged commit workflow and strengthened validation across the protocol to ensure higher security and interoperability.

### 🛡️ RFC 9420 Compliance & Security

- We implemented the staged commit workflow as defined in RFC 9420 §14 to improve session state management.
- We introduced strict validation and replay protection to enhance the security of the protocol implementation.
- We added comprehensive validation for Welcome messages and TLS variable-length integers to ensure protocol integrity.
- We enforced strict RFC 9420 compliance across the library to guarantee better interoperability.

### 🔧 Protocol Refinements

- We refined leaf node capabilities and validation logic for more robust group management.
- We aligned Pre-Shared Key (PSK) types and added usage validation to prevent configuration errors.
- We updated the joiner secret derivation process to maintain alignment with the latest security standards.

## [v1.1.0] - 2026-04-04

[v1.1.0]: https://github.com/thomas-vilte/mls-go/compare/v1.0.0...v1.1.0

In this release, we focused on aligning our implementation with the RFC 9420 standard and expanding group management capabilities. We have introduced more flexibility for external senders and streamlined the core MLS logic for better performance and compliance.

### ✨ New Features

- We added support for creating groups with raw external senders, providing more flexibility in group initialization.
- We introduced GroupInfo customization options to better align with the RFC 9420 specification.

### 🛠️ Protocol & Implementation

- We streamlined the MLS implementation to ensure full compliance with RFC 9420 standards.
- We improved code clarity regarding protocol generality to assist developers in understanding the core logic.

## [v1.0.0] - 2026-04-01

[v1.0.0]: https://github.com/thomas-vilte/mls-go/compare/v0.3.0...v1.0.0

We are proud to announce the v1.0.0 release of mls-go, marking its transition to a production-ready Messaging Layer Security implementation. This milestone introduces full RFC 9420 compliance, robust encrypted storage options, and advanced group management features to provide a secure and scalable foundation for group communications.

### 🔐 Security & Protocol Compliance

- We achieved full RFC 9420 compliance to ensure seamless cross-implementation compatibility.
- We added support for X.509 credentials to allow integration with standard public key infrastructure.
- We enhanced messaging security by implementing Authenticated Additional Data (AAD) and detailed sender information.
- We introduced robust state validation during deserialization to prevent the loading of corrupted or malicious group data.
- We improved message signature verification across different epochs to maintain security consistency.

### 👥 Group Management & Lifecycle

- We introduced external group join capabilities, enabling new members to join groups via public commits.
- We added support for multi-stage group proposals and the ability to cancel or revoke pending proposals.
- We implemented self-update functionality and refined member re-joining through enhanced external commits.
- We added a comprehensive event handler system to track and respond to group lifecycle changes in real-time.

### 💾 Storage & Persistence

- We introduced encrypted and file-based storage providers to secure sensitive group data at rest.
- We implemented secret tree state persistence to ensure session continuity across application restarts.
- We added group state caching to significantly reduce overhead when accessing frequently used group data.

### 🚀 Performance & Reliability

- We implemented lock striping to enable safe and efficient concurrent group operations.
- We added epoch history support to handle out-of-order decryption of messages from previous timeframes.
- We optimized performance through secret caching and refined path derivation logic.

### 🔧 Developer Experience

- We launched an MLS interoperability server and expanded test vector generation for multi-suite support.
- We introduced a Docker-first testing environment to simplify cross-platform verification and interop testing.
- We added a new client API with context support and flexible configuration options for improved developer ergonomics.

### ⚠️ Breaking Changes

- Refactored group and staged commit states into encapsulated types, requiring updates to code that previously accessed internal state directly.
- Consolidated extension and group context types, which may require updates to custom protocol implementations.
- Updated varint prefix decoding and proposal encoding to strictly align with RFC 9420, potentially breaking compatibility with non-compliant legacy data.


We are proud to announce the v1.0.0 release of mls-go, marking its transition to a production-ready Messaging Layer Security implementation. This milestone introduces full RFC 9420 compliance, robust encrypted storage options, and advanced group management features to provide a secure and scalable foundation for group communications.

## [v0.3.0] - 2026-03-13

[v0.3.0]: https://github.com/thomas-vilte/mls-go/compare/v0.2.0...v0.3.0

- Added multi-suite support for the currently targeted cipher suites.
- Expanded interoperability coverage for self-interop, `mlspp`, and the supported OpenMLS scenario subset.
- Improved RFC 9420 compliance around TreeKEM, Welcome handling, transcript hashing, and message framing.
- Added broader fuzzing, benchmarking, and property-style coverage across core packages.

## [v0.2.0] - 2026-03-09

[v0.2.0]: https://github.com/thomas-vilte/mls-go/compare/v0.1.0...v0.2.0

- Brought core key schedule, framing, and tree handling closer to RFC 9420.
- Added interoperability vectors and improved serialization and proposal processing.
- Expanded group lifecycle support, including reinit-related work and stricter validation.

## [v0.1.0] - 2026-03-09

[v0.1.0]: https://github.com/thomas-vilte/mls-go/compare/v0.0.0...v0.1.0

- First working public release of `mls-go`.
- Implemented the initial MLS group, messaging, HPKE, and extension foundations.
