# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

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

- Refactored the `group.Group` and `group.StagedCommit` APIs to encapsulate internal state.
- Consolidated shared MLS `Extension` and `GroupContext` types across packages.
- Improved API ergonomics with typed optional parameters, safer lookups, and additive extension points.
- Added `CreateWelcomeWithOptions`, `ValidateLeafNodeLifetimeAt`, and public integration interfaces for storage and validation.
- Strengthened group message verification across epochs and historical context handling.

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
