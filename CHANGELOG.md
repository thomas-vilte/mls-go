# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

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
