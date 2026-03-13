# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]


## [v0.3.0] - 2026-03-13

[v0.3.0]: https://github.com/thomas-vilte/mls-go/compare/v0.2.0...v0.3.0

We have achieved significant alignment with the RFC 9420 standard, introducing comprehensive validation rules and multi-suite cryptographic support. This update also strengthens the library's reliability through advanced testing methodologies and refined error handling.

### 🛡️ RFC 9420 Compliance & Security

- Enforced strict psk_nonce requirements and sender/content-type rules as per RFC 9420.
- Implemented distinct HPKE keys and LeafNode TBS context to ensure protocol integrity.
- Enhanced proposal and capability validation to strictly follow RFC compliance standards.
- Added EpochAuthenticator and improved signature verification for group messages.

### 🔐 Cryptographic Enhancements

- Added support for multiple ciphersuites, including Ed25519 and ChaCha20Poly1305.
- Integrated native Go crypto/hpke for Ciphersuite 1 and 3 implementations.
- Standardized ECDSA signature and public key encoding to match RFC specifications.
- Transitioned to ciphersuite-agnostic hash references across all cryptographic modules.

### ⚙️ Group & State Management

- Implemented resumption PSKs and logic for handling unmerged leaves in the group state.
- Refined commit processing and update path logic to align with the latest protocol requirements.
- Improved secret hygiene and secret tree management for better security and performance.

### 🛠️ Developer Experience & Testing

- Introduced property-based testing for framing and tree synchronization to catch edge cases.
- Added fuzzing and benchmarking workflows to ensure long-term stability and performance.
- Enhanced API documentation and added context support for better integration flexibility.
- Adopted typed errors to provide more semantic and actionable error handling for developers.

### 🩹 Bug Fixes & Stability

- Fixed TreeKEM interoperability issues by correctly accumulating path secrets during tests.
- Adjusted Welcome message processing to ensure compatibility across different ciphersuites.
- Improved the robustness of external sender unmarshalling and extension parsing.

### ⚠️ Breaking Changes

- Refactored core operations to be ciphersuite-agnostic, which may require updates to custom implementations.
- Introduced typed errors for more granular error handling, replacing some generic error returns.
- Updated signature validation and public key encoding to strictly follow RFC 9420, which may affect interoperability with non-compliant implementations.

## [v0.2.0] - 2026-03-09

[v0.2.0]: https://github.com/thomas-vilte/mls-go/compare/v0.1.0...v0.2.0

In this version, we focused on achieving full compliance with the RFC 9420 (Messaging Layer Security) standard. We implemented critical tree operations, improved interoperability with official proof vectors, and refined key management to ensure robust security in group communications.

### 🔐 RFC 9420 Protocol and Standards

- We aligned the DHKEM, KeySchedule, and PSK components with the RFC 9180 and RFC 9420 standards to ensure full compatibility.

- We integrated dynamic hash functions that depend on the selected cipher suite for greater cryptographic flexibility.

- We implemented signature tagging and proposal filtering, strictly adhering to the protocol specifications.

### 🌳 Tree Operations and Security

- We added full support for tree operations, including node hashing and efficient member management.

- We implemented secret tree ratchets to strengthen key derivation within the group.

- We improved tree synchronization and data validation to maintain the integrity of the hierarchical structure.

### 📦 Messaging and Serialization

- We enabled the processing and verification of public messages, ensuring the authenticity of communication.

- We refactored the unmarshaling system for extensions and credentials, optimizing data reading from various sources.

- We unified the handling of membership tags in the framing to simplify the message structure.

### 🔄 Group Management

- We added the ability to reinitialize groups using a ReInitProposal, simplifying the updating of group parameters.

- We improved the management of LeafNode and KeyPackage to align them with the field order required by the standard.

### 🧪 Interoperability and Stability

- We incorporated an extensive suite of interoperability tests and test vectors to validate compatibility with implementations such as other implementations.

- We fixed critical errors in private key derivation and data serialization.

- We ensured the generation of valid private keys during the derivation process.

## [v0.1.0] - 2026-03-09

[v0.1.0]: https://github.com/thomas-vilte/mls-go/compare/v0.0.0...v0.1.0

We are releasing the first working version of mls-go, establishing the foundation of the Messaging Layer Security (RFC 9420) protocol. In this release, we focus on providing a robust architecture for group management, secure messaging, and strict compliance with international cryptographic standards.

### 🚀 Core Protocol and Messaging

- We implemented the complete MLS message flow, including the Welcome and Commit protocols.

- We added a robust messaging system with support for framing application data and core components.

- We introduced comprehensive integration tests to validate end-to-end messaging functionality.

### 👥 Group and Membership Management

- We introduced advanced components for group management and tracking member proposals.

- We improved member updates and ratchet tree management to ensure accurate synchronization between participants.

- We added support for proposal referencing and dynamic updates to the status tree.

### 🔒 Security and Cryptography

- We incorporated support for HPKE key encapsulation and robust validation using X.509 certificates and GREASE mechanisms.

- We refactored the combination of pre-shared keys (PSK) and the use of HKDF to align with modern security standards.

- We added extension comparison and validation capabilities to strengthen protocol integrity.

### 📜 Standards and Compatibility

- We aligned the key schedule with the final RFC 9420 specification.
- We implemented full support for critical extensions such as RatchetTree, LastResort, and Application ID.

- We improved the processing of welcome messages to ensure strict compliance with the MLS standard.

### 🛠️ Fixes and Stability

- We fixed errors in credential serialization and improved access to application data within the framing.

- We resolved an issue in proposal application that affected the integrity of sender leaves in the tree.

- We optimized group initialization and welcome message processing to avoid inconsistent states.

### ⚠️ Breaking Changes

- We renamed several internal packages and updated message serialization to improve the project structure.

- We adopted an interleaved tree representation that modifies how group nodes are managed.

We introduced the first functional version of mls-go, establishing the foundation of the Messaging Layer Security (RFC 9420) protocol. In this release, we focused on providing a robust architecture for group management, secure messaging, and strict compliance with international cryptographic standards.

### 🚀 Core Protocol and Messaging

- We implemented the complete MLS message flow, including the Welcome and Commit protocols.

- We added a robust messaging system with support for framing application data and core components.

- We introduced comprehensive integration testing to validate end-to-end messaging functionality.

### 👥 Group Management and Membership

- We introduced advanced components for group management and tracking member proposals.

- We improved member updates and ratchet tree management to ensure accurate synchronization between participants.

- We added support for proposal referencing and dynamic updates to the state tree.

### 🔒 Security and Cryptography

- We incorporated support for HPKE key encapsulation and robust validation using X.509 certificates and GREASE mechanisms.

- We refactored the combination of pre-shared keys (PSK) and the use of HKDF to align with modern security standards.

- We added extension comparison and validation capabilities to strengthen protocol integrity.

### 📜 Standards and Compatibility

- We aligned the key schedule with the final RFC 9420 specification.

- We implemented full support for critical extensions such as RatchetTree, LastResort, and Application ID.

- We improved welcome message processing to ensure strict compliance with the MLS standard.

### 🛠️ Fixes and Stability

- We fixed errors in credential serialization and improved access to application data within the framing.

- We resolved an issue in proposal application that affected the integrity of the sender's leaves in the tree.

- We optimized group initialization and Welcome message processing to avoid inconsistent states.

### ⚠️ Breaking Changes

- We renamed several packages.

