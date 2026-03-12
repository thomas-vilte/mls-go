// Package keypackages implements MLS KeyPackages per RFC 9420 §10.
//
// KeyPackages are the primary mechanism for adding members to MLS groups.
// They contain a member's public keys (HPKE and signature), identity
// credentials, and capabilities.
//
// # KeyPackage Structure (RFC 9420 §10.1)
//
// ```text
// ┌────────────────────────────────────────────────────────────┐
// │                 KeyPackage (RFC 9420 §10.1)                │
// ├────────────────────────────────────────────────────────────┤
// │  version         : ProtocolVersion (uint16)                │
// │  cipher_suite    : CipherSuite (uint16)                    │
// │  init_key        : HPKEPublicKey (opaque<V>)               │
// │  leaf_node       : LeafNode (see below)                    │
// │  extensions      : Extension[] (opaque<V>)                 │
// │  signature       : opaque<V>                               │
// └────────────────────────────────────────────────────────────┘
// ```
//
// The KeyPackage is signed by the member's signature key, allowing
// other group members to verify its authenticity.
//
// # LeafNode Structure (RFC 9420 §7.2)
//
// ```text
// ┌────────────────────────────────────────────────────────────┐
// │                 LeafNode (RFC 9420 §7.2)                   │
// ├────────────────────────────────────────────────────────────┤
// │  encryption_key  : HPKEPublicKey (opaque<V>)               │
// │  signature_key   : SignaturePublicKey (opaque<V>)          │
// │  credential      : Credential (see credentials package)    │
// │  capabilities    : Capabilities (see below)                │
// │  leaf_node_source: uint8                                   │
// │  ├─ 0x01: key_package (includes Lifetime)                  │
// │  ├─ 0x02: update (no extra data)                           │
// │  └─ 0x03: commit (includes parent_hash)                    │
// │  [conditional data based on source]                        │
// │  extensions      : Extension[] (opaque<V>)                 │
// │  signature       : opaque<V>                               │
// └────────────────────────────────────────────────────────────┘
// ```
//
// # Capabilities Structure (RFC 9420 §7.2)
//
// ```text
// ┌────────────────────────────────────────────────────────────┐
// │              Capabilities (RFC 9420 §7.2)                  │
// ├────────────────────────────────────────────────────────────┤
// │  protocol_versions : ProtocolVersion[] (uint16<V>)         │
// │  cipher_suites     : CipherSuite[] (uint16<V>)             │
// │  extensions        : ExtensionType[] (uint16<V>)           │
// │  proposals         : ProposalType[] (uint16<V>)            │
// │  credentials       : CredentialType[] (uint16<V>)          │
// └────────────────────────────────────────────────────────────┘
// ```
//
// Capabilities advertise what a client supports, allowing groups to
// negotiate common parameters.
//
// # Supported Cipher Suites
//
// | ID | Name | KEM | AEAD | Hash | Signature |
// |----|------|-----|-----|------|-----------|
// | 0x0001 | MLS128DHKEMX25519 | X25519 | AES-128-GCM | SHA-256 | Ed25519 |
// | 0x0002 | MLS128DHKEMP256 | P-256 | AES-128-GCM | SHA-256 | ECDSA-P256 |
// | 0x0003 | MLS256DHKEMX25519ChaCha20 | X25519 | ChaCha20Poly1305 | SHA-256 | Ed25519 |
//
// # Usage
//
// Create a KeyPackage:
//
//	credWithKey, _, err := credentials.GenerateCredentialWithKeyForCS(
//	    []byte("alice"),
//	    ciphersuite.MLS128DHKEMP256,
//	)
//	if err != nil {
//	    return err
//	}
//
//	kp, privKeys, err := keypackages.Generate(credWithKey, keypackages.MLS128DHKEMP256)
//	if err != nil {
//	    return err
//	}
//
//	// Store privKeys securely - needed for group operations
//	// Share kp publicly - others use this to add you to groups
//
// Validate a KeyPackage:
//
//	if err := kp.Validate(); err != nil {
//	    return err // Invalid KeyPackage
//	}
//
//	// Verify signature cryptographically
//	cs := ciphersuite.CipherSuite(kp.CipherSuite)
//	if err := kp.Verify(cs); err != nil {
//	    return err // Invalid signature
//	}
//
// Unmarshal from wire format:
//
//	kp, err := keypackages.UnmarshalKeyPackage(wireData)
//	if err != nil {
//	    return err
//	}
//
// # Security Considerations
//
// **Private Key Protection:** KeyPackagePrivateKeys contains all private
// keys for a KeyPackage. These MUST be stored securely and never transmitted.
//
// **Lifetime Validation:** KeyPackages include a validity period. Clients
// MUST reject expired KeyPackages to prevent replay attacks.
//
// **Signature Verification:** Always verify KeyPackage signatures before
// use. The signature covers the entire KeyPackage including the LeafNode.
//
// **Unique Init Keys:** Each KeyPackage should have a unique HPKE init_key.
// Reusing keys across KeyPackages compromises forward secrecy.
//
// # RFC Compliance
//
//   - RFC 9420 §10: KeyPackages
//   - RFC 9420 §10.1: KeyPackage Structure
//   - RFC 9420 §7.2: LeafNode
//   - RFC 9420 §7.3: Capabilities
//   - RFC 9420 §5.1: Cipher Suites
//
// # Implementation Notes
//
// **Signing:** KeyPackages are signed using SignWithLabel per RFC 9420 §7.2.
// The label is "KeyPackageTBS" for the KeyPackage and "LeafNodeTBS" for
// the LeafNode.
//
// **Hash Reference:** KeyPackages are identified by their hash reference
// (SHA-256 of the serialized KeyPackage) in Welcome messages.
//
// **Extension Handling:** Unknown extensions are accepted during parsing
// but not validated. Known extensions are validated according to their
// specifications.
package keypackages
