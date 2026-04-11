// Package messages implements MLS message types according to RFC 9420.
//
// # Overview
//
// This package provides the core message types used in the MLS protocol for
// group creation, member management, and state synchronization. It implements
// the message structures defined in RFC 9420 for Welcome messages, GroupInfo,
// and GroupContext.
//
// # Message Types
//
// Welcome Messages (§12.4.3.1) - For adding new members to a group:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                    Welcome Structure                            │
//	├─────────────────────────────────────────────────────────────────┤
//	│  cipher_suite (uint16)        - Cipher suite for the group      │
//	│  secrets<V>                   - Encrypted secrets per member    │
//	│    ├─ key_package_hash<V>     - Hash of member's KeyPackage     │
//	│    ├─ kem_output<V>           - HPKE encapsulated key           │
//	│    └─ ciphertext<V>           - Encrypted group secrets         │
//	│  encrypted_group_info<V>      - Encrypted GroupInfo object      │
//	└─────────────────────────────────────────────────────────────────┘
//
// GroupInfo (§12.4.3) - Public information about a group's state:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                    GroupInfo Structure                          │
//	├─────────────────────────────────────────────────────────────────┤
//	│  group_context                - Current group state             │
//	│  extensions<V>                - Optional extensions             │
//	│  confirmation_tag             - MAC for epoch confirmation      │
//	│  signer (uint32)              - Leaf index of signer            │
//	│  signature<V>                 - Signature over GroupInfo        │
//	└─────────────────────────────────────────────────────────────────┘
//
// GroupContext (§8.1) - Summary of shared group state:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                   GroupContext Structure                        │
//	├─────────────────────────────────────────────────────────────────┤
//	│  protocol_version (uint16)    - MLS protocol version            │
//	│  cipher_suite (uint16)        - Cipher suite in use             │
//	│  group_id<V>                  - Unique group identifier         │
//	│  epoch (uint64)               - Current epoch number            │
//	│  tree_hash<V>                 - Hash of ratchet tree            │
//	│  confirmed_transcript_hash<V> - Hash of transcript              │
//	│  extensions<V>                - Group extensions                │
//	└─────────────────────────────────────────────────────────────────┘
//
// # Wire Format
//
// All messages use the TLS presentation language (RFC 8446 §3) for encoding.
// Variable-length vectors use the MLS variable-size integer encoding (RFC 9420 §2.1.2):
//
//	┌────────┬────────┬───────────────┬──────────┬───────────┐
//	│ Prefix │ Length │ Usable Bits   │ Min      │ Max       │
//	├────────┼────────┼───────────────┼──────────┼───────────┤
//	│ 00     │ 1      │ 6             │ 0        │ 63        │
//	│ 01     │ 2      │ 14            │ 64       │ 16383     │
//	│ 10     │ 4      │ 30            │ 16384    │ 1073741823│
//	│ 11     │ invalid│ -             │ -        │ -         │
//	└────────┴────────┴───────────────┴──────────┴───────────┘
//
// Example encoding:
//
//	// Variable-length integer encoding
//	0x25       → 37 (single byte)
//	0x7bbd     → 15293 (two bytes)
//	0x9d7f3e7d → 494878333 (four bytes)
//
// # Welcome Message Flow
//
// When adding a new member to a group:
//
//	┌─────────────┐                          ┌─────────────┐
//	│  Existing   │                          │    New      │
//	│   Member    │                          │   Member    │
//	└──────┬──────┘                          └──────┬──────┘
//	       │                                        │
//	       │  1. Fetch KeyPackage from DS           │
//	       │───────────────────────────────────────►│
//	       │                                        │
//	       │  2. Create Welcome with                │
//	       │     EncryptedGroupSecrets              │
//	       │                                        │
//	       │  3. Send Welcome message               │
//	       │───────────────────────────────────────►│
//	       │                                        │
//	       │                                        │ 4. Decrypt secrets
//	       │                                        │    using HPKE
//	       │                                        │ 5. Initialize state
//	       │                                        │    from GroupInfo
//
// # GroupInfo Encryption
//
// The GroupInfo is encrypted using AES-128-GCM with keys derived from the
// welcome_secret (RFC 9420 §12.4.3.1):
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│              GroupInfo Encryption Flow                          │
//	├─────────────────────────────────────────────────────────────────┤
//	│  welcome_secret                                                   │
//	│      │                                                          │
//	│      ├─ HKDF-Expand-Label("welcome")                            │
//	│      │   └─► welcome_key (16 bytes for AES-128)                 │
//	│      │                                                          │
//	│      └─ HKDF-Expand-Label("nonce")                              │
//	│          └─► welcome_nonce (12 bytes for GCM)                   │
//	│                                                                 │
//	│  ciphertext = AES-GCM-Seal(welcome_key, welcome_nonce,          │
//	│                            GroupInfo.Marshal(), aad=[])         │
//	└─────────────────────────────────────────────────────────────────┘
//
// # Confirmation Tags
//
// Confirmation tags provide integrity protection for the confirmed transcript
// hash (RFC 9420 §8.2):
//
//	confirmation_tag = MAC(confirmation_key, confirmed_transcript_hash)
//
// The confirmation_key is derived from the epoch_secret using HKDF-Expand-Label
// with the label "confirm".
//
// # KeyPackage Hash References
//
// KeyPackages are referenced in Welcome messages using their hash:
//
//	key_package_hash = Hash(KeyPackage.Marshal())
//
// This allows new members to identify which encrypted secrets in the Welcome
// message are intended for them.
//
// # Security Considerations
//
//   - Welcome messages MUST be encrypted to protect group secrets from
//     unauthorized disclosure. Only the intended recipient should be able
//     to decrypt their EncryptedGroupSecrets.
//
//   - GroupInfo signatures MUST be verified before tgoing the group state.
//     The signature binds the GroupContext to the signer's identity.
//
//   - Confirmation tags MUST be verified to ensure the GroupInfo was
//     correctly generated and the epoch is valid.
//
//   - KeyPackage hashes MUST be computed over the full serialized KeyPackage
//     to ensure unique identification.
//
// # Usage Examples
//
// Creating a Welcome message:
//
//	secrets := []messages.EncryptedGroupSecrets{
//	    {
//	        KeyPackageHash: keyPackageHash,
//	        EncryptedKey:   kemOutput,
//	        Ciphertext:     encryptedSecrets,
//	    },
//	}
//	welcome := messages.NewWelcome(cipherSuite, secrets, encryptedGroupInfo)
//	data, err := welcome.Marshal()
//
// Parsing a Welcome message:
//
//	welcome, err := messages.UnmarshalWelcome(data)
//	if err != nil {
//	    return err
//	}
//	secret := welcome.FindSecret(myKeyPackageHash)
//	if secret == nil {
//	    return errors.New("no secrets for me")
//	}
//
// Encrypting GroupInfo:
//
//	encryptedGI, err := messages.EncryptGroupInfo(groupInfo, welcomeKey, welcomeNonce, cs)
//	if err != nil {
//	    return err
//	}
//
// Decrypting GroupInfo:
//
//	groupInfo, err := messages.DecryptGroupInfo(encryptedGI, welcomeKey, welcomeNonce, cs)
//	if err != nil {
//	    return err
//	}
//
// Computing confirmation tag:
//
//	tag := messages.ComputeConfirmationTag(
//	    sha256.New,
//	    confirmationKey,
//	    confirmedTranscriptHash,
//	)
//
// # RFC Compliance
//
// This package is fully compliant with:
//   - RFC 9420: The Messaging Layer Security (MLS) Protocol
//   - §2.1.2: Variable-Size Vector Length Headers
//   - §8.1: Group Context
//   - §8.2: Transcript Hashes and Confirmation Tags
//   - §10.1: KeyPackage Hash References
//   - §12.4.3: GroupInfo
//   - §12.4.3.1: Welcome Messages
//   - RFC 8446: TLS 1.3 Presentation Language
//
// # Testing
//
// The package includes comprehensive tests:
//   - Marshal/Unmarshal round-trip tests for all message types
//   - Encryption/Decryption tests for GroupInfo
//   - Confirmation tag computation and verification
//   - KeyPackage hash determinism and uniqueness
//   - Edge cases (wrong keys, tampered data, etc.)
//
// Run tests with:
//
//	go test ./messages/...
//	go test -race ./messages/...
//	go test -cover ./messages/...
//
// # References
//
//   - RFC 9420: https://www.rfc-editor.org/rfc/rfc9420.html
//   - RFC 8446 (TLS Presentation Language): https://www.rfc-editor.org/rfc/rfc8446.html#section-3
//   - RFC 5869 (HKDF): https://www.rfc-editor.org/rfc/rfc5869.html
//   - RFC 9180 (HPKE): https://www.rfc-editor.org/rfc/rfc9180.html
package messages
