// Package secrettree implements the MLS Secret Tree according to RFC 9420 §9.
//
// # Overview
//
// The secret tree is the core mechanism for deriving per-sender encryption keys
// in MLS. It provides forward secrecy through ratcheting and ensures that each
// group member has independent encryption keys for their messages.
//
// From the encryption_secret (derived in the key schedule, RFC §8), the secret
// tree derives leaf secrets for each member, and from those, per-generation
// encryption keys and nonces.
//
// # Tree Structure (RFC 9420 §9)
//
// The secret tree uses a left-balanced binary tree structure to derive leaf
// secrets. This allows efficient key derivation for any leaf without storing
// all leaf secrets explicitly.
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                    Secret Tree Hierarchy                        │
//	├─────────────────────────────────────────────────────────────────┤
//	│                                                                 │
//	│  encryption_secret (root)                                       │
//	│      │                                                          │
//	│      ├─ Leaf 0 ──► handshake_ratchet[0] ──► app_ratchet[0]     │
//	│      │              │                        │                  │
//	│      │              ├─ key[0]                ├─ key[0]          │
//	│      │              ├─ key[1]                ├─ key[1]          │
//	│      │              └─ ...                   └─ ...             │
//	│      │                                                          │
//	│      ├─ Leaf 1 ──► handshake_ratchet[1] ──► app_ratchet[1]     │
//	│      │              │                        │                  │
//	│      │              └─ (same structure)      └─ (same)          │
//	│      │                                                          │
//	│      └─ ... (one leaf per group member)                         │
//	│                                                                 │
//	└─────────────────────────────────────────────────────────────────┘
//
// # Leaf Secret Derivation (RFC 9420 §9, Figure 25)
//
// For groups with more than one member, leaf secrets are derived using a
// left-balanced binary tree navigation:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│              Left-Balanced Binary Tree (8 leaves)               │
//	├─────────────────────────────────────────────────────────────────┤
//	│                                                                 │
//	│                         Root                                    │
//	│                          │                                      │
//	│              ┌───────────┴───────────┐                         │
//	│              │                       │                         │
//	│           "left"                  "right"                       │
//	│              │                       │                         │
//	│      ┌───────┴───────┐       ┌───────┴───────┐                 │
//	│      │               │       │               │                 │
//	│   "left"  "right"  "left"  "right"  ...                       │
//	│      │       │       │       │                                  │
//	│      L0      L1      L2      L3     ...  L7                    │
//	│                                                                 │
//	│  To reach leaf L5: Root → "right" → "right" → "left"           │
//	│                                                                 │
//	└─────────────────────────────────────────────────────────────────┘
//
// The algorithm works as follows:
//   - At each node, if the target leaf is in the left subtree (pos < 2^k),
//     derive with label "left" and continue left.
//   - Otherwise, derive with label "right", subtract 2^k from position,
//     and continue right.
//   - Repeat until reaching a single leaf.
//
// Why left-balanced? This structure ensures that the tree is as balanced
// as possible for any number of leaves, minimizing the depth and thus the
// number of HKDF operations needed to reach any leaf.
//
// # Ratchet Structure (RFC 9420 §9.1)
//
// Each leaf maintains TWO independent ratchets:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                  Per-Leaf Ratchet Structure                     │
//	├─────────────────────────────────────────────────────────────────┤
//	│                                                                 │
//	│  leaf_secret                                                    │
//	│      │                                                          │
//	│      ├─ HKDF-Expand-Label("handshake") ──► handshake_root      │
//	│      │                        │                                 │
//	│      │                        ├─ DeriveTreeSecret(gen=0)        │
//	│      │                        │   ├─ handshake_key[0]           │
//	│      │                        │   └─ handshake_nonce[0]         │
//	│      │                        ├─ DeriveTreeSecret(gen=1)        │
//	│      │                        │   ├─ handshake_key[1]           │
//	│      │                        │   └─ handshake_nonce[1]         │
//	│      │                        └─ ...                           │
//	│      │                                                          │
//	│      └─ HKDF-Expand-Label("application") ──► application_root  │
//	│                               │                                 │
//	│                               ├─ DeriveTreeSecret(gen=0)        │
//	│                               │   ├─ application_key[0]         │
//	│                               │   └─ application_nonce[0]       │
//	│                               ├─ DeriveTreeSecret(gen=1)        │
//	│                               │   ├─ application_key[1]         │
//	│                               │   └─ application_nonce[1]       │
//	│                               └─ ...                           │
//	│                                                                 │
//	└─────────────────────────────────────────────────────────────────┘
//
// Why two ratchets? RFC 9420 §9 separates handshake and application messages
// to provide independent key management:
//   - Handshake ratchet: for Proposal and Commit messages (critical for security)
//   - Application ratchet: for ApplicationData messages (user content)
//
// This separation ensures that:
//  1. Compromise of application keys doesn't affect handshake security
//  2. Different retention policies can be applied
//  3. Handshake messages (which change group state) have stronger isolation
//
// # Ratchet Evolution (RFC 9420 §9.1, Figure 27)
//
// The ratchet advances forward-only, providing forward secrecy:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                  Ratchet Forward Evolution                      │
//	├─────────────────────────────────────────────────────────────────┤
//	│                                                                 │
//	│  Generation 0              Generation 1              Generation 2│
//	│  ┌─────────────┐          ┌─────────────┐          ┌─────────┐ │
//	│  │ ratchet[0]  │ ────────►│ ratchet[1]  │ ────────►│ratchet[2]│ │
//	│  │             │  "secret"│             │  "secret"│         │ │
//	│  │ key[0]      │          │ key[1]      │          │key[2]   │ │
//	│  │ nonce[0]    │          │ nonce[1]    │          │nonce[2] │ │
//	│  └─────────────┘          └─────────────┘          └─────────┘ │
//	│       │                        │                        │      │
//	│       │ (used)                 │ (current)              │(next)│
//	│       │                        │                        │      │
//	│  [DELETE]                 [IN USE]                [FUTURE]     │
//	│                                                                 │
//	│  HKDF-Expand-Label(ratchet[j], "secret", j, Nh) → ratchet[j+1] │
//	│                                                                 │
//	└─────────────────────────────────────────────────────────────────┘
//
// Forward secrecy: Once the ratchet advances from generation j to j+1,
// the secrets for generation j are irrecoverably lost. This ensures that
// compromise of current state doesn't reveal past messages.
//
// # Key and Nonce Derivation (RFC 9420 §9.1)
//
// For each generation j, keys and nonces are derived as:
//
//	application_key[j] = DeriveTreeSecret(
//	    application_ratchet_secret[j],
//	    "key",
//	    j,
//	    AEAD.Nk  // 16 bytes for AES-128-GCM
//	)
//
//	application_nonce[j] = DeriveTreeSecret(
//	    application_ratchet_secret[j],
//	    "nonce",
//	    j,
//	    AEAD.Nn  // 12 bytes for GCM
//	)
//
//	handshake_key[j] = DeriveTreeSecret(
//	    handshake_ratchet_secret[j],
//	    "key",
//	    j,
//	    AEAD.Nk
//	)
//
//	handshake_nonce[j] = DeriveTreeSecret(
//	    handshake_ratchet_secret[j],
//	    "nonce",
//	    j,
//	    AEAD.Nn
//	)
//
// The generation index j is included in the derivation to ensure that
// even if the ratchet state is somehow duplicated, different generations
// produce different keys.
//
// # Wire Format
//
// The Tree state is serialized using TLS presentation language:
//
//	struct {
//	    opaque encryption_secret<V>;
//	    uint32 leaf_count;
//	    uint64 generation;
//	} SecretTree;
//
// # Security Considerations
//
//   - Forward Secrecy: The ratchet MUST advance before encrypting messages
//     in a new generation. After advancing, previous generation secrets MUST
//     be zeroed to prevent recovery.
//
//   - Key Separation: Handshake and application ratchets MUST remain
//     independent. Never use application keys for handshake messages or
//     vice versa.
//
//   - Leaf Isolation: Each leaf's secrets MUST be independent. Compromise
//     of one leaf's state must not reveal other leaves' secrets.
//
//   - Generation Monotonicity: The ratchet generation MUST only increase.
//     Going backwards would violate forward secrecy.
//
//   - Secure Deletion: When a leaf is removed from the group (or the tree
//     is destroyed), all secrets MUST be securely zeroed from memory.
//
// # Usage Examples
//
// Creating a secret tree:
//
//	encSecret, err := ciphersuite.NewSecretRandom(32)
//	if err != nil {
//	    return err
//	}
//	tree, err := secrettree.NewTree(encSecret, leafCount, cipherSuite)
//	if err != nil {
//	    return err
//	}
//
// Getting a leaf for encryption:
//
//	leaf, err := tree.LeafForIndex(senderIndex)
//	if err != nil {
//	    return err
//	}
//
// Encrypting an application message:
//
//	seqNum := leaf.NextSequenceNumber()
//	ciphertext, err := leaf.Encrypt(plaintext, aad, seqNum)
//	if err != nil {
//	    return err
//	}
//
// Decrypting a message:
//
//	plaintext, err := leaf.Decrypt(ciphertext, aad, seqNum)
//	if err != nil {
//	    return err
//	}
//
// Advancing the ratchet (for forward secrecy):
//
//	err := leaf.Advance()
//	if err != nil {
//	    return err
//	}
//
// Removing a leaf (secure deletion):
//
//	leaf.DeleteLeaf() // Zeroes all secrets
//
// # Integration with Other Packages
//
// The secret tree integrates with:
//
//   - schedule: Provides encryption_secret from the key schedule (RFC §8)
//   - framing: Uses leaf secrets to encrypt/decrypt PrivateMessages (RFC §6)
//   - group: Manages tree lifecycle across epoch transitions
//
// Key schedule integration:
//
//	epoch_secret (from key schedule)
//	    │
//	    │ DeriveSecret("encryption")
//	    ▼
//	encryption_secret ──► NewTree() ──► SecretTree
//	                                      │
//	                                      └─► LeafForIndex() ──► LeafSecret
//	                                                              │
//	                                                              ├─ ApplicationKey()
//	                                                              ├─ HandshakeKey()
//	                                                              └─ Encrypt()
//
// # RFC Compliance
//
// This package is fully compliant with:
//   - RFC 9420 §9: Secret Tree
//   - RFC 9420 §9.1: Encryption Keys
//   - RFC 9420 §9.2: Deletion Schedule
//   - RFC 9420 §8: Key Schedule (for encryption_secret derivation)
//
// # Testing
//
// The package includes comprehensive tests:
//   - Tree creation and leaf derivation
//   - Ratchet forward secrecy verification
//   - Handshake vs application key separation
//   - Encrypt/Decrypt round-trips
//   - DeleteLeaf secure zeroing
//   - Marshal/Unmarshal serialization
//   - Multiple leaves produce distinct keys
//
// Run tests with:
//
//	go test ./secrettree/...
//	go test -race ./secrettree/...
//	go test -cover ./secrettree/...
//
// # References
//
//   - RFC 9420 §9: https://www.rfc-editor.org/rfc/rfc9420.html#section-9
//   - RFC 9420 §9.1: https://www.rfc-editor.org/rfc/rfc9420.html#section-9.1
//   - RFC 9420 §8: https://www.rfc-editor.org/rfc/rfc9420.html#section-8
//   - RFC 5869 (HKDF): https://www.rfc-editor.org/rfc/rfc5869.html
package secrettree
