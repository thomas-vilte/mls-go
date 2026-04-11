// Package treesync implements MLS ratchet tree operations according to RFC 9420 §7.
//
// # Overview
//
// The ratchet tree is the core data structure that enables efficient group key
// agreement in MLS. It allows members to encrypt to subsets of the group using
// a tree of HPKE public keys, reducing encryption cost from O(N) to O(log N).
//
// This package implements:
//   - Ratchet tree structure (RFC 9420 §7.1, §7.2)
//   - Leaf node validation (RFC 9420 §7.3)
//   - Tree hashing (RFC 9420 §7.8)
//   - Parent hashes (RFC 9420 §7.9)
//   - Update paths (RFC 9420 §7.6)
//   - Tree synchronization
//
// # Interleaved Tree Representation (RFC Appendix C)
//
// MLS uses an array-based interleaved representation for efficient indexing:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│              Interleaved Tree Layout (4 leaves)                 │
//	├─────────────────────────────────────────────────────────────────┤
//	│                                                                 │
//	│  Index:     0       1       2       3       4       5       6   │
//	│            ┌───┐   ┌───┐   ┌───┐   ┌───┐   ┌───┐   ┌───┐   ┌───┐│
//	│            │L0 │   │P0 │   │L1 │   │P1 │   │L2 │   │P2 │   │L3 ││
//	│            └───┘   └───┘   └───┘   └───┘   └───┘   └───┘   └───┘│
//	│              │       │       │       │       │       │       │   │
//	│              │       └───┬───┘       └───┬───┘       │       │   │
//	│              │           │               │           │       │   │
//	│              └───────────┴───────┬───────┴───────────┘       │   │
//	│                                  │                           │   │
//	│                                  └───────────┬───────────────┘   │
//	│                                              │                   │
//	│  Leaves (even indices):  L0, L1, L2, L3      │                   │
//	│  Parents (odd indices):  P0, P1, P2          ▼                   │
//	│                                        Root (P2)                 │
//	│                                                                 │
//	└─────────────────────────────────────────────────────────────────┘
//
// Key properties:
//   - Leaves are at even indices: 0, 2, 4, 6, ...
//   - Parents are at odd indices: 1, 3, 5, 7, ...
//   - For N leaves, there are 2N-1 total nodes
//   - Parent of node i: (i-1)/2 for odd i, i/2-1 for even i (with special cases)
//   - Left child of parent p: 2p+1
//   - Right child of parent p: 2p+2
//
// Why interleaved? This layout allows:
//   - O(1) leaf access by index
//   - Efficient tree traversal without pointers
//   - Compact serialization for wire format
//
// # Leaf Node Structure (RFC 9420 §7.2)
//
// Each leaf contains information about a group member:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                    LeafNode Structure                           │
//	├─────────────────────────────────────────────────────────────────┤
//	│  HPKEPublicKey encryption_key<V>     - Key for encrypting to   │
//	│                                        this member              │
//	│  SignaturePublicKey signature_key<V> - Key for verifying       │
//	│                                        member signatures        │
//	│  Credential credential               - Identity credential     │
//	│                                        (Basic, X509, etc.)      │
//	│  Capabilities capabilities           - Supported protocols,    │
//	│                                        cipher suites, etc.      │
//	│  LeafNodeSource leaf_node_source     - How node was created:   │
//	│                                        1=key_package,          │
//	│                                        2=update, 3=commit       │
//	│  select (leaf_node_source) {         - Conditional fields:     │
//	│    case key_package:                  - Lifetime for key_pkg    │
//	│      Lifetime lifetime;               - ParentHash for commit   │
//	│    case update:                       - Nothing for update      │
//	│    case commit:                       │                         │
//	│      opaque parent_hash<V>;           │                         │
//	│  }                                    │                         │
//	│  Extension extensions<V>             - Optional extensions     │
//	│  opaque signature<V>                 - Signature over TBS      │
//	└─────────────────────────────────────────────────────────────────┘
//
// # Tree Hash Computation (RFC 9420 §7.8)
//
// The tree hash provides a commitment to the entire tree state:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│              Tree Hash Computation Flow                         │
//	├─────────────────────────────────────────────────────────────────┤
//	│                                                                 │
//	│  Leaf Hash (RFC §7.8):                                          │
//	│  ┌──────────────────────────────────────────────────────────┐  │
//	│  │ struct {                                                  │  │
//	│  │     uint32 leaf_index;                                    │  │
//	│  │     optional<LeafNode> leaf_node;                         │  │
//	│  │ } LeafNodeHashInput;                                      │  │
//	│  │                                                           │  │
//	│  │ leaf_hash = Hash(LeafNodeHashInput)                       │  │
//	│  └──────────────────────────────────────────────────────────┘  │
//	│                                                                 │
//	│  Parent Hash (RFC §7.9):                                        │
//	│  ┌──────────────────────────────────────────────────────────┐  │
//	│  │ struct {                                                  │  │
//	│  │     HPKEPublicKey public_key;                             │  │
//	│  │     opaque parent_hash<V>;           // Recursive         │  │
//	│  │     opaque original_sibling_tree_hash<V>;                 │  │
//	│  │ } ParentHashInput;                                        │  │
//	│  │                                                           │  │
//	│  │ parent_hash = Hash(ParentHashInput)                       │  │
//	│  └──────────────────────────────────────────────────────────┘  │
//	│                                                                 │
//	│  Tree Hash = Root's parent_hash                                 │
//	│                                                                 │
//	└─────────────────────────────────────────────────────────────────┘
//
// # Parent Hashes (RFC 9420 §7.9)
//
// Parent hashes create a chain of authenticity from leaves to root:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                  Parent Hash Chain                              │
//	├─────────────────────────────────────────────────────────────────┤
//	│                                                                 │
//	│         Root                                                    │
//	│        ┌─┴─┐                                                    │
//	│       P1   L3                                                   │
//	│      ┌─┴─┐                                                      │
//	│     P0   L2          P0.hash = Hash(P0.key, P0.parent_hash,    │
//	│    ┌─┴─┐               L1.hash)                                 │
//	│   L0   L1                                                       │
//	│                                                                 │
//	│  Each parent hash includes:                                     │
//	│  1. Parent's HPKE public key                                    │
//	│  2. Parent's parent hash (recursive, or empty for root)         │
//	│  3. Original sibling's tree hash (before blanking)              │
//	│                                                                 │
//	│  This creates a chain where modifying any node invalidates      │
//	│  all hashes up to the root.                                     │
//	│                                                                 │
//	└─────────────────────────────────────────────────────────────────┘
//
// Why parent hashes? They provide:
//   - Tree integrity: Detect unauthorized modifications
//   - Authentication path: Verify membership without full tree
//   - Efficient sync: Compare hashes instead of full trees
//
// # Update Paths (RFC 9420 §7.6)
//
// When a member updates their keys, they send an UpdatePath:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                   UpdatePath Structure                          │
//	├─────────────────────────────────────────────────────────────────┤
//	│  LeafNode leaf_node              - New leaf with fresh keys    │
//	│  HPKECiphertext nodes<V>         - Encrypted path secrets      │
//	│                                   for each parent node         │
//	└─────────────────────────────────────────────────────────────────┘
//
// The UpdatePath allows other members to:
//  1. Verify the new leaf node signature
//  2. Decrypt their path secret using their leaf keys
//  3. Derive new parent keys for the updated path
//  4. Update their tree view
//
// # Path Secret Derivation (RFC 9420 §7.4.3)
//
// Path secrets are derived using HKDF:
//
//	path_secret[0] = HKDF-Extract(init_secret, HPKE_shared_secret)
//	path_secret[i] = HKDF-Extract(path_secret[i-1], HPKE_shared_secret[i])
//
// Each path secret is then used to derive:
//   - Node encryption key (HPKE)
//   - Node parent hash
//
// # Node Blanking
//
// For efficiency, nodes not on a member's direct path can be "blanked":
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                    Node Blanking                                │
//	├─────────────────────────────────────────────────────────────────┤
//	│                                                                 │
//	│  Before update (member at L0):         After update:            │
//	│         Root                               Root                 │
//	│        ┌─┴─┐                              ┌─┴─┐                 │
//	│       P1   L3                            P1   L3                │
//	│      ┌─┴─┐                              ┌─┴─┐                   │
//	│     P0   L2                            P0   L2                  │
//	│    ┌─┴─┐                              ┌─┴─┐                     │
//	│   L0   L1                           L0*  L1                     │
//	│                                        │                        │
//	│  P0, P1 on direct path              P0, P1 updated             │
//	│  L1 is "unmerged" (not blanked)       L1 unchanged              │
//	│                                                                 │
//	└─────────────────────────────────────────────────────────────────┘
//
// Unmerged leaves tracking: Each parent tracks which leaves haven't
// been updated through it, allowing efficient path compression.
//
// # Wire Format
//
// Trees are serialized using TLS presentation language:
//
//	struct {
//	    uint32 num_leaves;
//	    RatchetTreeNode nodes<V>;
//	} RatchetTree;
//
//	struct {
//	    uint8 node_type;  // 0=empty, 1=leaf, 2=parent
//	    select (node_type) {
//	        case empty: struct{};
//	        case leaf: LeafNode leaf_node;
//	        case parent: struct {
//	            HPKEPublicKey encryption_key<V>;
//	            opaque parent_hash<V>;
//	            LeafIndex unmerged_leaves<V>;
//	        };
//	    };
//	} RatchetTreeNode;
//
// # Usage
//
// Creating a ratchet tree:
//
//	tree := treesync.NewRatchetTree(numLeaves)
//
// Setting a leaf:
//
//	leafData := &treesync.LeafNodeData{
//	    EncryptionKey: hpkePublicKey,
//	    SignatureKey:  signaturePublicKey,
//	    Credential:    cred,
//	    Capabilities:  caps,
//	    // ... other fields
//	}
//	tree.SetLeaf(leafIndex, leafData)
//
// Computing tree hash:
//
//	treeHash := tree.Hash()
//
// Validating a leaf:
//
//	err := leafData.Validate()
//	if err != nil {
//	    return err
//	}
//
// Creating an UpdatePath:
//
//	updatePath := treesync.NewUpdatePath(leafNode, ciphertexts)
//	data := updatePath.Marshal()
//
// # Security Considerations
//
//   - Leaf Validation: Always validate LeafNode signatures and credentials
//     before accepting into the tree (RFC §7.3).
//
//   - Parent Hash Verification: Verify parent hashes match to detect
//     tree manipulation attacks.
//
//   - Key Freshness: Each update should use fresh HPKE keys to maintain
//     post-compromise security.
//
//   - Credential Expiry: Check LeafNode lifetime to prevent using
//     expired credentials.
//
// # References
//
//   - RFC 9420 §7: Ratchet Tree Operations
//   - RFC 9420 §7.1: Parent Node Contents
//   - RFC 9420 §7.2: Leaf Node Contents
//   - RFC 9420 §7.3: Leaf Node Validation
//   - RFC 9420 §7.4: Ratchet Tree Evolution
//   - RFC 9420 §7.6: Update Paths
//   - RFC 9420 §7.8: Tree Hashes
//   - RFC 9420 §7.9: Parent Hashes
//   - RFC 9420 Appendix C: Array-Based Trees
package treesync
