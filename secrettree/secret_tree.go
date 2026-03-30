// Package secrettree implements the MLS Secret Tree according to RFC 9420 §9.
//
// The secret tree is derived from the encryption_secret (from the key schedule, RFC §8)
// and is used to derive encryption keys and nonces for application and handshake messages.
//
// RFC 9420 §9:
//
//	Each leaf in the tree corresponds to a group member. Each leaf maintains
//	two independent ratchets:
//	  - handshake_ratchet: for Proposal and Commit messages
//	  - application_ratchet: for ApplicationData messages
//
// From these ratchets, per-generation keys and nonces are derived:
//   - application_key[j], application_nonce[j]
//   - handshake_key[j], handshake_nonce[j]
package secrettree

import (
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/internal/tls"
)

// Tree represents the secret tree for a group epoch as defined in RFC 9420 §9.
//
// The tree is rooted at the encryption_secret and derives leaf secrets for
// each group member. Each leaf maintains independent ratchets for handshake
// and application messages.
//
// RFC 9420 §9, Figure 25:
//
//	encryption_secret
//	    │
//	    ├─► Leaf 0 ──► ratchets for member 0
//	    ├─► Leaf 1 ──► ratchets for member 1
//	    └─► ...
type Tree struct {
	cs               ciphersuite.CipherSuite
	encryptionSecret *ciphersuite.Secret
	leafCount        uint32
	generation       uint64
	leafCache        map[uint32]*LeafSecret // persisted per-leaf ratchet state
}

// LeafSecret holds the per-leaf ratchet state as defined in RFC 9420 §9.1.
//
// Each leaf maintains two separate ratchets for message type separation:
//   - handshakeRatchetSecret: for Proposal and Commit messages (handshake)
//   - applicationRatchetSecret: for ApplicationData messages (application)
//
// This separation ensures that compromise of application keys doesn't affect
// handshake security, and allows different retention policies.
//
// RFC 9420 §9.1, Figure 26:
//
//	leaf_secret
//	    │
//	    ├─ HKDF-Expand-Label("handshake") ──► handshake_ratchet_root
//	    │                                      │
//	    │                                      ├─ gen 0: key[0], nonce[0]
//	    │                                      ├─ gen 1: key[1], nonce[1]
//	    │                                      └─ ...
//	    │
//	    └─ HKDF-Expand-Label("application") ──► application_ratchet_root
//	                                           │
//	                                           ├─ gen 0: key[0], nonce[0]
//	                                           ├─ gen 1: key[1], nonce[1]
//	                                           └─ ...
//
// The ratchet advances forward-only (generation increases monotonically).
// To move to generation G, call ratchetTo(G) or use Advance() for sequential steps.
// cachedGenSecret holds the ratchet secrets for a past generation to support
// out-of-order message decryption (RFC 9420 §9.2).
type cachedGenSecret struct {
	application *ciphersuite.Secret
	handshake   *ciphersuite.Secret
}

// maxCachedGenerations is the maximum number of past generations to retain
// for out-of-order delivery. RFC 9420 §9.2 leaves this as a local decision.
const maxCachedGenerations = 2048

// LeafSecret tracks the per-leaf secret ratchets used for message protection.
type LeafSecret struct {
	cs                       ciphersuite.CipherSuite
	leafIndex                uint32
	generation               uint64 // current ratchet generation (both ratchets stay in sync)
	leafSecret               *ciphersuite.Secret
	handshakeRatchetSecret   *ciphersuite.Secret
	applicationRatchetSecret *ciphersuite.Secret
	sequenceNumber           uint64 // message counter (separate from ratchet generation)
	// secretCache retains ratchet secrets for past generations to support
	// out-of-order decryption. Entries are evicted when the cache exceeds
	// maxCachedGenerations to bound memory usage.
	secretCache map[uint32]*cachedGenSecret
}

// NewTree creates a new secret tree from an encryption secret and cipher suite.
//
// The encryption_secret is derived from the key schedule (RFC 9420 §8) using:
//
//	encryption_secret = DeriveSecret(epoch_secret, "encryption")
//
// The tree initializes with generation 0 and creates leaf secrets on-demand
// when LeafForIndex is called.
//
// Parameters:
//   - encryptionSecret: The root secret from the key schedule (MUST NOT be nil)
//   - leafCount: Number of leaves (group members) in the tree (MUST be > 0)
//   - cs: Cipher suite for HKDF operations
//
// Returns an error if encryptionSecret is nil or leafCount is zero.
func NewTree(encryptionSecret *ciphersuite.Secret, leafCount uint32, cs ciphersuite.CipherSuite) (*Tree, error) {
	if encryptionSecret == nil {
		return nil, fmt.Errorf("encryption_secret is nil")
	}
	if leafCount == 0 {
		return nil, fmt.Errorf("leaf_count must be > 0")
	}
	return &Tree{
		cs:               cs,
		encryptionSecret: encryptionSecret,
		leafCount:        leafCount,
		generation:       0,
		leafCache:        make(map[uint32]*LeafSecret),
	}, nil
}

// LeafCount returns the number of leaves in the tree.
func (t *Tree) LeafCount() uint32 { return t.leafCount }

// Generation returns the current epoch generation of the tree.
func (t *Tree) Generation() uint64 { return t.generation }

// IncrementGeneration increments the epoch generation counter.
func (t *Tree) IncrementGeneration() { t.generation++ }

// LeafForIndex returns a LeafSecret for the given leaf index.
//
// This method derives the leaf secret using the left-balanced binary tree
// navigation algorithm (RFC 9420 §9, Figure 25). The returned LeafSecret
// starts at ratchet generation t.generation (the tree's current epoch).
//
// Each call creates a fresh LeafSecret derived from the encryption_secret.
// The leaf secret is derived as:
//
//	leaf_secret = NavigateTree(encryption_secret, leaf_index)
//	handshake_ratchet = DeriveSecret(leaf_secret, "handshake")
//	application_ratchet = DeriveSecret(leaf_secret, "application")
//
// For single-member groups (leafCount == 1), the encryption_secret itself
// is used as the leaf_secret (no tree navigation needed).
//
// Parameters:
//   - leafIndex: The index of the leaf (0 <= leafIndex < leafCount)
//
// Returns an error if leafIndex is out of range.
func (t *Tree) LeafForIndex(leafIndex uint32) (*LeafSecret, error) {
	if leafIndex >= t.leafCount {
		return nil, fmt.Errorf("leaf index %d out of range [0, %d)", leafIndex, t.leafCount)
	}

	// Return cached leaf if available — preserves ratchet state (generation,
	// sequenceNumber) across successive encrypt/decrypt calls on the same leaf.
	if ls, ok := t.leafCache[leafIndex]; ok {
		return ls, nil
	}

	var leafSecret *ciphersuite.Secret
	if t.leafCount == 1 {
		leafSecret = t.encryptionSecret
	} else {
		leafSecret = t.deriveLeafSecret(leafIndex)
	}

	// RFC 9420 §9, Figure 26: derive two ratchet roots from leaf_secret
	handshakeRatchetSecret, err := leafSecret.DeriveSecret(t.cs, "handshake")
	if err != nil {
		return nil, fmt.Errorf("deriving handshake ratchet secret: %w", err)
	}

	applicationRatchetSecret, err := leafSecret.DeriveSecret(t.cs, "application")
	if err != nil {
		return nil, fmt.Errorf("deriving application ratchet secret: %w", err)
	}

	// Advance both ratchets to the tree's current epoch generation.
	ls := &LeafSecret{
		cs:                       t.cs,
		leafIndex:                leafIndex,
		generation:               0,
		leafSecret:               leafSecret,
		handshakeRatchetSecret:   handshakeRatchetSecret,
		applicationRatchetSecret: applicationRatchetSecret,
		sequenceNumber:           0,
	}
	if err := ls.ratchetTo(uint32(t.generation)); err != nil {
		return nil, fmt.Errorf("advancing to epoch generation %d: %w", t.generation, err)
	}
	t.leafCache[leafIndex] = ls
	return ls, nil
}

// deriveLeafSecret derives the leaf secret for a given leaf index using
// RFC 9420 §9 tree navigation on a left-balanced binary tree.
//
// The algorithm navigates from the root to the target leaf by repeatedly
// dividing the tree in half:
//   - If target leaf is in the left half (pos < 2^k): derive with "left" label
//   - If target leaf is in the right half: derive with "right" label and adjust position
//
// This produces a unique path for each leaf, ensuring leaf isolation:
//
//	Example: 8 leaves, reaching leaf 5
//	Root ──► "right" (pos=5 >= 4) ──► "right" (pos=1 >= 2) ──► "left" (pos=1 < 2) ──► Leaf 5
//
// Why left-balanced? This structure minimizes tree depth for any N, ensuring
// O(log N) HKDF operations to reach any leaf.
//
// Parameters:
//   - leafIndex: Target leaf index (0-based)
//
// Returns the derived leaf secret.
func (t *Tree) deriveLeafSecret(leafIndex uint32) *ciphersuite.Secret {
	current := t.encryptionSecret
	n := t.leafCount
	pos := leafIndex

	for n > 1 {
		k := prevPow2(n) // largest power-of-2 strictly less than n
		if pos < k {
			current, _ = current.KdfExpandLabel("tree", []byte("left"), t.cs.HashLength())
			n = k
		} else {
			current, _ = current.KdfExpandLabel("tree", []byte("right"), t.cs.HashLength())
			pos -= k
			n -= k
		}
	}
	return current
}

// prevPow2 returns the largest power of 2 strictly less than n (n > 1).
func prevPow2(n uint32) uint32 {
	p := uint32(1)
	for p*2 < n {
		p *= 2
	}
	return p
}

// ratchetTo advances both ratchets (handshake and application) to the target generation.
//
// This is the core forward secrecy mechanism. The ratchet evolves as:
//
//	ratchet_secret[j+1] = HKDF-Expand-Label(ratchet_secret[j], "secret", j, Nh)
//
// where j is the current generation and Nh is the hash output length (32 for SHA-256).
//
// RFC 9420 §9.1, Figure 27:
//
//	ratchet[0] ──► Derive("secret", 0) ──► ratchet[1]
//	                                          │
//	                                          ├─► key[1], nonce[1]
//	                                          │
//	                                          └─► Derive("secret", 1) ──► ratchet[2]
//	                                                                        │
//	                                                                        └─► key[2], nonce[2]
//
// Forward secrecy: Once advanced from generation j to j+1, the secrets for
// generation j are irrecoverably lost (unless explicitly retained).
//
// Parameters:
//   - gen: Target generation (MUST be >= current generation)
//
// Returns an error if gen < current generation (can't go backwards).
// This is a no-op if already at the target generation.
func (ls *LeafSecret) ratchetTo(gen uint32) error {
	if uint64(gen) < ls.generation {
		// Past generation: must be in the cache for out-of-order decryption.
		if _, ok := ls.secretCache[gen]; ok {
			return nil // cached — key derivation will use secretCache[gen]
		}
		return fmt.Errorf("generation %d already advanced past (current: %d)", gen, ls.generation)
	}
	nh := ls.cs.HashLength()
	for ls.generation < uint64(gen) {
		g := uint32(ls.generation)
		genBytes := uint32ToBytes(g)

		next, err := ls.applicationRatchetSecret.KdfExpandLabel("secret", genBytes, nh)
		if err != nil {
			return fmt.Errorf("advance application ratchet (gen %d): %w", g, err)
		}
		nextHs, err := ls.handshakeRatchetSecret.KdfExpandLabel("secret", genBytes, nh)
		if err != nil {
			next.SecureZero()
			return fmt.Errorf("advance handshake ratchet (gen %d): %w", g, err)
		}

		// Cache secrets at generation g before advancing, for out-of-order delivery.
		if ls.secretCache == nil {
			ls.secretCache = make(map[uint32]*cachedGenSecret)
		}
		if len(ls.secretCache) < maxCachedGenerations {
			// Clone secrets before zeroing so cache holds the gen-g value.
			ls.secretCache[g] = &cachedGenSecret{
				application: ls.applicationRatchetSecret.Clone(),
				handshake:   ls.handshakeRatchetSecret.Clone(),
			}
		}

		ls.applicationRatchetSecret.SecureZero() // RFC §9.2: delete consumed secret
		ls.applicationRatchetSecret = next
		ls.handshakeRatchetSecret.SecureZero() // RFC §9.2: delete consumed secret
		ls.handshakeRatchetSecret = nextHs

		ls.generation++
	}
	return nil
}

// Advance ratchets both secrets (handshake and application) one step forward,
// providing forward secrecy.
//
// After Advance, the secrets for the previous generation are replaced and
// cannot be recovered. This ensures that compromise of current state doesn't
// reveal past messages.
//
// RFC 9420 §9.1:
//
//	After sending a message with generation j, the sender SHOULD advance
//	the ratchet to generation j+1 and delete the secrets for generation j.
//
// This method is equivalent to ratchetTo(current_generation + 1).
func (ls *LeafSecret) Advance() error {
	return ls.ratchetTo(uint32(ls.generation) + 1)
}

// CurrentGeneration returns the current ratchet generation.
func (ls *LeafSecret) CurrentGeneration() uint32 {
	return uint32(ls.generation)
}

// ApplicationKey derives the application content key for generation gen.
//
// RFC 9420 §9.1:
//
//	application_key[j] = HKDF-Expand-Label(
//	    application_ratchet_secret[j],
//	    "key",
//	    j,
//	    AEAD.Nk  // 16 bytes for AES-128-GCM
//	)
//
// The generation index j is included in the derivation to ensure that
// different generations produce different keys even if the ratchet state
// is somehow duplicated.
//
// Parameters:
//   - gen: Target generation (will advance ratchet if needed)
//
// Returns the 16-byte application encryption key, or an error if derivation fails.
func (ls *LeafSecret) ApplicationKey(generation uint32) ([]byte, error) {
	if err := ls.ratchetTo(generation); err != nil {
		return nil, err
	}
	secret := ls.applicationRatchetSecret
	if uint64(generation) < ls.generation {
		if cached, ok := ls.secretCache[generation]; ok {
			secret = cached.application
		} else {
			return nil, fmt.Errorf("application key for generation %d not in cache", generation)
		}
	}
	key, err := secret.KdfExpandLabel("key", uint32ToBytes(generation), ls.cs.AeadKeyLength())
	if err != nil {
		return nil, fmt.Errorf("deriving application key: %w", err)
	}
	return key.AsSlice(), nil
}

// ApplicationNonce derives the application content nonce for generation gen.
//
// RFC 9420 §9.1:
//
//	application_nonce[j] = HKDF-Expand-Label(
//	    application_ratchet_secret[j],
//	    "nonce",
//	    j,
//	    AEAD.Nn  // 12 bytes for GCM
//	)
//
// Parameters:
//   - gen: Target generation (will advance ratchet if needed)
//
// Returns the 12-byte nonce for AES-GCM encryption, or an error if derivation fails.
func (ls *LeafSecret) ApplicationNonce(generation uint32) ([]byte, error) {
	if err := ls.ratchetTo(generation); err != nil {
		return nil, err
	}
	secret := ls.applicationRatchetSecret
	if uint64(generation) < ls.generation {
		if cached, ok := ls.secretCache[generation]; ok {
			secret = cached.application
		} else {
			return nil, fmt.Errorf("application nonce for generation %d not in cache", generation)
		}
	}
	nonce, err := secret.KdfExpandLabel("nonce", uint32ToBytes(generation), ls.cs.AeadNonceLength())
	if err != nil {
		return nil, fmt.Errorf("deriving application nonce: %w", err)
	}
	return nonce.AsSlice(), nil
}

// HandshakeKey derives the handshake content key for generation gen.
//
// RFC 9420 §9.1:
//
//	handshake_key[j] = HKDF-Expand-Label(
//	    handshake_ratchet_secret[j],
//	    "key",
//	    j,
//	    AEAD.Nk  // 16 bytes for AES-128-GCM
//	)
//
// This key is used for encrypting Proposal and Commit messages (handshake).
// It is derived from a separate ratchet than application keys to ensure
// isolation between handshake and application message security.
//
// Parameters:
//   - gen: Target generation (will advance ratchet if needed)
//
// Returns the 16-byte handshake encryption key, or an error if derivation fails.
func (ls *LeafSecret) HandshakeKey(generation uint32) ([]byte, error) {
	if err := ls.ratchetTo(generation); err != nil {
		return nil, err
	}
	secret := ls.handshakeRatchetSecret
	if uint64(generation) < ls.generation {
		if cached, ok := ls.secretCache[generation]; ok {
			secret = cached.handshake
		} else {
			return nil, fmt.Errorf("handshake key for generation %d not in cache", generation)
		}
	}
	key, err := secret.KdfExpandLabel("key", uint32ToBytes(generation), ls.cs.AeadKeyLength())
	if err != nil {
		return nil, fmt.Errorf("deriving handshake key: %w", err)
	}
	return key.AsSlice(), nil
}

// HandshakeNonce derives the handshake content nonce for generation gen.
//
// RFC 9420 §9.1:
//
//	handshake_nonce[j] = HKDF-Expand-Label(
//	    handshake_ratchet_secret[j],
//	    "nonce",
//	    j,
//	    AEAD.Nn  // 12 bytes for GCM
//	)
//
// Parameters:
//   - gen: Target generation (will advance ratchet if needed)
//
// Returns the 12-byte nonce for handshake message encryption, or an error if derivation fails.
func (ls *LeafSecret) HandshakeNonce(generation uint32) ([]byte, error) {
	if err := ls.ratchetTo(generation); err != nil {
		return nil, err
	}
	secret := ls.handshakeRatchetSecret
	if uint64(generation) < ls.generation {
		if cached, ok := ls.secretCache[generation]; ok {
			secret = cached.handshake
		} else {
			return nil, fmt.Errorf("handshake nonce for generation %d not in cache", generation)
		}
	}
	nonce, err := secret.KdfExpandLabel("nonce", uint32ToBytes(generation), ls.cs.AeadNonceLength())
	if err != nil {
		return nil, fmt.Errorf("deriving handshake nonce: %w", err)
	}
	return nonce.AsSlice(), nil
}

// EncryptionKey derives a content encryption key for generation seqNum using
// the application ratchet.
//
// This is a convenience method that delegates to ApplicationKey for backward
// compatibility with the framing package interface.
//
// Note: RFC 9420 §9 distinguishes handshake vs application ratchets by content_type.
// This method always uses the application ratchet. For handshake messages, use
// HandshakeKey directly.
//
// Parameters:
//   - seqNum: Sequence number (used as generation index)
//
// Returns the 16-byte encryption key, or an error if derivation fails.
func (ls *LeafSecret) EncryptionKey(seqNum uint64) ([]byte, error) {
	return ls.ApplicationKey(uint32(seqNum))
}

// Nonce derives a content encryption nonce for generation seqNum using
// the application ratchet.
//
// This is a convenience method that delegates to ApplicationNonce for backward
// compatibility with the framing package interface.
//
// Parameters:
//   - seqNum: Sequence number (used as generation index)
//
// Returns the 12-byte nonce for AES-GCM, or an error if derivation fails.
func (ls *LeafSecret) Nonce(seqNum uint64) ([]byte, error) {
	return ls.ApplicationNonce(uint32(seqNum))
}

// NextSequenceNumber returns the current sequence number and increments it.
func (ls *LeafSecret) NextSequenceNumber() uint64 {
	seq := ls.sequenceNumber
	ls.sequenceNumber++
	return seq
}

// SetSequenceNumber sets the sequence number.
func (ls *LeafSecret) SetSequenceNumber(seq uint64) {
	ls.sequenceNumber = seq
}

// DeleteLeaf zeroes all ratchet secrets for forward secrecy.
//
// This method securely erases all sensitive state from memory when a leaf
// is removed from the group or when the tree is being destroyed.
//
// RFC 9420 §9.2 (Deletion Schedule):
//
//	When a member leaves the group (or is removed), the secrets for that
//	member's leaf SHOULD be deleted to prevent decryption of future messages.
//
// After DeleteLeaf, the leaf cannot be used to encrypt or decrypt messages.
// Any subsequent key derivation will use zeroed secrets and produce invalid keys.
func (ls *LeafSecret) DeleteLeaf() {
	if ls.leafSecret != nil {
		ls.leafSecret.SecureZero() // RFC §9.2: MUST delete secret values from memory
		ls.leafSecret = nil
	}
	if ls.handshakeRatchetSecret != nil {
		ls.handshakeRatchetSecret.SecureZero()
		ls.handshakeRatchetSecret = nil
	}
	if ls.applicationRatchetSecret != nil {
		ls.applicationRatchetSecret.SecureZero()
		ls.applicationRatchetSecret = nil
	}
	for _, cached := range ls.secretCache {
		if cached.application != nil {
			cached.application.SecureZero()
		}
		if cached.handshake != nil {
			cached.handshake.SecureZero()
		}
	}
	ls.secretCache = nil
	ls.sequenceNumber = 0
}

// Encrypt encrypts a message for the given generation using the application ratchet.
//
// This method derives the application key and nonce for the specified sequence
// number, then encrypts the plaintext using AES-128-GCM.
//
// Parameters:
//   - plaintext: The data to encrypt
//   - aad: Additional authenticated data (authenticated but not encrypted)
//   - seqNum: Sequence number for key/nonce derivation
//
// Returns the ciphertext (including authentication tag), or an error if encryption fails.
//
// RFC 9420 §9.1:
//
//	ciphertext = AEAD-Seal(application_key[seqNum], application_nonce[seqNum], plaintext, aad)
//
//nolint:gocritic // Keep separate []byte parameters for clarity
func (ls *LeafSecret) Encrypt(plaintext []byte, aad []byte, seqNum uint64) ([]byte, error) {
	key, err := ls.ApplicationKey(uint32(seqNum))
	if err != nil {
		return nil, fmt.Errorf("getting encryption key: %w", err)
	}
	nonce, err := ls.ApplicationNonce(uint32(seqNum))
	if err != nil {
		return nil, fmt.Errorf("getting nonce: %w", err)
	}
	return ciphersuite.EncryptWithCipherSuite(key, nonce, plaintext, aad, ls.cs)
}

// Decrypt decrypts a message for the given generation using the application ratchet.
//
// This method derives the application key and nonce for the specified sequence
// number, then decrypts the ciphertext using AES-128-GCM.
//
// Parameters:
//   - ciphertext: The encrypted data (including authentication tag)
//   - aad: Additional authenticated data (must match what was used for encryption)
//   - seqNum: Sequence number for key/nonce derivation
//
// Returns the decrypted plaintext, or an error if decryption fails (e.g., wrong key,
// tampered ciphertext, or mismatched AAD).
//
// RFC 9420 §9.1:
//
//	plaintext = AEAD-Open(application_key[seqNum], application_nonce[seqNum], ciphertext, aad)
//
//nolint:gocritic // Keep separate []byte parameters for clarity
func (ls *LeafSecret) Decrypt(ciphertext []byte, aad []byte, seqNum uint64) ([]byte, error) {
	key, err := ls.ApplicationKey(uint32(seqNum))
	if err != nil {
		return nil, fmt.Errorf("getting encryption key: %w", err)
	}
	nonce, err := ls.ApplicationNonce(uint32(seqNum))
	if err != nil {
		return nil, fmt.Errorf("getting nonce: %w", err)
	}
	return ciphersuite.DecryptWithCipherSuite(key, nonce, ciphertext, aad, ls.cs)
}

// Helper functions

func uint32ToBytes(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// Marshal serializes the tree state to TLS presentation language format.
//
// The serialized format is:
//
//	struct {
//	    opaque encryption_secret<V>;
//	    uint32 leaf_count;
//	    uint64 generation;
//	} SecretTree;
//
// This allows the tree state to be persisted or transmitted for state synchronization.
// Note: Only the tree-level state is serialized. Leaf-specific ratchet state
// is NOT included and must be managed separately if needed.
func (t *Tree) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteVLBytes(t.encryptionSecret.AsSlice())
	w.WriteUint32(t.leafCount)
	w.WriteUint64(t.generation)
	return w.Bytes()
}

// Unmarshal deserializes the tree state from TLS presentation language format.
//
// Parameters:
//   - data: The serialized tree data
//   - cs: Cipher suite for HKDF operations (must match the one used for serialization)
//
// Returns the reconstructed Tree, or an error if the data is malformed.
//
// Note: The deserialized tree will have the same encryption_secret and generation
// as the original, but leaf-specific ratchet state is NOT restored. Leaf secrets
// must be re-derived using LeafForIndex after unmarshaling.
func Unmarshal(data []byte, cs ciphersuite.CipherSuite) (*Tree, error) {
	r := tls.NewReader(data)

	encSecretBytes, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	leafCount, err := r.ReadUint32()
	if err != nil {
		return nil, err
	}
	generation, err := r.ReadUint64()
	if err != nil {
		return nil, err
	}

	return &Tree{
		cs:               cs,
		encryptionSecret: ciphersuite.NewSecret(encSecretBytes),
		leafCount:        leafCount,
		generation:       generation,
		leafCache:        make(map[uint32]*LeafSecret),
	}, nil
}
