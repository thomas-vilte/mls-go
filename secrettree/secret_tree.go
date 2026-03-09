// Package secrettree implements the MLS Secret Tree according to RFC 9420 §9.
//
// The secret tree is derived from the encryption_secret and is used to derive
// encryption keys and nonces for application and handshake messages.
package secrettree

import (
	"fmt"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/internal/tls"
)

// Tree represents the secret tree for a group epoch.
type Tree struct {
	cs               ciphersuite.CipherSuite
	encryptionSecret *ciphersuite.Secret
	leafCount        uint32
	generation       uint64
}

// LeafSecret holds the per-leaf ratchet state (RFC 9420 §9.1).
//
// Each leaf maintains two separate ratchets:
//   - handshakeRatchetSecret: for Proposal and Commit messages
//   - applicationRatchetSecret: for ApplicationData messages
//
// The ratchet advances forward-only. To move to generation G, call
// ratchetTo(G) or use Advance() for sequential steps.
type LeafSecret struct {
	leafIndex                uint32
	generation               uint64 // current ratchet generation (both ratchets stay in sync)
	leafSecret               *ciphersuite.Secret
	handshakeRatchetSecret   *ciphersuite.Secret
	applicationRatchetSecret *ciphersuite.Secret
	sequenceNumber           uint64 // message counter (separate from ratchet generation)
}

// NewTree creates a new secret tree from an encryption secret and cipher suite.
//
// encryption_secret is derived from the key schedule (RFC 9420 §8).
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
// The returned LeafSecret starts at ratchet generation t.generation.
// Each call creates a fresh LeafSecret derived from the encryption_secret.
func (t *Tree) LeafForIndex(leafIndex uint32) (*LeafSecret, error) {
	if leafIndex >= t.leafCount {
		return nil, fmt.Errorf("leaf index %d out of range [0, %d)", leafIndex, t.leafCount)
	}

	var leafSecret *ciphersuite.Secret
	if t.leafCount == 1 {
		leafSecret = t.encryptionSecret
	} else {
		leafSecret = t.deriveLeafSecret(leafIndex)
	}

	nh := t.cs.HashLength()

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
	_ = nh // reserved for future use with multi-suite support
	return ls, nil
}

// deriveLeafSecret derives the leaf secret for a given leaf index using
// RFC 9420 §9 tree navigation on a left-balanced binary tree.
//
// At each step: if the target leaf falls in the left half, derive with "left";
// otherwise derive with "right" and adjust the position. Works for any N >= 1.
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
			n = n - k
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

// ratchetTo advances both ratchets to the target generation.
//
// It is a no-op if already at the target generation.
// Returns an error if gen < current generation (can't go backwards).
//
// RFC 9420 §9.1: ratchet_secret[j+1] = DeriveTreeSecret(ratchet_secret[j], "secret", j, KDF.Nh)
func (ls *LeafSecret) ratchetTo(gen uint32) error {
	nh := 32 // SHA-256 output length; matches KDF.Nh for CS=2
	for ls.generation < uint64(gen) {
		g := uint32(ls.generation)
		genBytes := uint32ToBytes(g)

		next, err := ls.applicationRatchetSecret.KdfExpandLabel("secret", genBytes, nh)
		if err != nil {
			return fmt.Errorf("advance application ratchet (gen %d): %w", g, err)
		}
		ls.applicationRatchetSecret = next

		nextHs, err := ls.handshakeRatchetSecret.KdfExpandLabel("secret", genBytes, nh)
		if err != nil {
			return fmt.Errorf("advance handshake ratchet (gen %d): %w", g, err)
		}
		ls.handshakeRatchetSecret = nextHs

		ls.generation++
	}
	return nil
}

// Advance ratchets both secrets one step forward, providing forward secrecy.
//
// After Advance, the secrets for the previous generation are replaced.
func (ls *LeafSecret) Advance() error {
	return ls.ratchetTo(uint32(ls.generation) + 1)
}

// CurrentGeneration returns the current ratchet generation.
func (ls *LeafSecret) CurrentGeneration() uint32 {
	return uint32(ls.generation)
}

// ApplicationKey derives the application content key for generation gen.
//
// RFC 9420 §9.1: application_key[j] = DeriveTreeSecret(application_ratchet_secret[j], "key", j, AEAD.Nk)
func (ls *LeafSecret) ApplicationKey(generation uint32) ([]byte, error) {
	if err := ls.ratchetTo(generation); err != nil {
		return nil, err
	}
	key, err := ls.applicationRatchetSecret.KdfExpandLabel("key", uint32ToBytes(generation), 16)
	if err != nil {
		return nil, fmt.Errorf("deriving application key: %w", err)
	}
	return key.AsSlice(), nil
}

// ApplicationNonce derives the application content nonce for generation gen.
//
// RFC 9420 §9.1: application_nonce[j] = DeriveTreeSecret(application_ratchet_secret[j], "nonce", j, AEAD.Nn)
func (ls *LeafSecret) ApplicationNonce(generation uint32) ([]byte, error) {
	if err := ls.ratchetTo(generation); err != nil {
		return nil, err
	}
	nonce, err := ls.applicationRatchetSecret.KdfExpandLabel("nonce", uint32ToBytes(generation), 12)
	if err != nil {
		return nil, fmt.Errorf("deriving application nonce: %w", err)
	}
	return nonce.AsSlice(), nil
}

// HandshakeKey derives the handshake content key for generation gen.
//
// RFC 9420 §9.1: handshake_key[j] = DeriveTreeSecret(handshake_ratchet_secret[j], "key", j, AEAD.Nk)
func (ls *LeafSecret) HandshakeKey(generation uint32) ([]byte, error) {
	if err := ls.ratchetTo(generation); err != nil {
		return nil, err
	}
	key, err := ls.handshakeRatchetSecret.KdfExpandLabel("key", uint32ToBytes(generation), 16)
	if err != nil {
		return nil, fmt.Errorf("deriving handshake key: %w", err)
	}
	return key.AsSlice(), nil
}

// HandshakeNonce derives the handshake content nonce for generation gen.
//
// RFC 9420 §9.1: handshake_nonce[j] = DeriveTreeSecret(handshake_ratchet_secret[j], "nonce", j, AEAD.Nn)
func (ls *LeafSecret) HandshakeNonce(generation uint32) ([]byte, error) {
	if err := ls.ratchetTo(generation); err != nil {
		return nil, err
	}
	nonce, err := ls.handshakeRatchetSecret.KdfExpandLabel("nonce", uint32ToBytes(generation), 12)
	if err != nil {
		return nil, fmt.Errorf("deriving handshake nonce: %w", err)
	}
	return nonce.AsSlice(), nil
}

// EncryptionKey derives a content key for generation seqNum using the application ratchet.
// Delegates to ApplicationKey for backward compatibility with framing.
//
// Note: RFC 9420 §9 distinguishes handshake vs application ratchets by content_type.
// This method always uses the application ratchet.
func (ls *LeafSecret) EncryptionKey(seqNum uint64) ([]byte, error) {
	return ls.ApplicationKey(uint32(seqNum))
}

// Nonce derives a content nonce for generation seqNum using the application ratchet.
// Delegates to ApplicationNonce for backward compatibility with framing.
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
func (ls *LeafSecret) DeleteLeaf() {
	if ls.leafSecret != nil {
		ls.leafSecret = ciphersuite.ZeroSecret(ls.leafSecret.Len())
	}
	if ls.handshakeRatchetSecret != nil {
		ls.handshakeRatchetSecret = ciphersuite.ZeroSecret(ls.handshakeRatchetSecret.Len())
	}
	if ls.applicationRatchetSecret != nil {
		ls.applicationRatchetSecret = ciphersuite.ZeroSecret(ls.applicationRatchetSecret.Len())
	}
	ls.sequenceNumber = 0
}

// Encrypt encrypts a message for the given generation using the application ratchet.
func (ls *LeafSecret) Encrypt(plaintext []byte, aad []byte, seqNum uint64) ([]byte, error) {
	key, err := ls.ApplicationKey(uint32(seqNum))
	if err != nil {
		return nil, fmt.Errorf("getting encryption key: %w", err)
	}
	nonce, err := ls.ApplicationNonce(uint32(seqNum))
	if err != nil {
		return nil, fmt.Errorf("getting nonce: %w", err)
	}
	return ciphersuite.AESEncrypt(key, nonce, plaintext, aad)
}

// Decrypt decrypts a message for the given generation using the application ratchet.
func (ls *LeafSecret) Decrypt(ciphertext []byte, aad []byte, seqNum uint64) ([]byte, error) {
	key, err := ls.ApplicationKey(uint32(seqNum))
	if err != nil {
		return nil, fmt.Errorf("getting encryption key: %w", err)
	}
	nonce, err := ls.ApplicationNonce(uint32(seqNum))
	if err != nil {
		return nil, fmt.Errorf("getting nonce: %w", err)
	}
	return ciphersuite.AESDecrypt(key, nonce, ciphertext, aad)
}

// Helper functions

func uint32ToBytes(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func uint64ToBytes(v uint64) []byte {
	return []byte{
		byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	}
}

// Marshal serializes the tree state.
func (t *Tree) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteVLBytes(t.encryptionSecret.AsSlice())
	w.WriteUint32(t.leafCount)
	w.WriteUint64(t.generation)
	return w.Bytes()
}

// Unmarshal deserializes the tree state.
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
	}, nil
}
