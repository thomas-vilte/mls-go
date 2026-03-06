// Package secret_tree implements the MLS Secret Tree according to RFC 9420 §9.
//
// The secret tree is derived from the encryption_secret and is used to derive
// encryption keys and nonces for application messages.
package secret_tree

import (
	"crypto/sha256"
	"fmt"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/internal/tls"
)

// Tree represents the secret tree for a group epoch.
type Tree struct {
	encryptionSecret *ciphersuite.Secret
	leafCount        uint32
	generation       uint64
}

// LeafSecret represents the secrets for a single leaf in the tree.
type LeafSecret struct {
	leafIndex      uint32
	generation     uint64
	encryptionKey  *ciphersuite.Secret
	sequenceNumber uint64
}

// NewTree creates a new secret tree from an encryption secret.
//
// encryption_secret is derived from the key schedule (RFC 9420 §8).
func NewTree(encryptionSecret *ciphersuite.Secret, leafCount uint32) (*Tree, error) {
	if encryptionSecret == nil {
		return nil, fmt.Errorf("encryption_secret is nil")
	}
	if leafCount == 0 {
		return nil, fmt.Errorf("leaf_count must be > 0")
	}

	return &Tree{
		encryptionSecret: encryptionSecret,
		leafCount:        leafCount,
		generation:       0,
	}, nil
}

// LeafCount returns the number of leaves in the tree.
func (t *Tree) LeafCount() uint32 {
	return t.leafCount
}

// Generation returns the current generation of the tree.
func (t *Tree) Generation() uint64 {
	return t.generation
}

// IncrementGeneration increments the generation counter.
//
// This is called when the group transitions to a new epoch.
func (t *Tree) IncrementGeneration() {
	t.generation++
}

// LeafForIndex returns the LeafSecret for a given leaf index.
//
// This derives the leaf secret from the encryption secret using HKDF.
func (t *Tree) LeafForIndex(leafIndex uint32) (*LeafSecret, error) {
	if leafIndex >= t.leafCount {
		return nil, fmt.Errorf("leaf index %d out of range [0, %d)", leafIndex, t.leafCount)
	}

	// Derive leaf secret: HKDF-Expand(encryption_secret, "leaf " || leaf_index, Hash.length)
	label := append([]byte("leaf "), uint32ToBytes(leafIndex)...)
	leafSecret, err := t.encryptionSecret.HKDFExpand(label, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("deriving leaf secret: %w", err)
	}

	return &LeafSecret{
		leafIndex:      leafIndex,
		generation:     t.generation,
		encryptionKey:  leafSecret,
		sequenceNumber: 0,
	}, nil
}

// EncryptionKey derives an encryption key for a message.
//
// key = HKDF-Expand(leaf_secret, "key" || generation || sequence_number, AEAD.Nk)
func (ls *LeafSecret) EncryptionKey(sequenceNumber uint64) ([]byte, error) {
	// label = "key" || generation || sequence_number
	label := append([]byte("key"), uint64ToBytes(ls.generation)...)
	label = append(label, uint64ToBytes(sequenceNumber)...)

	key, err := ls.encryptionKey.HKDFExpand(label, 16) // AES-128 key
	if err != nil {
		return nil, fmt.Errorf("deriving encryption key: %w", err)
	}

	return key.AsSlice(), nil
}

// Nonce derives a nonce for a message.
//
// nonce = HKDF-Expand(leaf_secret, "nonce" || generation || sequence_number, AEAD.Nn)
func (ls *LeafSecret) Nonce(sequenceNumber uint64) ([]byte, error) {
	// label = "nonce" || generation || sequence_number
	label := append([]byte("nonce"), uint64ToBytes(ls.generation)...)
	label = append(label, uint64ToBytes(sequenceNumber)...)

	nonce, err := ls.encryptionKey.HKDFExpand(label, 12) // AES-GCM nonce
	if err != nil {
		return nil, fmt.Errorf("deriving nonce: %w", err)
	}

	return nonce.AsSlice(), nil
}

// NextSequenceNumber returns the next sequence number and increments the counter.
func (ls *LeafSecret) NextSequenceNumber() uint64 {
	seq := ls.sequenceNumber
	ls.sequenceNumber++
	return seq
}

// SetSequenceNumber sets the sequence number.
func (ls *LeafSecret) SetSequenceNumber(seq uint64) {
	ls.sequenceNumber = seq
}

// DeleteLeaf marks a leaf as deleted by zeroing its secrets.
//
// This is used when a member is removed from the group.
func (ls *LeafSecret) DeleteLeaf() {
	// Zero out the encryption key
	if ls.encryptionKey != nil {
		// Create a zero secret
		zeroSecret := ciphersuite.ZeroSecret(ls.encryptionKey.Len())
		ls.encryptionKey = zeroSecret
	}
	ls.sequenceNumber = 0
}

// Encrypt encrypts a message using the derived key and nonce.
func (ls *LeafSecret) Encrypt(plaintext []byte, aad []byte, sequenceNumber uint64) ([]byte, error) {
	key, err := ls.EncryptionKey(sequenceNumber)
	if err != nil {
		return nil, fmt.Errorf("getting encryption key: %w", err)
	}

	nonce, err := ls.Nonce(sequenceNumber)
	if err != nil {
		return nil, fmt.Errorf("getting nonce: %w", err)
	}

	// Use AES-128-GCM to encrypt
	ciphertext, err := ciphersuite.AESEncrypt(key, nonce, plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}

	return ciphertext, nil
}

// Decrypt decrypts a message using the derived key and nonce.
func (ls *LeafSecret) Decrypt(ciphertext []byte, aad []byte, sequenceNumber uint64) ([]byte, error) {
	key, err := ls.EncryptionKey(sequenceNumber)
	if err != nil {
		return nil, fmt.Errorf("getting encryption key: %w", err)
	}

	nonce, err := ls.Nonce(sequenceNumber)
	if err != nil {
		return nil, fmt.Errorf("getting nonce: %w", err)
	}

	// Use AES-128-GCM to decrypt
	plaintext, err := ciphersuite.AESDecrypt(key, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return plaintext, nil
}

// Helper functions

func uint32ToBytes(v uint32) []byte {
	b := make([]byte, 4)
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
	return b
}

func uint64ToBytes(v uint64) []byte {
	b := make([]byte, 8)
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
	return b
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
func Unmarshal(data []byte) (*Tree, error) {
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

	encSecret := ciphersuite.NewSecret(encSecretBytes)

	return &Tree{
		encryptionSecret: encSecret,
		leafCount:        leafCount,
		generation:       generation,
	}, nil
}
