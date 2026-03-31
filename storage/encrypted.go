package storage

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/thomas-vilte/mls-go/group"
)

var (
	// ErrNilInnerStore is returned when NewEncryptedStore receives a nil inner store.
	ErrNilInnerStore = errors.New("storage: inner store is nil")
	// ErrInvalidEncryptionKey is returned when the encryption key is not 32 bytes.
	ErrInvalidEncryptionKey = errors.New("storage: encryption key must be 32 bytes")
	// ErrInvalidCiphertext is returned when stored ciphertext is malformed.
	ErrInvalidCiphertext = errors.New("storage: invalid ciphertext")
)

// EncryptedStore encrypts group state before delegating persistence to another GroupStorage.
//
// The wrapped store only ever sees encrypted bytes in the form nonce || ciphertext.
// AES-256-GCM is used with a random nonce generated on every SaveGroupState call.
type EncryptedStore struct {
	inner group.GroupStorage
	aead  cipher.AEAD
}

var _ group.GroupStorage = (*EncryptedStore)(nil)

// NewEncryptedStore wraps a GroupStorage with AES-256-GCM encryption at rest.
func NewEncryptedStore(inner group.GroupStorage, encryptionKey []byte) (*EncryptedStore, error) {
	if inner == nil {
		return nil, ErrNilInnerStore
	}
	if len(encryptionKey) != 32 {
		return nil, ErrInvalidEncryptionKey
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM AEAD: %w", err)
	}
	return &EncryptedStore{inner: inner, aead: aead}, nil
}

// SaveGroupState encrypts the plaintext state and stores nonce || ciphertext in the inner store.
func (s *EncryptedStore) SaveGroupState(ctx context.Context, groupID *group.GroupID, state []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}
	ciphertext := s.aead.Seal(nil, nonce, state, nil)
	blob := make([]byte, 0, len(nonce)+len(ciphertext))
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)
	return s.inner.SaveGroupState(ctx, groupID, blob)
}

// LoadGroupState loads nonce || ciphertext from the inner store and decrypts it.
func (s *EncryptedStore) LoadGroupState(ctx context.Context, groupID *group.GroupID) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	blob, err := s.inner.LoadGroupState(ctx, groupID)
	if err != nil {
		return nil, err
	}
	nonceSize := s.aead.NonceSize()
	if len(blob) < nonceSize {
		return nil, ErrInvalidCiphertext
	}
	nonce := blob[:nonceSize]
	ciphertext := blob[nonceSize:]
	plaintext, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting group state: %w", ErrInvalidCiphertext)
	}
	return plaintext, nil
}

// DeleteGroupState removes the encrypted group state from the inner store.
func (s *EncryptedStore) DeleteGroupState(ctx context.Context, groupID *group.GroupID) error {
	return s.inner.DeleteGroupState(ctx, groupID)
}
