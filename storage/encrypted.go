package storage

import (
	"bytes"
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

// encryptedStateHeader prefixes every blob written by SaveGroupState: the magic "MLSE" followed
// by the format version 1. It is also part of the additional authenticated data (AAD), so the
// format version is authenticated together with the group ID.
var encryptedStateHeader = []byte{'M', 'L', 'S', 'E', 0x01}

// EncryptedStore encrypts group state before delegating persistence to another GroupStorage.
//
// The wrapped store only ever sees encrypted bytes in the form header || nonce || ciphertext.
// AES-256-GCM is used with a random nonce generated on every SaveGroupState call. The AAD is
// header || group ID, so a blob written for one group does not authenticate as the state of
// another group.
//
// Legacy blobs. LoadGroupState also accepts the legacy form nonce || ciphertext,
// which v1.6.0 and earlier wrote without AAD, so groups stored by those versions keep loading. A legacy
// blob is not bound to its group, and this layer cannot tell which group it belongs to: whoever can
// write to the inner store can move it to another group's entry, and it authenticates there. The Client
// detects the move, because the decrypted state carries its group ID, and it refuses the state
// (fail-closed). A save always writes the current format, so the legacy form disappears from a group
// once that group is saved again. When every group has been saved, WithRejectLegacyBlobs closes the
// residual at this layer too.
type EncryptedStore struct {
	inner        group.GroupStorage
	aead         cipher.AEAD
	rejectLegacy bool
}

var _ group.GroupStorage = (*EncryptedStore)(nil)

// EncryptedStoreOption configures an EncryptedStore created by NewEncryptedStore.
type EncryptedStoreOption func(*EncryptedStore)

// WithRejectLegacyBlobs makes LoadGroupState refuse every blob that does not authenticate in the current
// format for its group, which includes legacy blobs and blobs moved from another group. Legacy blobs are
// accepted by default, so enable this option only after every group has been saved again.
func WithRejectLegacyBlobs() EncryptedStoreOption {
	return func(s *EncryptedStore) {
		s.rejectLegacy = true
	}
}

// NewEncryptedStore wraps a GroupStorage with AES-256-GCM encryption at rest.
func NewEncryptedStore(inner group.GroupStorage, encryptionKey []byte, opts ...EncryptedStoreOption) (*EncryptedStore, error) {
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

	s := &EncryptedStore{inner: inner, aead: aead}
	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

// SaveGroupState encrypts the plaintext state and stores header || nonce || ciphertext in the inner store.
func (s *EncryptedStore) SaveGroupState(ctx context.Context, groupID *group.ID, state []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}
	ciphertext := s.aead.Seal(nil, nonce, state, encryptedStateAAD(groupID))
	blob := make([]byte, 0, len(encryptedStateHeader)+len(nonce)+len(ciphertext))
	blob = append(blob, encryptedStateHeader...)
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)
	return s.inner.SaveGroupState(ctx, groupID, blob)
}

// LoadGroupState loads the blob from the inner store and decrypts it. The current format is tried
// first, bound to groupID. If it does not authenticate, the legacy format without AAD is tried so
// that states saved by earlier versions keep loading, unless WithRejectLegacyBlobs is set.
func (s *EncryptedStore) LoadGroupState(ctx context.Context, groupID *group.ID) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	blob, err := s.inner.LoadGroupState(ctx, groupID)
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(blob, encryptedStateHeader) {
		plaintext, openErr := s.openGroupState(blob[len(encryptedStateHeader):], encryptedStateAAD(groupID))
		if openErr == nil {
			return plaintext, nil
		}
	}
	if s.rejectLegacy {
		return nil, fmt.Errorf("blob is not in the current format for this group, and legacy blobs are refused: %w",
			ErrInvalidCiphertext)
	}

	// A legacy blob can begin with the header bytes by chance, so the legacy attempt runs
	// whenever the current format does not authenticate.
	return s.openGroupState(blob, nil)
}

// DeleteGroupState removes the encrypted group state from the inner store.
func (s *EncryptedStore) DeleteGroupState(ctx context.Context, groupID *group.ID) error {
	return s.inner.DeleteGroupState(ctx, groupID)
}

// encryptedStateAAD returns the AAD of the current format: the header followed by the group ID.
// A nil group ID contributes no bytes; inner stores reject nil group IDs.
func encryptedStateAAD(groupID *group.ID) []byte {
	var id []byte
	if groupID != nil {
		id = groupID.AsSlice()
	}
	aad := make([]byte, 0, len(encryptedStateHeader)+len(id))
	aad = append(aad, encryptedStateHeader...)
	return append(aad, id...)
}

// openGroupState splits nonce || ciphertext and authenticates it with the given AAD.
func (s *EncryptedStore) openGroupState(sealed, aad []byte) ([]byte, error) {
	nonceSize := s.aead.NonceSize()
	if len(sealed) < nonceSize {
		return nil, ErrInvalidCiphertext
	}
	plaintext, err := s.aead.Open(nil, sealed[:nonceSize], sealed[nonceSize:], aad)
	if err != nil {
		return nil, fmt.Errorf("decrypting group state: %w", ErrInvalidCiphertext)
	}
	return plaintext, nil
}
