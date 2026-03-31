package file

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
)

var (
	// ErrEmptyDir is returned when NewStore receives an empty directory.
	ErrEmptyDir = errors.New("file: directory is empty")
	// ErrNilGroupID is returned when a nil group ID is passed to any Store method.
	ErrNilGroupID = errors.New("file: group ID is nil")
	// ErrNilSignatureKey is returned when a nil signature key is passed to StoreSignatureKey.
	ErrNilSignatureKey = errors.New("file: signature key is nil")
	// ErrGroupStateNotFound is returned when LoadGroupState finds no entry for the given group.
	ErrGroupStateNotFound = errors.New("file: group state not found")
	// ErrSignatureKeyNotFound is returned when LoadSignatureKey finds no entry for the given group.
	ErrSignatureKeyNotFound = errors.New("file: signature key not found")
	// ErrLeafKeyNotFound is returned when LoadLeafEncryptionKey finds no entry for the given group and leaf.
	ErrLeafKeyNotFound = errors.New("file: leaf key not found")
)

// Store persists MLS state and leaf keys under a directory on disk.
//
// Group state and leaf encryption keys are stored as files and synced to disk.
// Signature private keys remain in memory because the ciphersuite package does
// not expose a public marshal/unmarshal API for them yet.
type Store struct {
	mu      sync.RWMutex
	dir     string
	sigKeys map[string]*ciphersuite.SignaturePrivateKey
}

var (
	_ group.GroupStorage = (*Store)(nil)
	_ group.KeyStore     = (*Store)(nil)
)

// NewStore returns a file-backed Store rooted at dir.
func NewStore(dir string) (*Store, error) {
	if dir == "" {
		return nil, ErrEmptyDir
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating store directory: %w", err)
	}
	return &Store{
		dir:     dir,
		sigKeys: make(map[string]*ciphersuite.SignaturePrivateKey),
	}, nil
}

// SaveGroupState persists serialized group state for the given group ID.
func (s *Store) SaveGroupState(ctx context.Context, groupID *group.GroupID, state []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := s.groupStatePath(groupID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeFileAtomic(path, state)
}

// LoadGroupState retrieves serialized group state for the given group ID.
func (s *Store) LoadGroupState(ctx context.Context, groupID *group.GroupID) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, err := s.groupStatePath(groupID)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := os.ReadFile(path) //nolint:gosec // path is constructed from the library's own directory, not user input
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrGroupStateNotFound
		}
		return nil, fmt.Errorf("reading group state: %w", err)
	}
	return append([]byte(nil), data...), nil
}

// DeleteGroupState removes the persisted group state for the given group ID.
func (s *Store) DeleteGroupState(ctx context.Context, groupID *group.GroupID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := s.groupStatePath(groupID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("deleting group state: %w", err)
	}
	return syncDir(filepath.Dir(path))
}

// StoreSignatureKey keeps the signature private key in memory for the given group.
func (s *Store) StoreSignatureKey(ctx context.Context, groupID *group.GroupID, key *ciphersuite.SignaturePrivateKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if key == nil {
		return ErrNilSignatureKey
	}
	groupKeyValue, err := groupKey(groupID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sigKeys[groupKeyValue] = key
	return nil
}

// LoadSignatureKey retrieves the signature private key for the given group.
func (s *Store) LoadSignatureKey(ctx context.Context, groupID *group.GroupID) (*ciphersuite.SignaturePrivateKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	groupKeyValue, err := groupKey(groupID)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.sigKeys[groupKeyValue]
	if !ok {
		return nil, ErrSignatureKeyNotFound
	}
	return key, nil
}

// StoreLeafEncryptionKey persists the leaf HPKE encryption private key for the given group and leaf index.
func (s *Store) StoreLeafEncryptionKey(ctx context.Context, groupID *group.GroupID, leafIndex group.LeafNodeIndex, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := s.leafKeyPath(groupID, leafIndex)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeFileAtomic(path, key)
}

// LoadLeafEncryptionKey retrieves the leaf HPKE encryption private key for the given group and leaf index.
func (s *Store) LoadLeafEncryptionKey(ctx context.Context, groupID *group.GroupID, leafIndex group.LeafNodeIndex) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, err := s.leafKeyPath(groupID, leafIndex)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := os.ReadFile(path) //nolint:gosec // path is constructed from the library's own directory, not user input
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrLeafKeyNotFound
		}
		return nil, fmt.Errorf("reading leaf key: %w", err)
	}
	return append([]byte(nil), data...), nil
}

func (s *Store) groupStatePath(groupID *group.GroupID) (string, error) {
	key, err := groupKey(groupID)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.dir, key+".bin"), nil
}

func (s *Store) leafKeyPath(groupID *group.GroupID, leafIndex group.LeafNodeIndex) (string, error) {
	key, err := groupKey(groupID)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.dir, fmt.Sprintf("%s.leaf.%d.bin", key, uint32(leafIndex))), nil
}

func groupKey(groupID *group.GroupID) (string, error) {
	if groupID == nil {
		return "", ErrNilGroupID
	}
	return hex.EncodeToString(groupID.AsSlice()), nil
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating parent directory: %w", err)
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("syncing temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("renaming temp file: %w", err)
	}
	cleanup = false
	return syncDir(filepath.Dir(path))
}

func syncDir(dir string) error {
	f, err := os.Open(dir) //nolint:gosec // dir is constructed from the library's own base directory, not user input
	if err != nil {
		return fmt.Errorf("opening directory for sync: %w", err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("syncing directory: %w", err)
	}
	return nil
}
