package memory

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
)

var (
	// ErrNilGroupID is returned when a nil group ID is passed to any Store method.
	ErrNilGroupID = errors.New("memory: group ID is nil")
	// ErrNilSignatureKey is returned when a nil signature key is passed to StoreSignatureKey.
	ErrNilSignatureKey = errors.New("memory: signature key is nil")
	// ErrGroupStateNotFound is returned when LoadGroupState finds no entry for the given group.
	ErrGroupStateNotFound = errors.New("memory: group state not found")
	// ErrSignatureKeyNotFound is returned when LoadSignatureKey finds no entry for the given group.
	ErrSignatureKeyNotFound = errors.New("memory: signature key not found")
	// ErrLeafKeyNotFound is returned when LoadLeafEncryptionKey finds no entry for the given group and leaf.
	ErrLeafKeyNotFound = errors.New("memory: leaf encryption key not found")
)

// Store implements group.GroupStorage and group.KeyStore.
//
// Group State is stored as serialized bytes. Signature keys are kept in memory as
// key objects because ciphersuite.SignaturePrivateKey does not currently expose a
// public marshal/unmarshal API.
type Store struct {
	mu       sync.RWMutex
	groups   map[string][]byte
	sigKeys  map[string]*ciphersuite.SignaturePrivateKey
	leafKeys map[string][]byte
}

var (
	_ group.GroupStorage = (*Store)(nil)
	_ group.KeyStore     = (*Store)(nil)
)

// NewStore returns an empty, ready-to-use in-memory Store.
func NewStore() *Store {
	return &Store{
		groups:   make(map[string][]byte),
		sigKeys:  make(map[string]*ciphersuite.SignaturePrivateKey),
		leafKeys: make(map[string][]byte),
	}
}

// SaveGroupState persists serialized group state for the given group ID.
func (s *Store) SaveGroupState(ctx context.Context, groupID *group.GroupID, state []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := groupKey(groupID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groups[key] = append([]byte(nil), state...)
	return nil
}

// LoadGroupState retrieves serialized group state for the given group ID.
func (s *Store) LoadGroupState(ctx context.Context, groupID *group.GroupID) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, err := groupKey(groupID)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.groups[key]
	if !ok {
		return nil, ErrGroupStateNotFound
	}
	return append([]byte(nil), state...), nil
}

// DeleteGroupState removes the persisted group state for the given group ID.
func (s *Store) DeleteGroupState(ctx context.Context, groupID *group.GroupID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := groupKey(groupID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.groups, key)
	return nil
}

// StoreSignatureKey persists the signature private key for the given group.
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
	leafKeyValue, err := leafKey(groupID, leafIndex)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leafKeys[leafKeyValue] = append([]byte(nil), key...)
	return nil
}

// LoadLeafEncryptionKey retrieves the leaf HPKE encryption private key for the given group and leaf index.
func (s *Store) LoadLeafEncryptionKey(ctx context.Context, groupID *group.GroupID, leafIndex group.LeafNodeIndex) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	leafKeyValue, err := leafKey(groupID, leafIndex)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.leafKeys[leafKeyValue]
	if !ok {
		return nil, ErrLeafKeyNotFound
	}
	return append([]byte(nil), key...), nil
}

func groupKey(groupID *group.GroupID) (string, error) {
	if groupID == nil {
		return "", ErrNilGroupID
	}
	return hex.EncodeToString(groupID.AsSlice()), nil
}

func leafKey(groupID *group.GroupID, leafIndex group.LeafNodeIndex) (string, error) {
	groupKeyValue, err := groupKey(groupID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%d", groupKeyValue, uint32(leafIndex)), nil
}
