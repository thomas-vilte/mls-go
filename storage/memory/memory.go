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
	ErrNilGroupID           = errors.New("memory: group ID is nil")
	ErrNilSignatureKey      = errors.New("memory: signature key is nil")
	ErrGroupStateNotFound   = errors.New("memory: group state not found")
	ErrSignatureKeyNotFound = errors.New("memory: signature key not found")
	ErrLeafKeyNotFound      = errors.New("memory: leaf encryption key not found")
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

func NewStore() *Store {
	return &Store{
		groups:   make(map[string][]byte),
		sigKeys:  make(map[string]*ciphersuite.SignaturePrivateKey),
		leafKeys: make(map[string][]byte),
	}
}

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
