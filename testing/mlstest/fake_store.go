package mlstest

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
	ErrGroupStateNotFound   = errors.New("mlstest: group state not found")
	ErrSignatureKeyNotFound = errors.New("mlstest: signature key not found")
	ErrLeafKeyNotFound      = errors.New("mlstest: leaf key not found")
)

// FakeStore is a failure-injectable in-memory implementation of GroupStorage and KeyStore.
type FakeStore struct {
	mu sync.RWMutex

	FailSave      bool
	FailLoad      bool
	FailDelete    bool
	FailStoreSig  bool
	FailLoadSig   bool
	FailStoreLeaf bool
	FailLoadLeaf  bool

	SaveErr      error
	LoadErr      error
	DeleteErr    error
	StoreSigErr  error
	LoadSigErr   error
	StoreLeafErr error
	LoadLeafErr  error

	groups   map[string][]byte
	sigKeys  map[string]*ciphersuite.SignaturePrivateKey
	leafKeys map[string][]byte

	SaveCalls      int
	LoadCalls      int
	DeleteCalls    int
	StoreSigCalls  int
	LoadSigCalls   int
	StoreLeafCalls int
	LoadLeafCalls  int
}

var (
	_ group.GroupStorage = (*FakeStore)(nil)
	_ group.KeyStore     = (*FakeStore)(nil)
)

func NewFakeStore() *FakeStore {
	return &FakeStore{
		groups:   make(map[string][]byte),
		sigKeys:  make(map[string]*ciphersuite.SignaturePrivateKey),
		leafKeys: make(map[string][]byte),
	}
}

func (s *FakeStore) SaveGroupState(ctx context.Context, groupID *group.GroupID, state []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.FailSave {
		if s.SaveErr != nil {
			return s.SaveErr
		}
		return errors.New("mlstest: save failed")
	}
	key, err := fakeGroupKey(groupID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.SaveCalls++
	s.groups[key] = append([]byte(nil), state...)
	return nil
}

func (s *FakeStore) LoadGroupState(ctx context.Context, groupID *group.GroupID) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.FailLoad {
		if s.LoadErr != nil {
			return nil, s.LoadErr
		}
		return nil, errors.New("mlstest: load failed")
	}
	key, err := fakeGroupKey(groupID)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LoadCalls++
	state, ok := s.groups[key]
	if !ok {
		return nil, ErrGroupStateNotFound
	}
	return append([]byte(nil), state...), nil
}

func (s *FakeStore) DeleteGroupState(ctx context.Context, groupID *group.GroupID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.FailDelete {
		if s.DeleteErr != nil {
			return s.DeleteErr
		}
		return errors.New("mlstest: delete failed")
	}
	key, err := fakeGroupKey(groupID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DeleteCalls++
	delete(s.groups, key)
	return nil
}

func (s *FakeStore) StoreSignatureKey(ctx context.Context, groupID *group.GroupID, key *ciphersuite.SignaturePrivateKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.FailStoreSig {
		if s.StoreSigErr != nil {
			return s.StoreSigErr
		}
		return errors.New("mlstest: store signature key failed")
	}
	groupKeyValue, err := fakeGroupKey(groupID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.StoreSigCalls++
	s.sigKeys[groupKeyValue] = key
	return nil
}

func (s *FakeStore) LoadSignatureKey(ctx context.Context, groupID *group.GroupID) (*ciphersuite.SignaturePrivateKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.FailLoadSig {
		if s.LoadSigErr != nil {
			return nil, s.LoadSigErr
		}
		return nil, errors.New("mlstest: load signature key failed")
	}
	groupKeyValue, err := fakeGroupKey(groupID)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LoadSigCalls++
	key, ok := s.sigKeys[groupKeyValue]
	if !ok {
		return nil, ErrSignatureKeyNotFound
	}
	return key, nil
}

func (s *FakeStore) StoreLeafEncryptionKey(ctx context.Context, groupID *group.GroupID, leafIndex group.LeafNodeIndex, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.FailStoreLeaf {
		if s.StoreLeafErr != nil {
			return s.StoreLeafErr
		}
		return errors.New("mlstest: store leaf key failed")
	}
	leafKeyValue, err := fakeLeafKey(groupID, leafIndex)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.StoreLeafCalls++
	s.leafKeys[leafKeyValue] = append([]byte(nil), key...)
	return nil
}

func (s *FakeStore) LoadLeafEncryptionKey(ctx context.Context, groupID *group.GroupID, leafIndex group.LeafNodeIndex) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.FailLoadLeaf {
		if s.LoadLeafErr != nil {
			return nil, s.LoadLeafErr
		}
		return nil, errors.New("mlstest: load leaf key failed")
	}
	leafKeyValue, err := fakeLeafKey(groupID, leafIndex)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LoadLeafCalls++
	key, ok := s.leafKeys[leafKeyValue]
	if !ok {
		return nil, ErrLeafKeyNotFound
	}
	return append([]byte(nil), key...), nil
}

func fakeGroupKey(groupID *group.GroupID) (string, error) {
	if groupID == nil {
		return "", errors.New("mlstest: group ID is nil")
	}
	return hex.EncodeToString(groupID.AsSlice()), nil
}

func fakeLeafKey(groupID *group.GroupID, leafIndex group.LeafNodeIndex) (string, error) {
	groupKeyValue, err := fakeGroupKey(groupID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%d", groupKeyValue, uint32(leafIndex)), nil
}
