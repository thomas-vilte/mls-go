package group

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// mapPSKStore is a trivial PSKStore implementation for tests.
type mapPSKStore struct {
	m map[string][]byte
}

func newMapPSKStore() *mapPSKStore { return &mapPSKStore{m: make(map[string][]byte)} }

func (s *mapPSKStore) GetPSK(id []byte) ([]byte, error) {
	v, ok := s.m[string(id)]
	if !ok {
		return nil, fmt.Errorf("PSK not found: %x", id)
	}
	return v, nil
}

func TestPSKResolver_ExternalPSK(t *testing.T) {
	store := newMapPSKStore()
	pskID := []byte("my-external-psk")
	secret := []byte("super-secret-bytes")
	store.m[string(pskID)] = secret

	resolver := NewPSKResolver(store)
	got, err := resolver.ResolvePSK(&PskID{PskType: 1, ID: pskID})
	if err != nil {
		t.Fatalf("ResolvePSK external: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Errorf("got %x, want %x", got, secret)
	}
}

func TestPSKResolver_ResumptionPSK(t *testing.T) {
	store := newMapPSKStore()
	groupID := []byte{0x01, 0x02, 0x03, 0x04}
	epoch := uint64(42)
	secret := []byte("resumption-secret")

	// La clave compuesta que PSKResolver genera es groupID || epoch (big-endian 8 bytes).
	compoundKey := make([]byte, len(groupID)+8)
	copy(compoundKey, groupID)
	for i := 7; i >= 0; i-- {
		compoundKey[len(groupID)+i] = byte(epoch >> (8 * (7 - i)))
	}
	store.m[string(compoundKey)] = secret

	resolver := NewPSKResolver(store)
	got, err := resolver.ResolvePSK(&PskID{PskType: 2, PskGroupID: groupID, PskEpoch: epoch})
	if err != nil {
		t.Fatalf("ResolvePSK resumption: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Errorf("got %x, want %x", got, secret)
	}
}

func TestPSKResolver_BranchPSK(t *testing.T) {
	store := newMapPSKStore()
	id := []byte("branch-id")
	secret := []byte("branch-secret")
	store.m[string(id)] = secret

	resolver := NewPSKResolver(store)
	got, err := resolver.ResolvePSK(&PskID{PskType: 3, ID: id})
	if err != nil {
		t.Fatalf("ResolvePSK branch: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Errorf("got %x, want %x", got, secret)
	}
}

func TestPSKResolver_UnknownType(t *testing.T) {
	resolver := NewPSKResolver(newMapPSKStore())
	if _, err := resolver.ResolvePSK(&PskID{PskType: 99}); err == nil {
		t.Error("expected error for unsupported PSK type")
	}
}

func TestPSKResolver_NilID(t *testing.T) {
	resolver := NewPSKResolver(newMapPSKStore())
	if _, err := resolver.ResolvePSK(nil); err == nil {
		t.Error("expected error for nil PskID")
	}
}

func TestPSKResolver_NotFound(t *testing.T) {
	resolver := NewPSKResolver(newMapPSKStore())
	_, err := resolver.ResolvePSK(&PskID{PskType: 1, ID: []byte("missing")})
	if err == nil {
		t.Error("expected error when PSK not in store")
	}
}

func TestLoadPsk_StoresAndRetrieves(t *testing.T) {
	cred, _, err := credentials.GenerateCredentialWithKey([]byte("alice"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey: %v", err)
	}
	kp, priv, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	gid, _ := NewGroupIDRandom()
	g, err := NewGroup(gid, ciphersuite.MLS128DHKEMP256, kp, priv)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}

	id := []byte("test-psk-id")
	secret := []byte("test-psk-secret")
	g.LoadPsk(id, secret)

	got, ok := g.cachedPsks[string(id)]
	if !ok {
		t.Fatal("LoadPsk did not store PSK in CachedPsks")
	}
	if !bytes.Equal(got, secret) {
		t.Errorf("stored PSK = %x, want %x", got, secret)
	}
}

func TestGroup_PSKStore_SetAndGet(t *testing.T) {
	cred, _, err := credentials.GenerateCredentialWithKey([]byte("alice"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey: %v", err)
	}
	kp, priv, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	gid, _ := NewGroupIDRandom()
	g, err := NewGroup(gid, ciphersuite.MLS128DHKEMP256, kp, priv)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}

	store := newMapPSKStore()
	store.m["key"] = []byte("val")
	g.PSKStore = store

	if g.PSKStore == nil {
		t.Fatal("PSKStore should be set")
	}
	got, err := g.PSKStore.GetPSK([]byte("key"))
	if err != nil {
		t.Fatalf("GetPSK: %v", err)
	}
	if !bytes.Equal(got, []byte("val")) {
		t.Errorf("got %x, want val", got)
	}
}
