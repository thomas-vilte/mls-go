package mls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/storage"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

// joinTwoGroups makes bob a member, on the given storage, of two groups created by alice1 and
// alice2. It returns bob and the IDs of both groups.
func joinTwoGroups(t *testing.T, gs group.GroupStorage, ks group.KeyStore) (bob *Client, gid1, gid2 []byte) {
	t.Helper()
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMX25519
	var err error
	bob, err = NewClient([]byte("bob"), cs, WithStorage(gs, ks))
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}
	t.Cleanup(func() { _ = bob.Close() })

	join := func(identity string) []byte {
		alice, err := NewClient([]byte(identity), cs)
		if err != nil {
			t.Fatalf("NewClient(%s): %v", identity, err)
		}
		t.Cleanup(func() { _ = alice.Close() })
		gid, err := alice.CreateGroup(ctx)
		if err != nil {
			t.Fatalf("CreateGroup(%s): %v", identity, err)
		}
		kp, err := bob.FreshKeyPackageBytes(ctx)
		if err != nil {
			t.Fatalf("FreshKeyPackageBytes: %v", err)
		}
		_, welcome, err := alice.InviteMember(ctx, gid, kp)
		if err != nil {
			t.Fatalf("InviteMember(%s): %v", identity, err)
		}
		if _, err := bob.JoinGroup(ctx, welcome); err != nil {
			t.Fatalf("JoinGroup(%s): %v", identity, err)
		}
		return gid
	}
	gid1 = join("alice1")
	gid2 = join("alice2")
	return bob, gid1, gid2
}

// hasIdentity reports whether one of the members has the given identity.
func hasIdentity(members []MemberInfo, identity string) bool {
	for _, m := range members {
		if string(m.Identity) == identity {
			return true
		}
	}
	return false
}

// identitiesOf returns the identities of the members, for error messages.
func identitiesOf(members []MemberInfo) []string {
	ids := make([]string, 0, len(members))
	for _, m := range members {
		ids = append(ids, string(m.Identity))
	}
	return ids
}

// sealLegacyBlob seals state in the layout that EncryptedStore wrote before blobs named their group: nonce ||
// AES-GCM(state) with no AAD. Such a blob names no group, so nothing binds it to the group whose key holds it.
func sealLegacyBlob(t *testing.T, key, state []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return append(nonce, gcm.Seal(nil, nonce, state, nil)...)
}

// TestClientRefusesLegacyBlobOfAnotherGroup checks that the Client refuses the state of another group.
// EncryptedStore decrypts a legacy blob under any group ID, so the state of gid2 copied under the key of gid1 is
// returned as if it were gid1's. The Client refuses it, because the state names gid2. Control: gid2 still loads
// from its own state.
func TestClientRefusesLegacyBlobOfAnotherGroup(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x5A}, 32)
	inner := memorystore.NewStore()
	enc, err := storage.NewEncryptedStore(inner, key)
	if err != nil {
		t.Fatalf("NewEncryptedStore: %v", err)
	}
	bob, gid1, gid2 := joinTwoGroups(t, enc, inner)

	state2, err := enc.LoadGroupState(ctx, group.NewGroupID(gid2))
	if err != nil {
		t.Fatalf("LoadGroupState(gid2): %v", err)
	}
	if err := inner.SaveGroupState(ctx, group.NewGroupID(gid1), sealLegacyBlob(t, key, state2)); err != nil {
		t.Fatalf("SaveGroupState(legacy copy): %v", err)
	}
	if _, err := bob.ListMembers(ctx, gid1); !errors.Is(err, errStateGroupMismatch) {
		t.Errorf("ListMembers(gid1) with a legacy blob of gid2 = %v, want errStateGroupMismatch", err)
	}
	if _, err := bob.Epoch(ctx, gid1); !errors.Is(err, errStateGroupMismatch) {
		t.Errorf("Epoch(gid1) with a legacy blob of gid2 = %v, want errStateGroupMismatch", err)
	}
	members, err := bob.ListMembers(ctx, gid2)
	if err != nil {
		t.Fatalf("ListMembers(gid2) = %v, want nil", err)
	}
	if !hasIdentity(members, "alice2") {
		t.Errorf("ListMembers(gid2) = %v, want alice2 among the members", identitiesOf(members))
	}
}

// TestRefusedStateIsNotCached checks that a refused state does not stay in the cache. A Client without
// entries, as after a restart, uses CacheAlways. It refuses the state of gid2 stored under gid1 on every attempt,
// and once gid1's own state is stored again it serves gid1 from that state. Control: gid2 loads normally in the
// same Client.
func TestRefusedStateIsNotCached(t *testing.T) {
	ctx := context.Background()
	store := memorystore.NewStore()
	_, gid1, gid2 := joinTwoGroups(t, store, store)

	own1, err := store.LoadGroupState(ctx, group.NewGroupID(gid1))
	if err != nil {
		t.Fatalf("LoadGroupState(gid1): %v", err)
	}
	own1 = cloneBytes(own1)
	state2, err := store.LoadGroupState(ctx, group.NewGroupID(gid2))
	if err != nil {
		t.Fatalf("LoadGroupState(gid2): %v", err)
	}
	if err := store.SaveGroupState(ctx, group.NewGroupID(gid1), cloneBytes(state2)); err != nil {
		t.Fatalf("SaveGroupState(swap): %v", err)
	}

	cold, err := NewClient([]byte("bob"), ciphersuite.MLS128DHKEMX25519, WithStorage(store, store), WithCacheStrategy(CacheAlways))
	if err != nil {
		t.Fatalf("NewClient(cold): %v", err)
	}
	t.Cleanup(func() { _ = cold.Close() })

	if _, err := cold.ListMembers(ctx, gid2); err != nil {
		t.Fatalf("ListMembers(gid2) = %v, want nil", err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := cold.ListMembers(ctx, gid1); !errors.Is(err, errStateGroupMismatch) {
			t.Fatalf("attempt %d: ListMembers(gid1) = %v, want errStateGroupMismatch", attempt, err)
		}
	}
	if err := store.SaveGroupState(ctx, group.NewGroupID(gid1), own1); err != nil {
		t.Fatalf("SaveGroupState(restore): %v", err)
	}
	members, err := cold.ListMembers(ctx, gid1)
	if err != nil {
		t.Fatalf("ListMembers(gid1) after restoring its state = %v, want nil", err)
	}
	if !hasIdentity(members, "alice1") || hasIdentity(members, "alice2") {
		t.Errorf("ListMembers(gid1) = %v, want the members of gid1 (alice1, not alice2)", identitiesOf(members))
	}
}
