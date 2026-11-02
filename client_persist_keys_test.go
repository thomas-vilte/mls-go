package mls

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

// writeCountingStore is an in-memory store that counts the writes persistGroup makes.
type writeCountingStore struct {
	*memorystore.Store
	saveState int
	storeSig  int
	storeLeaf int
}

func (s *writeCountingStore) SaveGroupState(ctx context.Context, groupID *group.ID, state []byte) error {
	s.saveState++
	return s.Store.SaveGroupState(ctx, groupID, state)
}

func (s *writeCountingStore) StoreSignatureKey(ctx context.Context, groupID *group.ID, key *ciphersuite.SignaturePrivateKey) error {
	s.storeSig++
	return s.Store.StoreSignatureKey(ctx, groupID, key)
}

func (s *writeCountingStore) StoreLeafEncryptionKey(ctx context.Context, groupID *group.ID, leafIndex group.LeafNodeIndex, key []byte) error {
	s.storeLeaf++
	return s.Store.StoreLeafEncryptionKey(ctx, groupID, leafIndex, key)
}

// reset zeroes the write counters.
func (s *writeCountingStore) reset() {
	s.saveState, s.storeSig, s.storeLeaf = 0, 0, 0
}

// wantStoreWrites fails the test unless the writes counted since the last reset are the expected ones.
func wantStoreWrites(t *testing.T, store *writeCountingStore, op string, state, sig, leaf int) {
	t.Helper()
	if store.saveState != state || store.storeSig != sig || store.storeLeaf != leaf {
		t.Fatalf("%s: SaveGroupState=%d StoreSignatureKey=%d StoreLeafEncryptionKey=%d, want %d, %d, %d",
			op, store.saveState, store.storeSig, store.storeLeaf, state, sig, leaf)
	}
}

// checkStoredLeafKey fails the test unless the leaf key in the store is the leaf key of the stored group state.
func checkStoredLeafKey(t *testing.T, store *writeCountingStore, groupID []byte) {
	t.Helper()
	ctx := context.Background()
	gid := group.NewGroupID(groupID)
	state, err := store.LoadGroupState(ctx, gid)
	if err != nil {
		t.Fatalf("LoadGroupState: %v", err)
	}
	g, err := group.UnmarshalGroupState(state)
	if err != nil {
		t.Fatalf("UnmarshalGroupState: %v", err)
	}
	stored, err := store.LoadLeafEncryptionKey(ctx, gid, g.OwnLeafIndex())
	if err != nil {
		t.Fatalf("LoadLeafEncryptionKey: %v", err)
	}
	if !bytes.Equal(stored, g.MyLeafEncryptionKey()) {
		t.Fatalf("leaf key in the store differs from the leaf key of the stored group state")
	}
}

// expectDecryptedMessages fails the test unless receiver decrypts cts[i] to want[i] for every i.
func expectDecryptedMessages(ctx context.Context, t *testing.T, receiver *Client, groupID []byte, cts [][]byte, want []string) {
	t.Helper()
	for i, ct := range cts {
		rm, err := receiver.ReceiveMessage(ctx, groupID, ct)
		if err != nil {
			t.Fatalf("ReceiveMessage(%d): %v", i, err)
		}
		if string(rm.Plaintext) != want[i] {
			t.Fatalf("ReceiveMessage(%d) = %q, want %q", i, rm.Plaintext, want[i])
		}
	}
}

// TestPersistGroupWritesKeysOnlyWhenNeeded checks when persistGroup writes the signature key and the leaf key.
// The group state is saved by every operation, the signature key once per group entry, and the leaf key only
// when it changes or the entry has not written it yet. With the file store, each extra key write costs two
// fsyncs (file and directory).
func TestPersistGroupWritesKeysOnlyWhenNeeded(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	cases := []struct {
		name     string
		strategy CacheStrategy
	}{
		{"CacheNone", CacheNone},
		{"CacheAlways", CacheAlways},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			certDER, certKey := generateTestCertificate(t)
			store := &writeCountingStore{Store: memorystore.NewStore()}
			// The X.509 credential is part of the options so that a Client started over the same
			// store has the same signature key and can keep operating on the group.
			aliceOpts := []ClientOption{
				WithStorage(store, store),
				WithCacheStrategy(tc.strategy),
				WithX509Credential(certDER, certKey),
			}
			alice, err := NewClient([]byte("alice-persist"), cs, aliceOpts...)
			if err != nil {
				t.Fatalf("NewClient(alice): %v", err)
			}
			defer func() { _ = alice.Close() }()
			bob, err := NewClient([]byte("bob-persist"), cs, WithCacheStrategy(tc.strategy))
			if err != nil {
				t.Fatalf("NewClient(bob): %v", err)
			}
			defer func() { _ = bob.Close() }()

			gid, err := alice.CreateGroup(ctx)
			if err != nil {
				t.Fatalf("CreateGroup: %v", err)
			}
			bobKP, err := bob.FreshKeyPackageBytes(ctx)
			if err != nil {
				t.Fatalf("FreshKeyPackageBytes: %v", err)
			}
			_, welcome, err := alice.InviteMember(ctx, gid, bobKP)
			if err != nil {
				t.Fatalf("InviteMember: %v", err)
			}
			if _, err := bob.JoinGroup(ctx, welcome); err != nil {
				t.Fatalf("JoinGroup: %v", err)
			}

			// Ten messages rewrite the group state and nothing else.
			store.reset()
			const msgs = 10
			cts := make([][]byte, 0, msgs)
			want := make([]string, 0, msgs)
			for i := 0; i < msgs; i++ {
				want = append(want, fmt.Sprintf("msg-%d", i))
				ct, err := alice.SendMessage(ctx, gid, []byte(want[i]))
				if err != nil {
					t.Fatalf("SendMessage(%d): %v", i, err)
				}
				cts = append(cts, ct)
			}
			wantStoreWrites(t, store, "10 SendMessage", msgs, 0, 0)
			expectDecryptedMessages(ctx, t, bob, gid, cts, want)

			// A commit rotates the leaf key, so the new key is written once, with the new state.
			store.reset()
			commit, err := alice.SelfUpdate(ctx, gid)
			if err != nil {
				t.Fatalf("SelfUpdate: %v", err)
			}
			wantStoreWrites(t, store, "SelfUpdate", 1, 0, 1)
			checkStoredLeafKey(t, store, gid)
			if err := bob.ProcessCommit(ctx, gid, commit); err != nil {
				t.Fatalf("bob.ProcessCommit(SelfUpdate): %v", err)
			}

			// A Client started over on the same store has no entries. Its first operation writes the
			// signature key and the leaf key once, the next ones do not, and the state stays correct.
			restarted, err := NewClient([]byte("alice-persist"), cs, aliceOpts...)
			if err != nil {
				t.Fatalf("NewClient(restarted): %v", err)
			}
			defer func() { _ = restarted.Close() }()
			store.reset()
			ct1, err := restarted.SendMessage(ctx, gid, []byte("after restart 1"))
			if err != nil {
				t.Fatalf("SendMessage after restart: %v", err)
			}
			wantStoreWrites(t, store, "first SendMessage after restart", 1, 1, 1)
			store.reset()
			ct2, err := restarted.SendMessage(ctx, gid, []byte("after restart 2"))
			if err != nil {
				t.Fatalf("second SendMessage after restart: %v", err)
			}
			wantStoreWrites(t, store, "second SendMessage after restart", 1, 0, 0)
			expectDecryptedMessages(ctx, t, bob, gid, [][]byte{ct1, ct2}, []string{"after restart 1", "after restart 2"})

			store.reset()
			commit2, err := restarted.SelfUpdate(ctx, gid)
			if err != nil {
				t.Fatalf("SelfUpdate after restart: %v", err)
			}
			wantStoreWrites(t, store, "SelfUpdate after restart", 1, 0, 1)
			checkStoredLeafKey(t, store, gid)
			if err := bob.ProcessCommit(ctx, gid, commit2); err != nil {
				t.Fatalf("bob.ProcessCommit(SelfUpdate after restart): %v", err)
			}
		})
	}
}
