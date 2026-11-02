package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
)

// TestDeleteLeafEncryptionKeysOnlyDeletesOneGroup checks that DeleteLeafEncryptionKeys removes the leaf keys
// and the signature key of one group only. The second group ID is a hex prefix of the first, so the key
// prefixes must not collide.
func TestDeleteLeafEncryptionKeysOnlyDeletesOneGroup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewStore()
	sigKey, err := ciphersuite.GenerateSignaturePrivateKeyForCS(ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating signature key: %v", err)
	}
	gone := group.NewGroupID([]byte{0x0a})
	kept := group.NewGroupID([]byte{0x0a, 0x0b})
	for _, gid := range []*group.ID{gone, kept} {
		if err := store.StoreSignatureKey(ctx, gid, sigKey); err != nil {
			t.Fatalf("StoreSignatureKey: %v", err)
		}
		for leaf := group.LeafNodeIndex(0); leaf < 2; leaf++ {
			if err := store.StoreLeafEncryptionKey(ctx, gid, leaf, []byte{byte(leaf) + 1}); err != nil {
				t.Fatalf("StoreLeafEncryptionKey: %v", err)
			}
		}
	}

	if err := store.DeleteLeafEncryptionKeys(ctx, gone); err != nil {
		t.Fatalf("DeleteLeafEncryptionKeys: %v", err)
	}

	for leaf := group.LeafNodeIndex(0); leaf < 2; leaf++ {
		if _, err := store.LoadLeafEncryptionKey(ctx, gone, leaf); !errors.Is(err, ErrLeafKeyNotFound) {
			t.Errorf("deleted group, leaf %d: LoadLeafEncryptionKey err = %v, want ErrLeafKeyNotFound", leaf, err)
		}
	}
	if _, err := store.LoadSignatureKey(ctx, gone); !errors.Is(err, ErrSignatureKeyNotFound) {
		t.Errorf("deleted group: LoadSignatureKey err = %v, want ErrSignatureKeyNotFound", err)
	}

	for leaf := group.LeafNodeIndex(0); leaf < 2; leaf++ {
		got, err := store.LoadLeafEncryptionKey(ctx, kept, leaf)
		if err != nil || len(got) != 1 || got[0] != byte(leaf)+1 {
			t.Errorf("kept group, leaf %d: LoadLeafEncryptionKey = %x, %v; want the stored key", leaf, got, err)
		}
	}
	if _, err := store.LoadSignatureKey(ctx, kept); err != nil {
		t.Errorf("kept group: LoadSignatureKey: %v", err)
	}
}
