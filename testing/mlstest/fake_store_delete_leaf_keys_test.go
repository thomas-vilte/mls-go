package mlstest

import (
	"context"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
)

// TestFakeStoreDeleteLeafEncryptionKeys checks that FakeStore deletes the leaf keys and the signature key of
// the given group, and honors FailDeleteLeaf and DeleteLeafErr like its other methods.
func TestFakeStoreDeleteLeafEncryptionKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fake := NewFakeStore()
	gid := group.NewGroupID([]byte{0x01, 0x02})
	sigKey, err := ciphersuite.GenerateSignaturePrivateKeyForCS(ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("generating signature key: %v", err)
	}
	if err := fake.StoreSignatureKey(ctx, gid, sigKey); err != nil {
		t.Fatalf("StoreSignatureKey: %v", err)
	}
	if err := fake.StoreLeafEncryptionKey(ctx, gid, 1, []byte("leaf")); err != nil {
		t.Fatalf("StoreLeafEncryptionKey: %v", err)
	}

	errDelete := errors.New("mlstest: injected leaf key deletion failure")
	fake.FailDeleteLeaf = true
	fake.DeleteLeafErr = errDelete
	if err := fake.DeleteLeafEncryptionKeys(ctx, gid); !errors.Is(err, errDelete) {
		t.Fatalf("DeleteLeafEncryptionKeys with FailDeleteLeaf = %v, want the injected error", err)
	}
	if _, err := fake.LoadLeafEncryptionKey(ctx, gid, 1); err != nil {
		t.Fatalf("failed deletion removed the leaf key: %v", err)
	}

	fake.FailDeleteLeaf = false
	if err := fake.DeleteLeafEncryptionKeys(ctx, gid); err != nil {
		t.Fatalf("DeleteLeafEncryptionKeys: %v", err)
	}
	if _, err := fake.LoadLeafEncryptionKey(ctx, gid, 1); !errors.Is(err, ErrLeafKeyNotFound) {
		t.Errorf("LoadLeafEncryptionKey after delete = %v, want ErrLeafKeyNotFound", err)
	}
	if _, err := fake.LoadSignatureKey(ctx, gid); !errors.Is(err, ErrSignatureKeyNotFound) {
		t.Errorf("LoadSignatureKey after delete = %v, want ErrSignatureKeyNotFound", err)
	}
	if fake.DeleteLeafCalls != 1 {
		t.Errorf("DeleteLeafCalls = %d, want 1 (the injected failure is not counted)", fake.DeleteLeafCalls)
	}
}
