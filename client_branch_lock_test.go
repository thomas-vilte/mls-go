package mls

import (
	"bytes"
	"context"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
)

// branchLockProbe records whether the source entry lock is free during validation.
type branchLockProbe struct {
	entry    *groupEntry
	identity []byte
	calls    int
	unlocked int
}

func (p *branchLockProbe) ValidateCredential(_ context.Context, cred *credentials.Credential) error {
	if !bytes.Equal(cred.Identity, p.identity) {
		return nil
	}
	p.calls++
	if p.entry.mu.TryLock() {
		p.unlocked++
		p.entry.mu.Unlock()
	}
	return nil
}

func TestClientBranchHoldsSourceLock(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	cs := ciphersuite.MLS128DHKEMP256
	bobIdentity := []byte("bob")
	probe := &branchLockProbe{identity: bobIdentity}

	alice, err := NewClient(
		[]byte("alice"),
		cs,
		WithCacheStrategy(CacheAlways),
		WithCredentialValidator(probe),
	)
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	t.Cleanup(func() {
		if err := alice.Close(); err != nil {
			t.Errorf("Close(alice): %v", err)
		}
	})

	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	alice.mu.Lock()
	probe.entry = alice.groupEntries[groupCacheKeyBytes(groupID)]
	alice.mu.Unlock()
	if probe.entry == nil {
		t.Fatal("CreateGroup did not register an entry")
	}

	bob, err := NewClient(bobIdentity, cs)
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}
	t.Cleanup(func() {
		if err := bob.Close(); err != nil {
			t.Errorf("Close(bob): %v", err)
		}
	})

	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes: %v", err)
	}

	if _, _, _, err := alice.Branch(ctx, groupID, [][]byte{bobKP}); err != nil {
		t.Fatalf("Branch: %v", err)
	}
	if probe.calls == 0 {
		t.Fatal("validator was not called for the other member's KeyPackage")
	}
	if probe.unlocked > 0 {
		t.Fatalf("credential validation ran without the source entry lock in %d of %d calls",
			probe.unlocked, probe.calls)
	}
}
