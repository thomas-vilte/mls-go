package group

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// TestBranchDoesNotAliasResumptionSecret checks that Branch gives the branch group its own copy of the
// old group's resumption secret. LoadPsk keeps the slice it is given, so a branch that cached the live slice
// would share bytes with the epoch secrets of the old group. Erasing those secrets (EpochSecrets().Zero, or a
// caller that scrubs them) would then silently change the PSK used by the branch's first commit. Branch keeps
// its own copy, as the other resumption-secret caches do.
func TestBranchDoesNotAliasResumptionSecret(t *testing.T) {
	cred, _, err := credentials.GenerateCredentialWithKey([]byte("Alice"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey: %v", err)
	}
	kp, kpPriv, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	groupID, _ := NewGroupIDRandom()
	oldGroup, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kp, kpPriv)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}

	branchCred, _, err := credentials.GenerateCredentialWithKey([]byte("Alice-branch"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(branch): %v", err)
	}
	branchKP, branchPriv, err := keypackages.Generate(branchCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate(branch): %v", err)
	}
	branch, err := Branch(oldGroup, branchKP, branchPriv, nil)
	if err != nil {
		t.Fatalf("Branch: %v", err)
	}

	key := ResumptionPskCacheKey(oldGroup.groupID.AsSlice(), oldGroup.epoch.AsUint64())
	want, ok := branch.cachedPsk(key)
	if !ok || len(want) == 0 {
		t.Fatalf("branch has no cached resumption PSK under its branch key")
	}
	saved := append([]byte(nil), want...)

	// Erase the old epoch's resumption secret in place, as EpochSecrets().Zero does.
	oldGroup.epochSecrets.ResumptionSecret.SecureZero()

	got, _ := branch.cachedPsk(key)
	if !bytes.Equal(got, saved) {
		t.Fatalf("branch PSK changed to %x after the old group's resumption secret was erased; the branch must keep its own copy", got)
	}
}
