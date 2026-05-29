package group

// Tests for the epoch history eviction fix.
//
// Previously, cacheOldEpoch guarded eviction behind:
//
//	if oldEpoch >= maxCachedEpochs { ... }
//
// so the map grew unboundedly for epochs 0–(maxCachedEpochs-1).
// The fix removes the guard and uses a saturating subtraction so eviction
// runs from epoch 0 onwards.
//
// Run:
//
//	go test -run TestEpochHistory ./group/...

import (
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// newSingleMemberGroup is a test helper that creates an operational one-member
// group with a freshly generated credential and key package.
func newSingleMemberGroup(t *testing.T, identity string) (*Group, *keypackages.KeyPackagePrivateKeys) {
	t.Helper()
	credWithKey, _, err := credentials.GenerateCredentialWithKey([]byte(identity))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(%q): %v", identity, err)
	}
	kp, kpPriv, err := keypackages.Generate(credWithKey, ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("keypackages.Generate: %v", err)
	}
	groupID, err := NewGroupIDRandom()
	if err != nil {
		t.Fatalf("NewGroupIDRandom: %v", err)
	}
	g, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kp, kpPriv)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	return g, kpPriv
}

// advanceEpoch commits a self-update on g, advancing it by one epoch.
// This is the simplest way to trigger cacheOldEpoch via MergeCommit.
func advanceEpoch(t *testing.T, g *Group, privKeys *keypackages.KeyPackagePrivateKeys) {
	t.Helper()
	sigPriv := ciphersuite.NewSignaturePrivateKey(privKeys.SignatureKey)
	sigPub := sigPriv.PublicKey()

	if _, err := g.SelfUpdate(sigPriv); err != nil {
		t.Fatalf("SelfUpdate: %v", err)
	}
	staged, err := g.Commit(sigPriv, sigPub, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := g.MergeCommit(staged); err != nil {
		t.Fatalf("MergeCommit: %v", err)
	}
}

// TestEpochHistory_SizeBoundedFromEpochZero is the primary regression test.
//
// It drives a group through maxCachedEpochs+3 epochs and asserts that
// len(epochHistory) never exceeds maxCachedEpochs at any point - including
// during the first maxCachedEpochs-1 epochs where the old guard prevented
// eviction.
func TestEpochHistory_SizeBoundedFromEpochZero(t *testing.T) {
	t.Parallel()

	g, privKeys := newSingleMemberGroup(t, "alice")

	totalEpochs := maxCachedEpochs + 3

	for i := 0; i < totalEpochs; i++ {
		advanceEpoch(t, g, privKeys)

		currentEpoch := g.Epoch().AsUint64()
		historySize := len(g.epochHistory)

		if historySize > maxCachedEpochs {
			t.Errorf(
				"after advancing to epoch %d: epochHistory size = %d, want ≤ %d - "+
					"eviction is not running correctly",
				currentEpoch, historySize, maxCachedEpochs,
			)
		}
	}
}

// TestEpochHistory_NeverExceedsMaxDuringEarlyEpochs specifically targets epochs
// 1 through maxCachedEpochs-1, which were the ones the old guard skipped.
// Before the fix, the map would grow to {epoch 0, epoch 1, ..., epoch N} without
// any eviction occurring.
func TestEpochHistory_NeverExceedsMaxDuringEarlyEpochs(t *testing.T) {
	t.Parallel()

	g, privKeys := newSingleMemberGroup(t, "alice")

	// Advance exactly maxCachedEpochs times. Old code: no eviction, so size
	// would reach maxCachedEpochs. Fixed code: size stays ≤ maxCachedEpochs.
	for i := 0; i < maxCachedEpochs; i++ {
		advanceEpoch(t, g, privKeys)

		size := len(g.epochHistory)
		if size > maxCachedEpochs {
			t.Errorf(
				"epoch %d (early phase): history size = %d, want ≤ %d",
				g.Epoch().AsUint64(), size, maxCachedEpochs,
			)
		}
	}
}

// TestEpochHistory_OldEntriesEvicted verifies that an entry for epoch N is
// removed once the group advances far enough that epoch N falls below the
// retention window.
func TestEpochHistory_OldEntriesEvicted(t *testing.T) {
	t.Parallel()

	g, privKeys := newSingleMemberGroup(t, "alice")

	// Advance past the retention window.
	evictTarget := uint64(0)     // epoch 0 will be stored after the first commit.
	advanceEpoch(t, g, privKeys) // now at epoch 1, history = {0}

	// Confirm epoch 0 is in history.
	if _, ok := g.epochHistory[evictTarget]; !ok {
		t.Fatalf("epoch %d not in history after one advance - test precondition broken", evictTarget)
	}

	// Advance maxCachedEpochs more times to push epoch 0 out of the window.
	for i := 0; i < maxCachedEpochs; i++ {
		advanceEpoch(t, g, privKeys)
	}

	if _, ok := g.epochHistory[evictTarget]; ok {
		t.Errorf(
			"epoch %d still in history after advancing %d more epochs - old entry was not evicted",
			evictTarget, maxCachedEpochs,
		)
	}
}

// TestEpochHistory_CurrentEpochNotEvicted verifies that the entry just stored
// is never immediately evicted. This guards the ep < cutoff (strict) comparison
// introduced by the fix (replacing the previous ep <= cutoff).
func TestEpochHistory_CurrentEpochNotEvicted(t *testing.T) {
	t.Parallel()

	g, privKeys := newSingleMemberGroup(t, "alice")

	// Advance well past maxCachedEpochs so eviction is definitely running.
	for i := 0; i < maxCachedEpochs+2; i++ {
		advanceEpoch(t, g, privKeys)
	}

	// The epoch that was just cached is oldEpoch = currentEpoch - 1.
	// It must still be present in the map.
	currentEpoch := g.Epoch().AsUint64()
	justCached := currentEpoch - 1

	if _, ok := g.epochHistory[justCached]; !ok {
		t.Errorf(
			"epoch %d (just cached) was immediately evicted - strict < cutoff comparison broken",
			justCached,
		)
	}
}

// TestEpochHistory_ExactlyMaxEntriesRetained verifies that after a long run
// the history contains exactly min(epoch, maxCachedEpochs) entries - no more,
// no less.
func TestEpochHistory_ExactlyMaxEntriesRetained(t *testing.T) {
	t.Parallel()

	g, privKeys := newSingleMemberGroup(t, "alice")

	totalAdvances := maxCachedEpochs * 3

	for i := 0; i < totalAdvances; i++ {
		advanceEpoch(t, g, privKeys)
	}

	got := len(g.epochHistory)
	// After totalAdvances epochs the window is always full.
	if got != maxCachedEpochs {
		t.Errorf(
			"after %d advances: history size = %d, want exactly %d",
			totalAdvances, got, maxCachedEpochs,
		)
	}
}
