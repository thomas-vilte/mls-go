package secrettree

import (
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// TestRatchetForwardDistanceConfiguration checks default and custom forward limits, invalid settings, existing and new leaves, and restoration defaults.
func TestRatchetForwardDistanceConfiguration(t *testing.T) {
	encSecret, err := ciphersuite.NewSecretRandom(32)
	if err != nil {
		t.Fatalf("NewSecretRandom: %v", err)
	}
	tree, err := NewTree(encSecret, 4, ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}

	if got := tree.MaxForwardDistance(); got != DefaultMaxForwardDistance {
		t.Fatalf("MaxForwardDistance() = %d, want default %d", got, DefaultMaxForwardDistance)
	}
	if DefaultMaxForwardDistance != 1000 {
		t.Errorf("DefaultMaxForwardDistance = %d, want 1000 (see its documentation)", DefaultMaxForwardDistance)
	}

	existing, err := tree.LeafForIndex(0)
	if err != nil {
		t.Fatalf("LeafForIndex(0): %v", err)
	}

	// A zero limit would reject the next in-order generation, so it must be refused
	// and the current limit must stay in place.
	if err := tree.SetMaxForwardDistance(0); err == nil {
		t.Fatal("SetMaxForwardDistance(0) succeeded, want error")
	}
	if got := tree.MaxForwardDistance(); got != DefaultMaxForwardDistance {
		t.Errorf("failed SetMaxForwardDistance(0) changed the limit to %d", got)
	}

	if err := tree.SetMaxForwardDistance(10); err != nil {
		t.Fatalf("SetMaxForwardDistance(10): %v", err)
	}
	if got := tree.MaxForwardDistance(); got != 10 {
		t.Fatalf("MaxForwardDistance() = %d after set, want 10", got)
	}

	// The leaf created before the change honours the new limit: 10 steps are
	// allowed, and 11 steps beyond the current generation (10) are not.
	if _, err := existing.ApplicationKey(10); err != nil {
		t.Errorf("existing leaf: ApplicationKey(10) within limit 10: %v", err)
	}
	if _, err := existing.ApplicationKey(21); err == nil {
		t.Error("existing leaf: ApplicationKey(21) succeeded, want rejection beyond limit 10")
	}

	// A leaf created after the change gets the same limit.
	fresh, err := tree.LeafForIndex(1)
	if err != nil {
		t.Fatalf("LeafForIndex(1): %v", err)
	}
	if _, err := fresh.ApplicationKey(11); err == nil {
		t.Error("fresh leaf: ApplicationKey(11) succeeded, want rejection beyond limit 10")
	}
	if got := fresh.CurrentGeneration(); got != 0 {
		t.Errorf("fresh leaf: CurrentGeneration = %d after rejected jump, want 0", got)
	}
	if _, err := fresh.ApplicationKey(10); err != nil {
		t.Errorf("fresh leaf: ApplicationKey(10) within limit 10: %v", err)
	}

	// The limit is local policy: a restored tree starts again from the default.
	restored, err := UnmarshalFull(tree.MarshalFull(), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("UnmarshalFull: %v", err)
	}
	if got := restored.MaxForwardDistance(); got != DefaultMaxForwardDistance {
		t.Errorf("restored MaxForwardDistance() = %d, want default %d", got, DefaultMaxForwardDistance)
	}
}
