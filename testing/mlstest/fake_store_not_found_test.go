package mlstest

import (
	"context"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/group"
)

// TestFakeStoreNotFoundMatchesGroupSentinel checks that FakeStore reports a missing group with an error that
// matches both its own ErrGroupStateNotFound and group.ErrGroupStateNotFound.
func TestFakeStoreNotFoundMatchesGroupSentinel(t *testing.T) {
	t.Parallel()
	_, err := NewFakeStore().LoadGroupState(context.Background(), group.NewGroupID([]byte("missing-group")))
	if !errors.Is(err, ErrGroupStateNotFound) || !errors.Is(err, group.ErrGroupStateNotFound) {
		t.Fatalf("LoadGroupState(missing group) = %v, want an error matching ErrGroupStateNotFound and group.ErrGroupStateNotFound", err)
	}
}
