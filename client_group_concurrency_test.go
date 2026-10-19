package mls

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// newGroupWelcome creates a group on alice's client and returns a Welcome for bob.
func newGroupWelcome(t *testing.T, alice, bob *Client) []byte {
	t.Helper()

	ctx := t.Context()
	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes: %v", err)
	}
	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	_, welcome, err := alice.InviteMember(ctx, groupID, bobKP)
	if err != nil {
		t.Fatalf("InviteMember: %v", err)
	}
	return welcome
}

func TestClientLeaveGroupConcurrentJoinAndEpoch(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	cs := ciphersuite.MLS128DHKEMP256

	alice, err := NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	t.Cleanup(func() {
		if err := alice.Close(); err != nil {
			t.Errorf("Close(alice): %v", err)
		}
	})

	bob, err := NewClient([]byte("bob"), cs)
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}
	t.Cleanup(func() {
		if err := bob.Close(); err != nil {
			t.Errorf("Close(bob): %v", err)
		}
	})

	const rounds = 4

	leaveIDs := make([][]byte, 0, rounds)
	for i := 0; i < rounds; i++ {
		joinedID, err := bob.JoinGroup(ctx, newGroupWelcome(t, alice, bob))
		if err != nil {
			t.Fatalf("setup JoinGroup %d: %v", i, err)
		}
		leaveIDs = append(leaveIDs, joinedID)
	}

	welcomes := make([][]byte, 0, rounds)
	for i := 0; i < rounds; i++ {
		welcomes = append(welcomes, newGroupWelcome(t, alice, bob))
	}

	start := make(chan struct{})
	errs := make(chan error, 3)

	// Only the JoinGroup goroutine writes joinedIDs; the test reads it after Wait.
	joinedIDs := make([][]byte, 0, rounds)

	var wg sync.WaitGroup
	wg.Go(func() {
		<-start
		for _, groupID := range leaveIDs {
			if _, err := bob.LeaveGroup(ctx, groupID); err != nil {
				errs <- fmt.Errorf("LeaveGroup: %w", err)
				return
			}
		}
	})
	wg.Go(func() {
		<-start
		for _, welcome := range welcomes {
			groupID, err := bob.JoinGroup(ctx, welcome)
			if err != nil {
				errs <- fmt.Errorf("JoinGroup: %w", err)
				return
			}
			joinedIDs = append(joinedIDs, groupID)
		}
	})
	wg.Go(func() {
		<-start
		for i := 0; i < 8; i++ {
			for _, groupID := range leaveIDs {
				if _, err := bob.Epoch(ctx, groupID); err != nil && !errors.Is(err, ErrGroupNotFound) {
					errs <- fmt.Errorf("Epoch: %w", err)
					return
				}
			}
		}
	})

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
	if t.Failed() {
		return
	}

	for i, groupID := range leaveIDs {
		if _, err := bob.Epoch(ctx, groupID); !errors.Is(err, ErrGroupNotFound) {
			t.Fatalf("left group %d: expected ErrGroupNotFound, got %v", i, err)
		}
	}
	if len(joinedIDs) != rounds {
		t.Fatalf("expected %d joined groups, got %d", rounds, len(joinedIDs))
	}
	for i, groupID := range joinedIDs {
		if _, err := bob.Epoch(ctx, groupID); err != nil {
			t.Fatalf("joined group %d: Epoch: %v", i, err)
		}
	}
}
