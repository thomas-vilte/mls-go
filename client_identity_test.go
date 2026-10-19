package mls

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

func TestClientClosePreservesIdentity(t *testing.T) {
	t.Parallel()

	c, err := NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	before := bytes.Clone(c.identity)
	if len(before) == 0 {
		t.Fatal("client identity is empty")
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !bytes.Equal(c.identity, before) {
		t.Fatalf("identity after Close = %q, want %q", c.identity, before)
	}
}

func TestClientSelfUpdateConcurrentClose(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	for round := 0; round < 20; round++ {
		c, err := NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256)
		if err != nil {
			t.Fatalf("round %d: NewClient: %v", round, err)
		}
		groupID, err := c.CreateGroup(ctx)
		if err != nil {
			t.Fatalf("round %d: CreateGroup: %v", round, err)
		}

		start := make(chan struct{})
		errs := make(chan error, 2)

		var wg sync.WaitGroup
		wg.Go(func() {
			<-start
			if _, err := c.SelfUpdate(ctx, groupID); err != nil && !errors.Is(err, ErrClientClosed) {
				errs <- err
			}
		})
		wg.Go(func() {
			<-start
			if err := c.Close(); err != nil {
				errs <- err
			}
		})

		close(start)
		wg.Wait()
		close(errs)

		for err := range errs {
			t.Fatalf("round %d: %v", round, err)
		}
	}
}
