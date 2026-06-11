package mls

// Tests for the fixes introduced:
//
//   1. WithX509Credential error propagation
//   2. EventHandler panic recovery
//   3. PendingCommitHandle / Close() race (requires -race flag)
//   4. LeaveGroup documentation (behaviour unchanged, guarded by existing test)

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// ---------------------------------------------------------------------------
// Fix 1 - WithX509Credential must surface errors from NewClient
// ---------------------------------------------------------------------------

// TestWithX509Credential_InvalidDER verifies that passing a syntactically
// invalid DER blob to WithX509Credential causes NewClient to return a
// descriptive error rather than silently falling back to the Basic credential
// path and returning a confusing ErrEmptyIdentity.
func TestWithX509Credential_InvalidDER(t *testing.T) {
	t.Parallel()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}

	_, err = NewClient(
		[]byte(""), // empty identity - previously masked the real error
		ciphersuite.MLS128DHKEMP256,
		WithX509Credential([]byte("this is not a valid DER certificate"), privKey),
	)
	if err == nil {
		t.Fatal("NewClient should have returned an error for an invalid DER certificate")
	}

	// The error must come from the X.509 path, not be the generic ErrEmptyIdentity.
	if err == ErrEmptyIdentity {
		t.Fatalf("got ErrEmptyIdentity - the certificate error was swallowed and "+
			"NewClient fell through to the Basic credential path: %v", err)
	}

	// The error message should reference the option so callers know where to look.
	if !strings.Contains(err.Error(), "WithX509Credential") {
		t.Errorf("error %q does not mention WithX509Credential; context unclear for callers", err)
	}
}

// TestWithX509Credential_NilPrivateKey verifies that a nil private key is
// rejected gracefully. The option function guards against nil and returns early,
// so NewClient falls through - but with an empty identity that should still
// produce a clear error rather than a panic.
func TestWithX509Credential_NilPrivateKey(t *testing.T) {
	t.Parallel()

	certDER, _ := generateTestCertificate(t)

	// nil key: the option skips setting credentialWithKey, NewClient uses Basic.
	// With a non-empty identity this must succeed (Basic credential path).
	_, err := NewClient(
		[]byte("fallback-identity"),
		ciphersuite.MLS128DHKEMP256,
		WithX509Credential(certDER, nil),
	)
	if err != nil {
		// The option silently no-ops on nil key; Basic path should succeed.
		t.Fatalf("unexpected error with nil key (option should no-op): %v", err)
	}
}

// TestWithX509Credential_EmptyCert verifies that an empty cert DER byte slice
// causes the option to no-op, and NewClient continues with the Basic credential
// path using the supplied identity.
func TestWithX509Credential_EmptyCert(t *testing.T) {
	t.Parallel()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}

	// Empty cert - option no-ops, Basic path used instead.
	_, err = NewClient(
		[]byte("alice"),
		ciphersuite.MLS128DHKEMP256,
		WithX509Credential([]byte{}, privKey),
	)
	if err != nil {
		t.Fatalf("unexpected error with empty cert DER (option should no-op): %v", err)
	}
}

// ---------------------------------------------------------------------------
// Fix 2 - EventHandler panics must not crash the calling goroutine
// ---------------------------------------------------------------------------

// TestEventHandler_PanicRecovery verifies that an EventHandler that panics on
// every invocation does not crash the process or leave the Client in a broken
// state. After the panicking invite, the client must still be able to send and
// receive messages.
func TestEventHandler_PanicRecovery(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256

	// Register a handler that always panics.
	alice, err := NewClient([]byte("alice"), cs, WithEventHandler(func(GroupEvent) {
		panic("deliberate panic in event handler")
	}))
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	bob, err := NewClient([]byte("bob"), cs)
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}

	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes: %v", err)
	}

	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	// InviteMember triggers EventMemberJoined + EventEpochAdvanced - both fire
	// the panicking handler. The test must not crash or deadlock.
	_, welcome, err := alice.InviteMember(ctx, groupID, bobKP)
	if err != nil {
		t.Fatalf("InviteMember: %v", err)
	}

	// Give goroutines time to execute the handler (and panic-recover).
	time.Sleep(50 * time.Millisecond)

	bobGroupID, err := bob.JoinGroup(ctx, welcome)
	if err != nil {
		t.Fatalf("JoinGroup: %v", err)
	}

	// Alice's Client must still be operational after the handler panicked.
	ct, err := alice.SendMessage(ctx, groupID, []byte("still works"))
	if err != nil {
		t.Fatalf("SendMessage after panicking handler: %v", err)
	}
	msg, err := bob.ReceiveMessage(ctx, bobGroupID, ct)
	if err != nil {
		t.Fatalf("ReceiveMessage after panicking handler: %v", err)
	}
	if string(msg.Plaintext) != "still works" {
		t.Fatalf("plaintext = %q, want \"still works\"", msg.Plaintext)
	}
}

// TestEventHandler_PanicIsIsolated verifies that panics from one event emission
// do not prevent subsequent events from firing. Two separate invocations should
// each independently reach the (panicking) handler.
func TestEventHandler_PanicIsIsolated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256

	var mu sync.Mutex
	callCount := 0

	alice, err := NewClient([]byte("alice"), cs, WithEventHandler(func(GroupEvent) {
		mu.Lock()
		callCount++
		mu.Unlock()
		panic("deliberate panic")
	}))
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	bob, err := NewClient([]byte("bob"), cs)
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}
	carol, err := NewClient([]byte("carol"), cs)
	if err != nil {
		t.Fatalf("NewClient(carol): %v", err)
	}

	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	// First invite (fires EventMemberJoined + EventEpochAdvanced).
	bobKP, _ := bob.FreshKeyPackageBytes(ctx)
	_, bobWelcome, err := alice.InviteMember(ctx, groupID, bobKP)
	if err != nil {
		t.Fatalf("InviteMember(bob): %v", err)
	}
	_, err = bob.JoinGroup(ctx, bobWelcome)
	if err != nil {
		t.Fatalf("JoinGroup(bob): %v", err)
	}

	// Second invite (fires the same events again).
	carolKP, _ := carol.FreshKeyPackageBytes(ctx)
	_, _, err = alice.InviteMember(ctx, groupID, carolKP)
	if err != nil {
		t.Fatalf("InviteMember(carol): %v", err)
	}

	// Allow goroutines to complete.
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	got := callCount
	mu.Unlock()

	// Two invites × two events each = four calls (EventMemberJoined + EventEpochAdvanced
	// for each). The count should be ≥ 2; if panics were silently stopping further
	// dispatch the count would be 1.
	if got < 2 {
		t.Errorf("handler called %d times; panics appear to have stopped further dispatch (want ≥ 2)", got)
	}
}

// ---------------------------------------------------------------------------
// Fix 3 - PendingCommitHandle / Close() race
// ---------------------------------------------------------------------------

// TestStagedCommit_CloseWhileHandlePending verifies that calling Close()
// concurrently with ConfirmPendingCommit does not produce a data race.
//
// Must be run with -race: go test -race -run TestStagedCommit_CloseWhileHandlePending
func TestStagedCommit_CloseWhileHandlePending(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256

	alice, err := NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	bob, err := NewClient([]byte("bob"), cs)
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}

	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes: %v", err)
	}
	_, err = alice.ProposeAddMember(ctx, groupID, bobKP)
	if err != nil {
		t.Fatalf("ProposeAddMember: %v", err)
	}

	handle, err := alice.CommitPendingProposalsStaged(ctx, groupID)
	if err != nil {
		t.Fatalf("CommitPendingProposalsStaged: %v", err)
	}

	// Race: Close() and ConfirmPendingCommit() concurrently.
	// Without the fix, Close() would close the store while persistGroup inside
	// ConfirmPendingCommit was still running, triggering a data race.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		// Small sleep so both goroutines have time to reach their critical path.
		time.Sleep(time.Millisecond)
		if err := alice.Close(); err != nil {
			t.Logf("Close: %v (may be expected if Confirm ran first)", err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := alice.ConfirmPendingCommit(ctx, handle); err != nil {
			t.Logf("ConfirmPendingCommit: %v (may be expected if Close ran first)", err)
		}
	}()

	wg.Wait()
	// No assertions beyond "did not crash or race". The -race detector is the
	// enforcer here.
}

// TestStagedCommit_CloseWaitsForDiscard verifies the symmetric case: Close()
// must wait for DiscardPendingCommit to finish before tearing down the store.
func TestStagedCommit_CloseWaitsForDiscard(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256

	alice, err := NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	bob, err := NewClient([]byte("bob"), cs)
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}

	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes: %v", err)
	}
	_, err = alice.ProposeAddMember(ctx, groupID, bobKP)
	if err != nil {
		t.Fatalf("ProposeAddMember: %v", err)
	}

	handle, err := alice.CommitPendingProposalsStaged(ctx, groupID)
	if err != nil {
		t.Fatalf("CommitPendingProposalsStaged: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		time.Sleep(time.Millisecond)
		if err := alice.Close(); err != nil {
			t.Logf("Close: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := alice.DiscardPendingCommit(ctx, handle); err != nil {
			t.Logf("DiscardPendingCommit: %v", err)
		}
	}()

	wg.Wait()
}

// TestStagedCommit_PendingHandlesCounterBalance verifies the WaitGroup
// accounting: every CommitPendingProposalsStaged call must be balanced by
// exactly one Confirm or Discard before Close() returns. If the counter were
// wrong (e.g. Add without Done), Close() would block forever and the test
// would time out.
func TestStagedCommit_PendingHandlesCounterBalance(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256

	alice, err := NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatalf("NewClient(alice): %v", err)
	}
	bob, err := NewClient([]byte("bob"), cs)
	if err != nil {
		t.Fatalf("NewClient(bob): %v", err)
	}

	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes: %v", err)
	}
	_, err = alice.ProposeAddMember(ctx, groupID, bobKP)
	if err != nil {
		t.Fatalf("ProposeAddMember: %v", err)
	}

	handle, err := alice.CommitPendingProposalsStaged(ctx, groupID)
	if err != nil {
		t.Fatalf("CommitPendingProposalsStaged: %v", err)
	}

	// Discard the handle - this must call pendingHandles.Done().
	if err := alice.DiscardPendingCommit(ctx, handle); err != nil {
		t.Fatalf("DiscardPendingCommit: %v", err)
	}

	// Close must return promptly (no pending handles outstanding).
	// If the WaitGroup counter was not decremented, this blocks forever.
	done := make(chan struct{})
	go func() {
		_ = alice.Close()
		close(done)
	}()

	select {
	case <-done:
		// pass
	case <-time.After(2 * time.Second):
		t.Fatal("Close() blocked - pendingHandles WaitGroup counter was not decremented by DiscardPendingCommit")
	}
}
