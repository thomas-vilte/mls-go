package group

import (
	"errors"
	"testing"
	"time"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// joinWithDeadline runs JoinFromWelcome under a deadline. A panic is recovered inside the goroutine and
// reported as a test failure, and a join that never returns fails the test instead of hanging the test binary.
func joinWithDeadline(t *testing.T, welcome *Welcome, kp *keypackages.KeyPackage, priv *keypackages.KeyPackagePrivateKeys) (*Group, error) {
	t.Helper()
	type outcome struct {
		group    *Group
		err      error
		panicked any
	}
	done := make(chan outcome, 1)
	go func() {
		var res outcome
		defer func() {
			res.panicked = recover()
			done <- res
		}()
		res.group, res.err = JoinFromWelcome(welcome, kp, priv, nil)
	}()
	select {
	case res := <-done:
		if res.panicked != nil {
			t.Fatalf("JoinFromWelcome panicked: %v", res.panicked)
		}
		return res.group, res.err
	case <-time.After(10 * time.Second):
		t.Fatal("JoinFromWelcome did not return within 10s")
		return nil, nil
	}
}

// welcomeWithoutRatchetTree creates a Welcome for bob whose GroupInfo carries no ratchet_tree extension.
// The joiner then runs with the placeholder one-leaf tree and does not verify the GroupInfo signature, so the
// Signer field of the GroupInfo is not checked against any tree. mutate, when not nil, runs after the commit
// is merged and before the Welcome is created.
func welcomeWithoutRatchetTree(t *testing.T, mutate func(*Group)) (*Welcome, *testUser) {
	t.Helper()
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")
	groupID, err := NewGroupIDRandom()
	if err != nil {
		t.Fatalf("NewGroupIDRandom: %v", err)
	}
	aliceGroup, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, alice.kp, alice.priv)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	if _, err := aliceGroup.AddMember(bob.kp); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	sc, err := aliceGroup.Commit(alice.sigPriv, alice.sigPub, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	joinerSecret := sc.JoinerSecret()
	if err := aliceGroup.MergeCommit(sc); err != nil {
		t.Fatalf("MergeCommit: %v", err)
	}
	if mutate != nil {
		mutate(aliceGroup)
	}
	// An Add-only commit carries no UpdatePath, so it has no path_secret of its own. The Welcome gets an
	// explicit one, which is what a crafted Welcome may carry, so the joiner reaches the committer's
	// direct-path step.
	welcome, err := aliceGroup.CreateWelcomeWithOpts(
		[]*keypackages.KeyPackage{bob.kp},
		alice.sigPriv,
		WithJoinerSecret(joinerSecret),
		WithPathSecret(make([]byte, 32)),
		WithStagedCommit(sc),
		WithGroupInfoOptions(WithRatchetTree(false)),
	)
	if err != nil {
		t.Fatalf("CreateWelcomeWithOpts: %v", err)
	}
	return welcome, bob
}

// TestJoinFromWelcomeRejectsSignerOutsideTree checks that a Welcome without a ratchet_tree extension and with
// a Signer that is not a leaf of the placeholder one-leaf tree is refused with ErrSignerLeafMissing. The
// join used to take the direct path of that Signer, which was nil, and panic when it sliced it.
func TestJoinFromWelcomeRejectsSignerOutsideTree(t *testing.T) {
	t.Parallel()
	welcome, bob := welcomeWithoutRatchetTree(t, func(g *Group) { g.ownLeafIndex = 7 })
	if _, err := joinWithDeadline(t, welcome, bob.kp, bob.priv); !errors.Is(err, ErrSignerLeafMissing) {
		t.Fatalf("JoinFromWelcome err = %v, want ErrSignerLeafMissing", err)
	}
}

// TestJoinFromWelcomeWithoutRatchetTreeAcceptsSignerZero checks that the same Welcome still joins when the
// Signer is leaf 0, which the placeholder tree has.
func TestJoinFromWelcomeWithoutRatchetTreeAcceptsSignerZero(t *testing.T) {
	t.Parallel()
	welcome, bob := welcomeWithoutRatchetTree(t, nil)
	joined, err := joinWithDeadline(t, welcome, bob.kp, bob.priv)
	if err != nil {
		t.Fatalf("JoinFromWelcome(signer 0, no ratchet_tree) err = %v", err)
	}
	if joined == nil {
		t.Fatal("JoinFromWelcome(signer 0, no ratchet_tree) returned a nil group")
	}
}
