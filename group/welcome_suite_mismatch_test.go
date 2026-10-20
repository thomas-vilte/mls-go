package group

import (
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// newCipherSuiteTestWelcome builds a CS2 group in which Alice adds Bob and returns the Welcome for
// Bob's KeyPackage together with Bob's identity. mutate, when not nil, runs after the
// commit is merged and before the Welcome is created, so it can change the GroupInfo
// that the Welcome carries.
func newCipherSuiteTestWelcome(t *testing.T, mutate func(*Group)) (*Welcome, *testUser) {
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
	welcome, err := aliceGroup.CreateWelcomeWithOpts(
		[]*keypackages.KeyPackage{bob.kp},
		alice.sigPriv,
		WithJoinerSecret(joinerSecret),
		WithStagedCommit(sc),
	)
	if err != nil {
		t.Fatalf("CreateWelcomeWithOpts: %v", err)
	}
	return welcome, bob
}

// joinCipherSuiteTestWelcome runs JoinFromWelcome and fails the test if it panics.
func joinCipherSuiteTestWelcome(t *testing.T, welcome *Welcome, kp *keypackages.KeyPackage, priv *keypackages.KeyPackagePrivateKeys) (*Group, error) {
	t.Helper()
	var (
		joined *Group
		err    error
	)
	mustNotPanic(t, "JoinFromWelcome", func() {
		joined, err = JoinFromWelcome(welcome, kp, priv, nil)
	})
	return joined, err
}

// TestJoinFromWelcomeCipherSuiteMismatch verifies that the Welcome, KeyPackage,
// and GroupInfo use the same cipher suite.
func TestJoinFromWelcomeCipherSuiteMismatch(t *testing.T) {
	t.Parallel()

	t.Run("welcome_cs_differs_from_kp", func(t *testing.T) {
		welcome, bob := newCipherSuiteTestWelcome(t, nil)
		// The Welcome says CS1 while Bob's KeyPackage is CS2. The join must stop at the
		// comparison and not reach the HPKE decryption with the wrong suite.
		mismatched := *welcome
		mismatched.CipherSuite = ciphersuite.MLS128DHKEMX25519

		if _, err := joinCipherSuiteTestWelcome(t, &mismatched, bob.kp, bob.priv); !errors.Is(err, ErrWelcomeCipherSuiteMismatch) {
			t.Fatalf("JoinFromWelcome err = %v, want ErrWelcomeCipherSuiteMismatch", err)
		}
	})

	t.Run("kp_cs_differs_from_welcome", func(t *testing.T) {
		welcome, bob := newCipherSuiteTestWelcome(t, nil)
		// Bob's KeyPackage now declares CS3 while the Welcome is CS2. Raw keeps the wire
		// bytes that the committer hashed, so key_package_ref still finds Bob's entry and
		// the declared suite is the only difference.
		kp := *bob.kp
		kp.Raw = bob.kp.Marshal()
		kp.CipherSuite = ciphersuite.MLS128DHKEMX25519ChaCha20

		if _, err := joinCipherSuiteTestWelcome(t, welcome, &kp, bob.priv); !errors.Is(err, ErrWelcomeCipherSuiteMismatch) {
			t.Fatalf("JoinFromWelcome err = %v, want ErrWelcomeCipherSuiteMismatch", err)
		}
	})

	t.Run("group_info_cs_differs_from_welcome", func(t *testing.T) {
		// The committer builds the GroupInfo from a GroupContext that says CS1, while the
		// Welcome itself is CS2. Every other field is valid for CS2.
		welcome, bob := newCipherSuiteTestWelcome(t, func(g *Group) {
			g.groupContext.CipherSuite = ciphersuite.MLS128DHKEMX25519
		})

		if _, err := joinCipherSuiteTestWelcome(t, welcome, bob.kp, bob.priv); !errors.Is(err, ErrWelcomeCipherSuiteMismatch) {
			t.Fatalf("JoinFromWelcome err = %v, want ErrWelcomeCipherSuiteMismatch", err)
		}
	})

	// Control: a Welcome whose suites all agree still joins.
	t.Run("control_valid_join", func(t *testing.T) {
		welcome, bob := newCipherSuiteTestWelcome(t, nil)

		joined, err := joinCipherSuiteTestWelcome(t, welcome, bob.kp, bob.priv)
		if err != nil {
			t.Fatalf("JoinFromWelcome(valid) err = %v", err)
		}
		if joined == nil {
			t.Fatal("JoinFromWelcome(valid) returned nil group")
		}
		if got := joined.CipherSuite(); got != ciphersuite.MLS128DHKEMP256 {
			t.Fatalf("joined cipher suite = %v, want %v", got, ciphersuite.MLS128DHKEMP256)
		}
	})
}
