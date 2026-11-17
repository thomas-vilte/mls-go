package group

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/treesync"
)

// WithCredentialValidator used to be stored in groupConfig and never read, so no path of the group
// package checked the credentials it admitted. The validator now runs on AddMember (the KeyPackage of
// the Add), on Commit (every Add it commits, including proposals stored by reference) and on
// processReceivedCommit (every Add the commit applies and the external joiner).

const rejectedIdentity = "mallory"

var errNotAdmitted = errors.New("identity not admitted by the application policy")

// admissionPolicy is an application admission policy. It rejects the identity "mallory".
type admissionPolicy struct{}

func (admissionPolicy) ValidateCredential(_ context.Context, cred *credentials.Credential) error {
	if cred != nil && string(cred.Identity) == rejectedIdentity {
		return errNotAdmitted
	}
	return nil
}

// newPolicyMember generates a credential and a KeyPackage for identity, with the private keys.
func newPolicyMember(t *testing.T, identity string) (*credentials.Credential, *keypackages.KeyPackage, *keypackages.KeyPackagePrivateKeys) {
	t.Helper()
	cwk, _, err := credentials.GenerateCredentialWithKey([]byte(identity))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(%s): %v", identity, err)
	}
	kp, priv, err := keypackages.Generate(cwk, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("keypackages.Generate(%s): %v", identity, err)
	}
	return cwk.Credential, kp, priv
}

// newPolicyCreator creates a one-member group for "alice" with the given options.
func newPolicyCreator(t *testing.T, opts ...GroupOption) (*Group, *ciphersuite.SignaturePrivateKey) {
	t.Helper()
	_, kp, priv := newPolicyMember(t, "alice")
	gid, err := NewGroupIDRandom()
	if err != nil {
		t.Fatalf("NewGroupIDRandom: %v", err)
	}
	g, err := NewGroup(gid, ciphersuite.MLS128DHKEMP256, kp, priv, opts...)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	return g, priv.GetSignaturePrivateKey()
}

// addPolicyMemberAndJoin adds identity to creator through a Commit and a Welcome and returns the joined
// group with its signature key. creator moves to the new epoch. The joined group has no validator.
func addPolicyMemberAndJoin(t *testing.T, creator *Group, creatorSig *ciphersuite.SignaturePrivateKey, identity string) (*Group, *ciphersuite.SignaturePrivateKey) {
	t.Helper()
	_, kp, priv := newPolicyMember(t, identity)
	if _, err := creator.AddMember(kp); err != nil {
		t.Fatalf("AddMember(%s): %v", identity, err)
	}
	sc, err := creator.Commit(creatorSig, creatorSig.PublicKey(), nil)
	if err != nil {
		t.Fatalf("Commit(add %s): %v", identity, err)
	}
	joinerSecret := sc.JoinerSecret()
	if err := creator.MergeCommit(sc); err != nil {
		t.Fatalf("MergeCommit(add %s): %v", identity, err)
	}
	welcome, err := creator.CreateWelcomeWithOpts(
		[]*keypackages.KeyPackage{kp},
		creatorSig,
		WithJoinerSecret(joinerSecret),
		WithStagedCommit(sc),
	)
	if err != nil {
		t.Fatalf("CreateWelcomeWithOpts(%s): %v", identity, err)
	}
	joined, err := JoinFromWelcome(welcome, kp, priv, nil)
	if err != nil {
		t.Fatalf("JoinFromWelcome(%s): %v", identity, err)
	}
	return joined, priv.GetSignaturePrivateKey()
}

// TestAddMemberRefusesRejectedCredential checks that AddMember refuses a KeyPackage whose credential the
// configured validator rejects, and stores no proposal.
func TestAddMemberRefusesRejectedCredential(t *testing.T) {
	t.Run("accepted credential is added", func(t *testing.T) {
		g, _ := newPolicyCreator(t, WithCredentialValidator(admissionPolicy{}))
		_, kp, _ := newPolicyMember(t, "bob")
		if _, err := g.AddMember(kp); err != nil {
			t.Fatalf("AddMember with an accepted credential: %v", err)
		}
	})

	t.Run("rejected credential fails before the proposal is stored", func(t *testing.T) {
		g, _ := newPolicyCreator(t, WithCredentialValidator(admissionPolicy{}))
		cred, kp, _ := newPolicyMember(t, rejectedIdentity)
		if err := (admissionPolicy{}).ValidateCredential(context.Background(), cred); !errors.Is(err, errNotAdmitted) {
			t.Fatalf("the policy does not reject %q (err=%v)", rejectedIdentity, err)
		}
		if _, err := g.AddMember(kp); !errors.Is(err, errNotAdmitted) {
			t.Fatalf("AddMember error = %v, want errNotAdmitted", err)
		}
		if n := len(g.Proposals().Proposals); n != 0 {
			t.Fatalf("rejected Add was stored: %d pending proposals", n)
		}
	})
}

// TestCommitRefusesRejectedStoredAdd checks that an Add received by reference is validated when a commit
// applies it: the committer does not commit it and the epoch does not advance.
func TestCommitRefusesRejectedStoredAdd(t *testing.T) {
	for _, tc := range []struct {
		name     string
		identity string
		wantErr  bool
	}{
		{"accepted stored Add is committed", "carol", false},
		{"rejected stored Add is refused", rejectedIdentity, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alice, aliceSig := newPolicyCreator(t, WithCredentialValidator(admissionPolicy{}))
			// bob is leaf 1. He proposes the Add by reference, so the proposal sits in alice's store.
			addPolicyMemberAndJoin(t, alice, aliceSig, "bob")
			_, kp, _ := newPolicyMember(t, tc.identity)
			alice.StoreProposal(&Proposal{Type: ProposalTypeAdd, Add: &AddProposal{KeyPackage: kp}}, LeafNodeIndex(1), []byte("add-"+tc.identity))

			before := alice.Epoch().AsUint64()
			_, err := alice.Commit(aliceSig, aliceSig.PublicKey(), nil)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("Commit with an accepted stored Add: %v", err)
				}
				return
			}
			if !errors.Is(err, errNotAdmitted) {
				t.Fatalf("Commit error = %v, want errNotAdmitted", err)
			}
			if got := alice.Epoch().AsUint64(); got != before {
				t.Fatalf("refused commit advanced the epoch: %d -> %d", before, got)
			}
		})
	}
}

// TestProcessReceivedCommitRefusesRejectedAdd checks that a commit from another member that adds a
// credential the receiver's validator rejects is refused and leaves the receiver's state unchanged.
func TestProcessReceivedCommitRefusesRejectedAdd(t *testing.T) {
	for _, tc := range []struct {
		name     string
		identity string
		wantErr  bool
	}{
		{"accepted Add is processed", "carol", false},
		{"rejected Add is refused", rejectedIdentity, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alice, aliceSig := newPolicyCreator(t, WithCredentialValidator(admissionPolicy{}))
			// bob has no validator. The check that matters here is the receiver's, which is alice's.
			bob, bobSig := addPolicyMemberAndJoin(t, alice, aliceSig, "bob")
			_, kp, _ := newPolicyMember(t, tc.identity)
			if _, err := bob.AddMember(kp); err != nil {
				t.Fatalf("bob.AddMember(%s): %v", tc.identity, err)
			}
			sc, err := bob.Commit(bobSig, bobSig.PublicKey(), nil)
			if err != nil {
				t.Fatalf("bob.Commit: %v", err)
			}

			before := alice.Epoch().AsUint64()
			err = alice.ProcessReceivedCommit(sc.AuthenticatedContent(), treesync.LeafIndex(1), alice.MyLeafEncryptionKey())
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("alice refused an accepted Add: %v", err)
				}
				if got := alice.Epoch().AsUint64(); got != before+1 {
					t.Fatalf("epoch = %d after accepted commit, want %d", got, before+1)
				}
				return
			}
			if !errors.Is(err, errNotAdmitted) {
				t.Fatalf("ProcessReceivedCommit error = %v, want errNotAdmitted", err)
			}
			if got := alice.Epoch().AsUint64(); got != before {
				t.Fatalf("refused commit advanced alice's epoch: %d -> %d", before, got)
			}
		})
	}
}

// TestProcessReceivedCommitRefusesRejectedExternalJoiner checks that an external commit whose joiner
// credential the validator rejects is refused and the group does not advance.
func TestProcessReceivedCommitRefusesRejectedExternalJoiner(t *testing.T) {
	for _, tc := range []struct {
		name     string
		identity string
		wantErr  bool
	}{
		{"accepted joiner is processed", "carol", false},
		{"rejected joiner is refused", rejectedIdentity, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alice, aliceSig := newPolicyCreator(t, WithCredentialValidator(admissionPolicy{}))
			groupInfo, err := alice.GetGroupInfo(aliceSig)
			if err != nil {
				t.Fatalf("GetGroupInfo: %v", err)
			}
			cred, _, priv := newPolicyMember(t, tc.identity)
			joinerSig := priv.GetSignaturePrivateKey()
			_, staged, err := ExternalCommit(groupInfo, ciphersuite.MLS128DHKEMP256, joinerSig, joinerSig.PublicKey(), nil, cred)
			if err != nil {
				t.Fatalf("ExternalCommit(%s): %v", tc.identity, err)
			}

			before := alice.Epoch().AsUint64()
			err = alice.ProcessReceivedCommit(staged.AuthenticatedContent(), treesync.LeafIndex(0), alice.MyLeafEncryptionKey())
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("alice refused an accepted external joiner: %v", err)
				}
				if got := alice.Epoch().AsUint64(); got != before+1 {
					t.Fatalf("epoch = %d after accepted external commit, want %d", got, before+1)
				}
				return
			}
			if !errors.Is(err, errNotAdmitted) {
				t.Fatalf("ProcessReceivedCommit error = %v, want errNotAdmitted", err)
			}
			if got := alice.Epoch().AsUint64(); got != before {
				t.Fatalf("refused external commit advanced alice's epoch: %d -> %d", before, got)
			}
		})
	}
}

// TestAddMemberWithoutValidatorAppliesNoPolicy checks that without WithCredentialValidator the group
// applies no credential policy, so the option is the only switch and existing callers see no change.
func TestAddMemberWithoutValidatorAppliesNoPolicy(t *testing.T) {
	g, _ := newPolicyCreator(t)
	_, kp, _ := newPolicyMember(t, rejectedIdentity)
	if _, err := g.AddMember(kp); err != nil {
		t.Fatalf("AddMember without a validator: %v", err)
	}
}

// TestGroupFromReInitKeepsCredentialValidator checks that a group created by NewGroupFromReInit with
// WithCredentialValidator applies the policy to the Adds it makes.
func TestGroupFromReInitKeepsCredentialValidator(t *testing.T) {
	kp, priv := makeSingleKP(t)
	resumptionSecret := ciphersuite.NewSecret(bytes.Repeat([]byte{0xAB}, 32))
	g, err := NewGroupFromReInit(makeReInitProposal([]byte("reinit-group-id")), resumptionSecret, []byte("old-group-id"), 0, kp, priv,
		WithCredentialValidator(admissionPolicy{}))
	if err != nil {
		t.Fatalf("NewGroupFromReInit: %v", err)
	}

	_, accepted, _ := newPolicyMember(t, "bob")
	if _, err := g.AddMember(accepted); err != nil {
		t.Fatalf("AddMember with an accepted credential: %v", err)
	}
	_, rejected, _ := newPolicyMember(t, rejectedIdentity)
	if _, err := g.AddMember(rejected); !errors.Is(err, errNotAdmitted) {
		t.Fatalf("AddMember error = %v, want errNotAdmitted", err)
	}
}
