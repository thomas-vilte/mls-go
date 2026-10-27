package group

import (
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/treesync"
)

// TestExternalCommitProposalValidation checks each external Commit list rule of RFC 9420
// §12.2 on the validator that ProcessReceivedCommit uses. The joiner's LeafNode is passed
// explicitly, as it is taken from the UpdatePath LeafNode.
func TestExternalCommitProposalValidation(t *testing.T) {
	aliceGroup, bobGroup, _, bob := makeTwoMemberGroups(t)
	mallory := newTestUser(t, "mallory")
	dave := newTestUser(t, "dave")
	bobLeaf := bobGroup.ownLeafIndex

	pf := NewProposalFilter(aliceGroup.groupContext, aliceGroup.ownLeafIndex, aliceGroup.members, aliceGroup.cipherSuite, aliceGroup.ratchetTree)

	extInit := &Proposal{Type: ProposalTypeExternalInit, ExternalInit: &ExternalInitProposal{KemOutput: []byte{1}}}
	removeBob := &Proposal{Type: ProposalTypeRemove, Remove: &RemoveProposal{Removed: bobLeaf}}
	removeOutside := &Proposal{Type: ProposalTypeRemove, Remove: &RemoveProposal{Removed: 7}}
	add := &Proposal{Type: ProposalTypeAdd, Add: &AddProposal{KeyPackage: dave.kp}}
	nonce := make([]byte, aliceGroup.cipherSuite.HashLength())
	psk := &Proposal{Type: ProposalTypePreSharedKey, PreSharedKey: &PreSharedKeyProposal{
		PskType: 1,
		PskID:   PskID{PskType: 1, ID: []byte("test-psk"), Nonce: nonce},
	}}
	pskShortNonce := &Proposal{Type: ProposalTypePreSharedKey, PreSharedKey: &PreSharedKeyProposal{
		PskType: 1,
		PskID:   PskID{PskType: 1, ID: []byte("test-psk"), Nonce: []byte{1}},
	}}

	malloryJoiner := keyPackageLeafToTreeSync(mallory.kp.LeafNode)
	bobJoiner := keyPackageLeafToTreeSync(bob.kp.LeafNode)

	cases := []struct {
		name      string
		proposals []*Proposal
		joiner    *treesync.LeafNodeData
		wantErr   bool
	}{
		{"one ExternalInit", []*Proposal{extInit}, malloryJoiner, false},
		{"Remove of the joiner's own prior leaf", []*Proposal{removeBob, extInit}, bobJoiner, false},
		{"Remove of another member's leaf", []*Proposal{removeBob, extInit}, malloryJoiner, true},
		{"Remove of a leaf outside the tree", []*Proposal{removeOutside, extInit}, bobJoiner, true},
		{"two Remove proposals", []*Proposal{removeBob, removeBob, extInit}, bobJoiner, true},
		{"PreSharedKey with a valid nonce", []*Proposal{psk, extInit}, malloryJoiner, false},
		{"PreSharedKey with a short nonce", []*Proposal{pskShortNonce, extInit}, malloryJoiner, true},
		{"duplicate PreSharedKey ID", []*Proposal{psk, psk, extInit}, malloryJoiner, true},
		{"no ExternalInit", []*Proposal{}, malloryJoiner, true},
		{"two ExternalInit", []*Proposal{extInit, extInit}, malloryJoiner, true},
		{"Add", []*Proposal{add, extInit}, malloryJoiner, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := pf.validateExternalCommitProposals(tc.proposals, tc.joiner)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("validateExternalCommitProposals: %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidProposal) {
				t.Fatalf("validateExternalCommitProposals: err = %v, want ErrInvalidProposal", err)
			}
		})
	}
}

// TestSameCredentialIdentity checks the rule that matches a Remove with the joiner.
// Only the credential identifies a participant. An empty identity never matches.
func TestSameCredentialIdentity(t *testing.T) {
	basic := credentials.NewBasicCredentialFromString
	x509Cred := func(certs ...[]byte) *credentials.Credential { return credentials.NewX509Credential(certs) }

	cases := []struct {
		name string
		a, b *credentials.Credential
		want bool
	}{
		{"same basic identity", basic("bob"), basic("bob"), true},
		{"different basic identity", basic("bob"), basic("mallory"), false},
		{"empty basic identity", basic(""), basic(""), false},
		{"nil credential", nil, basic("bob"), false},
		{"basic against X509", basic("bob"), x509Cred([]byte{1, 2, 3}), false},
		{"same X509 certificate chain", x509Cred([]byte{1, 2, 3}), x509Cred([]byte{1, 2, 3}), true},
		{"different X509 certificate chain", x509Cred([]byte{1, 2, 3}), x509Cred([]byte{4, 5, 6}), false},
		{"empty X509 certificate chain", x509Cred(), x509Cred(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameCredentialIdentity(tc.a, tc.b); got != tc.want {
				t.Fatalf("sameCredentialIdentity = %v, want %v", got, tc.want)
			}
		})
	}
}
