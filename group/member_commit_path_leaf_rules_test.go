package group

import (
	"errors"
	"slices"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/extensions"
	"github.com/thomas-vilte/mls-go/treesync"
)

// TestMemberCommitPathLeafRules checks that the new LeafNode of the UpdatePath of a member commit meets the
// same restrictions as a LeafNode of an Update proposal, apart from leaf_node_source (RFC 9420 sections 7.4
// and 7.3). The committer copies its own capabilities and credential into that LeafNode and signs it, so a
// valid signature alone does not show that the leaf supports the cipher suite and the protocol version of the
// group, or a credential type that the other members support. Receivers refuse such a commit before they
// decrypt its path.
func TestMemberCommitPathLeafRules(t *testing.T) {
	t.Run("valid path leaf is accepted", func(t *testing.T) {
		aliceGroup, bobGroup, _, bob := newCredentialBindingTestGroups(t)
		sc, err := bobGroup.Commit(bob.sigPriv, bob.sigPub, nil)
		if err != nil {
			t.Fatalf("Commit(bob): %v", err)
		}
		if err := aliceGroup.ProcessReceivedCommit(sc.authenticatedContent, treesync.LeafIndex(bobGroup.ownLeafIndex), aliceGroup.myLeafEncryptionKey); err != nil {
			t.Fatalf("ProcessReceivedCommit(valid UpdatePath leaf): %v", err)
		}
	})

	t.Run("path leaf without the group cipher suite is refused", func(t *testing.T) {
		aliceGroup, bobGroup, _, bob := newCredentialBindingTestGroups(t)
		own := ownLeafData(t, bobGroup)
		caps := copyLeafCapabilities(own.Capabilities)
		caps.CipherSuites = []uint16{uint16(ciphersuite.MLS128DHKEMX25519)}
		own.Capabilities = caps
		sc, err := bobGroup.Commit(bob.sigPriv, bob.sigPub, nil)
		if err != nil {
			t.Fatalf("Commit(bob) with a leaf that lacks the group cipher suite: %v", err)
		}
		leaf := commitPathLeaf(t, sc)
		if slices.Contains(leaf.Capabilities.CipherSuites, uint16(ciphersuite.MLS128DHKEMP256)) {
			t.Fatalf("UpdatePath leaf still lists the group cipher suite: %v", leaf.Capabilities.CipherSuites)
		}
		expectCommitRefused(t, aliceGroup, bobGroup, sc, "UpdatePath leaf without the group cipher suite")
	})

	t.Run("path leaf without MLS 1.0 is refused", func(t *testing.T) {
		aliceGroup, bobGroup, _, bob := newCredentialBindingTestGroups(t)
		own := ownLeafData(t, bobGroup)
		caps := copyLeafCapabilities(own.Capabilities)
		caps.ProtocolVersions = []uint16{0x0002}
		own.Capabilities = caps
		sc, err := bobGroup.Commit(bob.sigPriv, bob.sigPub, nil)
		if err != nil {
			t.Fatalf("Commit(bob) with a leaf that lacks MLS 1.0: %v", err)
		}
		leaf := commitPathLeaf(t, sc)
		if slices.Contains(leaf.Capabilities.ProtocolVersions, uint16(0x0001)) {
			t.Fatalf("UpdatePath leaf still lists MLS 1.0: %v", leaf.Capabilities.ProtocolVersions)
		}
		expectCommitRefused(t, aliceGroup, bobGroup, sc, "UpdatePath leaf without MLS 1.0")
	})

	t.Run("path credential listed by every member is accepted", func(t *testing.T) {
		aliceGroup, bobGroup, _, bob := newCredentialBindingTestGroups(t)
		switchToBasicCredential(t, bobGroup)
		sc, err := bobGroup.Commit(bob.sigPriv, bob.sigPub, nil)
		if err != nil {
			t.Fatalf("Commit(bob) with a Basic credential: %v", err)
		}
		if err := aliceGroup.ProcessReceivedCommit(sc.authenticatedContent, treesync.LeafIndex(bobGroup.ownLeafIndex), aliceGroup.myLeafEncryptionKey); err != nil {
			t.Fatalf("ProcessReceivedCommit(Basic credential listed by all members): %v", err)
		}
	})

	t.Run("path credential not supported by the other members is refused", func(t *testing.T) {
		aliceGroup, bobGroup, _, bob := newCredentialBindingTestGroups(t)
		// The LeafNodes of the pair list Basic (the default capabilities) and X509. alice's leaf is narrowed to
		// X509 in both trees, so Basic is not supported by all members, and the two trees stay equal (their
		// hashes enter the provisional GroupContext of the path). bob's leaf lists both types, so the only
		// violation is the credential type that alice does not list.
		narrowLeafCredentials(t, treesync.LeafIndex(aliceGroup.ownLeafIndex), []uint16{uint16(credentials.X509Credential)}, aliceGroup, bobGroup)
		switchToBasicCredential(t, bobGroup)
		sc, err := bobGroup.Commit(bob.sigPriv, bob.sigPub, nil)
		if err != nil {
			t.Fatalf("Commit(bob) with a credential unsupported by alice: %v", err)
		}
		leaf := commitPathLeaf(t, sc)
		if leaf.Credential == nil || leaf.Credential.CredentialType != credentials.BasicCredential {
			t.Fatalf("UpdatePath leaf does not carry the Basic credential")
		}
		expectCommitRefused(t, aliceGroup, bobGroup, sc, "UpdatePath credential unsupported by the other members")
	})

	t.Run("the leaf the path replaces is not compared", func(t *testing.T) {
		aliceGroup, bobGroup, _, bob := newCredentialBindingTestGroups(t)
		// Both trees hold bob's leaf with X509 only. bob then switches to a Basic credential and lists both
		// types. The leaf he replaces is not compared: alice's own leaf supports Basic.
		narrowLeafCredentials(t, treesync.LeafIndex(bobGroup.ownLeafIndex), []uint16{uint16(credentials.X509Credential)}, aliceGroup, bobGroup)
		switchToBasicCredential(t, bobGroup)
		sc, err := bobGroup.Commit(bob.sigPriv, bob.sigPub, nil)
		if err != nil {
			t.Fatalf("Commit(bob) switching to a Basic credential: %v", err)
		}
		if err := aliceGroup.ProcessReceivedCommit(sc.authenticatedContent, treesync.LeafIndex(bobGroup.ownLeafIndex), aliceGroup.myLeafEncryptionKey); err != nil {
			t.Fatalf("ProcessReceivedCommit(credential switch with a replaced leaf): %v", err)
		}
	})

	t.Run("path leaf that lists the required credential is accepted", func(t *testing.T) {
		aliceGroup, bobGroup, _, bob := newCredentialBindingTestGroups(t)
		requireCredentialTypes(t, []credentials.CredentialType{credentials.BasicCredential}, aliceGroup, bobGroup)
		sc, err := bobGroup.Commit(bob.sigPriv, bob.sigPub, nil)
		if err != nil {
			t.Fatalf("Commit(bob) with the required credential listed: %v", err)
		}
		if err := aliceGroup.ProcessReceivedCommit(sc.authenticatedContent, treesync.LeafIndex(bobGroup.ownLeafIndex), aliceGroup.myLeafEncryptionKey); err != nil {
			t.Fatalf("ProcessReceivedCommit(required credential listed): %v", err)
		}
	})

	t.Run("path leaf without the required credential is refused", func(t *testing.T) {
		aliceGroup, bobGroup, _, bob := newCredentialBindingTestGroups(t)
		// The group requires Basic (RFC 9420 sections 7.3 and 11.1). bob's own leaf drops Basic and keeps X509,
		// which every member supports, so only the required_capabilities check can refuse the path.
		requireCredentialTypes(t, []credentials.CredentialType{credentials.BasicCredential}, aliceGroup, bobGroup)
		own := ownLeafData(t, bobGroup)
		caps := copyLeafCapabilities(own.Capabilities)
		caps.Credentials = []uint16{uint16(credentials.X509Credential)}
		own.Capabilities = caps
		sc, err := bobGroup.Commit(bob.sigPriv, bob.sigPub, nil)
		if err != nil {
			t.Fatalf("Commit(bob) with a leaf that lacks the required credential: %v", err)
		}
		leaf := commitPathLeaf(t, sc)
		if slices.Contains(leaf.Capabilities.Credentials, uint16(credentials.BasicCredential)) {
			t.Fatalf("UpdatePath leaf still lists the required Basic credential: %v", leaf.Capabilities.Credentials)
		}
		expectCommitRefused(t, aliceGroup, bobGroup, sc, "UpdatePath leaf without the required credential")
	})
}

// requireCredentialTypes adds a required_capabilities extension (RFC 9420 section 11.1) that requires the
// given credential types to the GroupContext of every group given.
func requireCredentialTypes(t *testing.T, credTypes []credentials.CredentialType, groups ...*Group) {
	t.Helper()
	data := (&extensions.RequiredCapabilitiesExtension{Credentials: credTypes}).Marshal()
	for _, g := range groups {
		g.groupContext.Extensions = append(g.groupContext.Extensions, Extension{
			Type: extensions.ExtensionTypeRequiredCapabilities,
			Data: data,
		})
	}
}

// narrowLeafCredentials sets the credential types listed in the capabilities of leaf in every group given.
// The same change is applied to each tree, so the trees keep equal leaves and equal hashes.
func narrowLeafCredentials(t *testing.T, leaf treesync.LeafIndex, credTypes []uint16, groups ...*Group) {
	t.Helper()
	for _, g := range groups {
		node := g.ratchetTree.GetLeaf(leaf)
		if node == nil || node.LeafData == nil {
			t.Fatalf("leaf %d missing from the ratchet tree", leaf)
		}
		caps := copyLeafCapabilities(node.LeafData.Capabilities)
		caps.Credentials = append([]uint16(nil), credTypes...)
		node.LeafData.Capabilities = caps
	}
}

// switchToBasicCredential gives bob a Basic credential in the committer's member entry and in its own leaf,
// and lists both credential types in the leaf capabilities that the UpdatePath copies.
func switchToBasicCredential(t *testing.T, bobGroup *Group) {
	t.Helper()
	basic := credentials.NewBasicCredentialFromString("bob-basic")
	bobGroup.members[bobGroup.ownLeafIndex].Credential = basic
	own := ownLeafData(t, bobGroup)
	own.Credential = basic
	caps := copyLeafCapabilities(own.Capabilities)
	caps.Credentials = []uint16{uint16(credentials.BasicCredential), uint16(credentials.X509Credential)}
	own.Capabilities = caps
}

// commitPathLeaf returns the LeafNode of the UpdatePath carried by the commit sc.
func commitPathLeaf(t *testing.T, sc *StagedCommit) *treesync.LeafNodeData {
	t.Helper()
	if sc.commit == nil || sc.commit.Path == nil || sc.commit.Path.LeafNode == nil || sc.commit.Path.LeafNode.Capabilities == nil {
		t.Fatalf("commit carries no UpdatePath leaf with capabilities")
	}
	return sc.commit.Path.LeafNode
}

// ownLeafData returns the LeafNodeData of g's own leaf. createUpdatePath copies the capabilities and the
// credential of this leaf into the UpdatePath LeafNode.
func ownLeafData(t *testing.T, g *Group) *treesync.LeafNodeData {
	t.Helper()
	node := g.ratchetTree.GetLeaf(treesync.LeafIndex(g.ownLeafIndex))
	if node == nil || node.LeafData == nil {
		t.Fatalf("own leaf %d missing from the ratchet tree", g.ownLeafIndex)
	}
	return node.LeafData
}

// copyLeafCapabilities returns a deep copy of caps so that each sub-case changes a single field.
func copyLeafCapabilities(caps *treesync.LeafNodeCapabilities) *treesync.LeafNodeCapabilities {
	return &treesync.LeafNodeCapabilities{
		ProtocolVersions: append([]uint16(nil), caps.ProtocolVersions...),
		CipherSuites:     append([]uint16(nil), caps.CipherSuites...),
		Extensions:       append([]uint16(nil), caps.Extensions...),
		Proposals:        append([]uint16(nil), caps.Proposals...),
		Credentials:      append([]uint16(nil), caps.Credentials...),
	}
}

// expectCommitRefused checks that alice refuses sc with ErrInvalidProposal and keeps her epoch.
func expectCommitRefused(t *testing.T, aliceGroup, bobGroup *Group, sc *StagedCommit, what string) {
	t.Helper()
	epochBefore := aliceGroup.epoch.AsUint64()
	err := aliceGroup.ProcessReceivedCommit(sc.authenticatedContent, treesync.LeafIndex(bobGroup.ownLeafIndex), aliceGroup.myLeafEncryptionKey)
	if !errors.Is(err, ErrInvalidProposal) {
		t.Fatalf("ProcessReceivedCommit(%s): err = %v, want ErrInvalidProposal", what, err)
	}
	if got := aliceGroup.epoch.AsUint64(); got != epochBefore {
		t.Fatalf("refused commit (%s) changed alice's epoch: %d -> %d", what, epochBefore, got)
	}
}
