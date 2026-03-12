// Package group implements MLS Group Management according to RFC 9420 §11-12.
//
// This package provides functionality for:
//   - Group creation and joining
//   - Proposal handling (Add, Update, Remove)
//   - Commit creation and processing
//   - Welcome message handling
//   - Member management
//
// This implementation is generic and can be used for any MLS-based protocol.
package group

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"sort"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/internal/tls"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/schedule"
	"github.com/thomas-vilte/mls-go/secrettree"
	"github.com/thomas-vilte/mls-go/treesync"
)

// GroupID uniquely identifies an MLS group
type GroupID struct {
	Value []byte
}

// NewGroupID creates a GroupID from bytes
func NewGroupID(value []byte) *GroupID {
	return &GroupID{Value: value}
}

// NewGroupIDRandom generates a random GroupID.
func NewGroupIDRandom() (*GroupID, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("generating random group ID: %w", err)
	}
	return &GroupID{Value: id}, nil
}

// AsSlice returns the GroupID as a byte slice.
func (g *GroupID) AsSlice() []byte {
	return g.Value
}

// GroupEpoch represents the epoch number of a group.
type GroupEpoch uint64

// NewGroupEpoch creates a new epoch.
func NewGroupEpoch(epoch uint64) GroupEpoch {
	return GroupEpoch(epoch)
}

// AsUint64 returns the epoch as uint64.
func (e GroupEpoch) AsUint64() uint64 {
	return uint64(e)
}

// Increment increments the epoch.
func (e *GroupEpoch) Increment() {
	*e++
}

// Group represents an MLS group.
type Group struct {
	GroupID               *GroupID
	Epoch                 GroupEpoch
	CipherSuite           ciphersuite.CipherSuite
	GroupContext          *GroupContext
	RatchetTree           *treesync.RatchetTree
	OwnLeafIndex          LeafNodeIndex
	EpochSecrets          *schedule.EpochSecrets
	Proposals             *ProposalStore
	ProposalByRef         map[string]*Proposal
	PendingCommit         *StagedCommit
	ConfirmationTag       []byte
	InterimTranscriptHash []byte
	KeySchedule           *schedule.KeySchedule
	Members               map[LeafNodeIndex]*Member
	state                 GroupState
	SecretTree            *secrettree.Tree
	CachedPsks            map[string][]byte
	PSKStore              PSKStore
	// MyLeafEncryptionKey is the private HPKE key of the own leaf, used for
	// decrypting path secrets in received commits (RFC 9420 §12.4.2).
	MyLeafEncryptionKey []byte
}

// NewGroup This is the entry point for creating a new group.
func NewGroup(
	groupID *GroupID,
	cipherSuite ciphersuite.CipherSuite,
	keyPackage *keypackages.KeyPackage,
	_ *keypackages.KeyPackagePrivateKeys,
) (*Group, error) {
	// Create ratchet tree with 1 leaf
	ratchetTree := treesync.NewRatchetTree(1)

	// Add our leaf
	leafData := treesync.LeafNodeData{
		EncryptionKey:   keyPackage.InitKey,
		SignatureKey:    keyPackage.LeafNode.SignatureKey,
		SignatureKeyRaw: append([]byte(nil), keyPackage.LeafNode.SignatureKeyBytes...),
		Credential:      keyPackage.LeafNode.Credential,
		Capabilities:    &treesync.LeafNodeCapabilities{},
		Lifetime:        &treesync.LeafNodeLifetime{},
		LeafNodeSource:  1, // key_package
	}

	_, _ = ratchetTree.AddLeaf(leafData)

	// Create group context
	groupContext := &GroupContext{
		GroupID:     groupID,
		Epoch:       NewGroupEpoch(0),
		CipherSuite: cipherSuite,
		Extensions:  []Extension{},
	}

	// Initialize key schedule with zeros for first epoch
	initSecret := ciphersuite.ZeroSecret(cipherSuite.HashLength())
	keySchedule := schedule.NewKeySchedule(cipherSuite, initSecret)

	// Compute epoch secrets
	commitSecret := ciphersuite.ZeroSecret(cipherSuite.HashLength())
	keySchedule.SetCommitSecret(commitSecret)

	groupContextBytes := groupContext.Marshal()

	_, err := keySchedule.ComputeJoinerSecret(groupContextBytes)
	if err != nil {
		return nil, fmt.Errorf("computing joiner secret: %w", err)
	}

	_, err = keySchedule.ComputePskSecret([]schedule.Psk{})
	if err != nil {
		return nil, fmt.Errorf("computing psk secret: %w", err)
	}
	_, err = keySchedule.ComputeEpochSecret(groupContextBytes)
	if err != nil {
		return nil, fmt.Errorf("computing epoch secret: %w", err)
	}

	epochSecrets, err := keySchedule.DeriveEpochSecrets()
	if err != nil {
		return nil, fmt.Errorf("deriving epoch secrets: %w", err)
	}

	// Create group
	group := &Group{
		GroupID:               groupID,
		Epoch:                 NewGroupEpoch(0),
		CipherSuite:           cipherSuite,
		GroupContext:          groupContext,
		RatchetTree:           ratchetTree,
		OwnLeafIndex:          NewLeafNodeIndex(0),
		EpochSecrets:          epochSecrets,
		Proposals:             NewProposalStore(),
		ProposalByRef:         make(map[string]*Proposal),
		KeySchedule:           keySchedule,
		InterimTranscriptHash: []byte{},
		Members:               make(map[LeafNodeIndex]*Member),
		state:                 StateOperational,
		CachedPsks:            make(map[string][]byte),
	}

	// Initialize secret tree
	group.SecretTree, err = secrettree.NewTree(epochSecrets.EncryptionSecret, 1, group.CipherSuite)
	if err != nil {
		return nil, fmt.Errorf("initializing secret tree: %w", err)
	}

	// Add ourselves as a member
	group.Members[NewLeafNodeIndex(0)] = &Member{
		LeafIndex:  NewLeafNodeIndex(0),
		KeyPackage: keyPackage,
		Credential: keyPackage.LeafNode.Credential,
		Active:     true,
	}

	return group, nil
}

// AddMember adds a new member to the group.
//
// This creates an Add proposal and stages it for commit.
func (g *Group) AddMember(keyPackage *keypackages.KeyPackage) (*Proposal, error) {
	if g.state != StateOperational {
		return nil, fmt.Errorf("group not in operational state")
	}

	// Create Add proposal
	proposal := &Proposal{
		Type: ProposalTypeAdd,
		Add: &AddProposal{
			KeyPackage: keyPackage,
		},
	}

	// Store proposal
	g.Proposals.AddProposal(proposal, g.OwnLeafIndex)

	return proposal, nil
}

// UpdateMember updates the own leaf node.
//
// This creates an Update proposal with a new LeafNode.
func (g *Group) UpdateMember(
	newLeafNode *treesync.LeafNodeData,
	privateKeys *keypackages.KeyPackagePrivateKeys,
) (*Proposal, error) {
	if g.state != StateOperational {
		return nil, fmt.Errorf("group not in operational state")
	}
	if newLeafNode == nil {
		return nil, fmt.Errorf("new leaf node is nil")
	}
	if privateKeys == nil {
		return nil, fmt.Errorf("private keys are nil")
	}
	if privateKeys.SignatureKey == nil && len(privateKeys.Ed25519SignatureKey) == 0 {
		return nil, fmt.Errorf("no signature key available")
	}

	// source = 2 (update); TBS includes group_id + leaf_index per RFC §7.2.
	newLeafNode.LeafNodeSource = 2
	sigKey := privateKeys.GetSignaturePrivateKey()
	tbs := newLeafNode.MarshalTBSWithContext(g.GroupContext.GroupID.AsSlice(), uint32(g.OwnLeafIndex))
	sig, err := ciphersuite.SignWithLabel(sigKey, "LeafNodeTBS", tbs)
	if err != nil {
		return nil, fmt.Errorf("signing leaf node: %w", err)
	}
	newLeafNode.Signature = sig.AsSlice()

	// Convert treesync leaf data to keypackages leaf node.
	kpLeafNode := &keypackages.LeafNode{
		EncryptionKey:     newLeafNode.EncryptionKey,
		SignatureKey:      newLeafNode.SignatureKey,
		SignatureKeyBytes: append([]byte(nil), newLeafNode.SignatureKeyRaw...),
		Credential:        newLeafNode.Credential,
		Capabilities:      treeSyncToKeyPackageCapabilities(newLeafNode.Capabilities),
		Lifetime:          treeSyncToKeyPackageLifetime(newLeafNode.Lifetime),
	}

	// Create Update proposal
	proposal := &Proposal{
		Type: ProposalTypeUpdate,
		Update: &UpdateProposal{
			LeafNode: kpLeafNode,
		},
	}

	// Store proposal
	g.Proposals.AddProposal(proposal, g.OwnLeafIndex)
	return proposal, nil
}

// RemoveMember removes a member from the group.
//
// This creates a Remove proposal.
func (g *Group) RemoveMember(leafIndex LeafNodeIndex) (*Proposal, error) {
	if g.state != StateOperational {
		return nil, fmt.Errorf("group not in operational state")
	}

	// Validate leaf index
	if int(leafIndex) >= int(g.RatchetTree.NumLeaves) {
		return nil, fmt.Errorf("invalid leaf index: %d", leafIndex)
	}

	// Create Remove proposal
	proposal := &Proposal{
		Type: ProposalTypeRemove,
		Remove: &RemoveProposal{
			Removed: leafIndex,
		},
	}

	// Store proposal
	g.Proposals.AddProposal(proposal, g.OwnLeafIndex)

	return proposal, nil
}

// Commit applies all pending proposals and creates a new epoch.
//
// This is the main function to advance the group to a new epoch.
// RFC 9420 §12.4
// Commit applies all pending proposals and creates a new epoch, generating a PublicMessage.
//
// This is the main function to advance the group to a new epoch.
// RFC 9420 §12.4
func (g *Group) Commit(
	sigPrivKey *ciphersuite.SignaturePrivateKey,
	sigPubKey *ciphersuite.SignaturePublicKey,
	psks []schedule.Psk,
) (*StagedCommit, error) {
	return g.CommitWithFormat(sigPrivKey, sigPubKey, psks, framing.WireFormatPublicMessage)
}

// CommitWithFormat creates a new epoch using the specified WireFormat for the commit signature.
func (g *Group) CommitWithFormat(
	sigPrivKey *ciphersuite.SignaturePrivateKey,
	sigPubKey *ciphersuite.SignaturePublicKey,
	psks []schedule.Psk,
	wireFormat framing.WireFormat,
) (*StagedCommit, error) {
	if g.state != StateOperational {
		return nil, fmt.Errorf("group not in operational state: %w", ErrInvalidGroupState)
	}

	if len(g.Proposals.Proposals) == 0 {
		return nil, fmt.Errorf("no proposals to commit")
	}

	// Filter and validate proposals (RFC §12.2)
	filtered, err := g.FilterProposalsForCommit(nil)
	if err != nil {
		return nil, fmt.Errorf("filtering proposals: %w", err)
	}

	proposals := make([]*Proposal, len(filtered))
	for i, fp := range filtered {
		proposals[i] = fp.Proposal
	}

	// Clone tree, apply proposals provisionally.
	// Track newly added leaves (Add proposals) to exclude them from
	// UpdatePath encryption (RFC §12.4.1: new members get commit_secret via Welcome).
	fmt.Printf("[DEBUG Commit] g.RatchetTree.TreeHash before proposals: %x\n", g.RatchetTree.TreeHash())
	treeDiff := g.RatchetTree.Clone()
	excluded := make(map[treesync.LeafIndex]bool)
	for _, fp := range filtered {
		if fp.Proposal.Type == ProposalTypeAdd && fp.Proposal.Add != nil && fp.Proposal.Add.KeyPackage != nil && fp.Proposal.Add.KeyPackage.LeafNode != nil {
			leafData := *keyPackageLeafToTreeSync(fp.Proposal.Add.KeyPackage.LeafNode)
			addedIdx, _ := treeDiff.AddLeaf(leafData)
			excluded[addedIdx] = true
		} else {
			if err := g.applyProposalToTree(fp.Proposal, treeDiff, fp.Sender); err != nil {
				return nil, fmt.Errorf("applying proposal to tree: %w", err)
			}
		}
	}

	// 3. Generate UpdatePath if necessary (RFC §12.4.1)
	var updatePath *UpdatePath
	var commitSecret *ciphersuite.Secret

	// Generate UpdatePath, excluding newly added leaves from encryption.
	updatePath, commitSecret, err = g.createUpdatePath(treeDiff, sigPrivKey, sigPubKey, excluded)
	if err != nil {
		return nil, fmt.Errorf("creating update path: %w", err)
	}

	// 4. Construir Commit struct
	commit := &Commit{
		Proposals: make([]ProposalOrRef, len(proposals)),
		Path:      updatePath,
	}

	for i, prop := range proposals {
		commit.Proposals[i] = ProposalOrRef{
			Proposal: prop,
		}
	}

	// 5. Create AuthenticatedContent and sign
	content := framing.FramedContent{
		GroupID: g.GroupID.AsSlice(),
		Epoch:   g.Epoch.AsUint64(),
		Sender:  framing.Sender{Type: framing.SenderTypeMember, LeafIndex: uint32(g.OwnLeafIndex)},
		Body:    framing.CommitBody{Data: commit.Marshal()},
	}

	groupContextBytes := g.GroupContext.Marshal()
	ac := &framing.AuthenticatedContent{
		WireFormat:   wireFormat,
		Content:      content,
		GroupContext: groupContextBytes,
	}

	// Sign the TBS con label (RFC §6.1 / §5.1.2)
	sig, err := ciphersuite.SignWithLabel(sigPrivKey, "FramedContentTBS", ac.MarshalTBS())
	if err != nil {
		return nil, fmt.Errorf("signing commit: %w", err)
	}
	ac.Auth.Signature = sig

	// 6. Compute confirmed_transcript_hash (RFC §8.2)
	cthi, err := framing.NewConfirmedTranscriptHashInput(ac)
	if err != nil {
		return nil, fmt.Errorf("creating transcript hash input: %w", err)
	}
	confirmedHash, err := cthi.Compute(g.CipherSuite, g.InterimTranscriptHash)
	if err != nil {
		return nil, fmt.Errorf("computing confirmed transcript hash: %w", err)
	}

	// Build provisional GroupContext para el nuevo epoch
	newTreeHash := treeDiff.TreeHash()
	newGC := &GroupContext{
		Version:                 g.GroupContext.Version,
		CipherSuite:             g.CipherSuite,
		GroupID:                 g.GroupContext.GroupID,
		Epoch:                   NewGroupEpoch(g.Epoch.AsUint64() + 1),
		TreeHash:                newTreeHash,
		ConfirmedTranscriptHash: confirmedHash,
		Extensions:              g.GroupContext.Extensions,
	}

	// Advance key schedule to compute confirmation_key del nuevo epoch
	newGCBytes := newGC.Marshal()
	fmt.Printf("[DEBUG Commit] newTreeHash: %x\n", newTreeHash)
	fmt.Printf("[DEBUG Commit] confirmedHash: %x\n", confirmedHash)
	fmt.Printf("[DEBUG Commit] newGCBytes: %x\n", newGCBytes)
	fmt.Printf("[DEBUG Commit] initSecret first4: %x\n", g.EpochSecrets.InitSecret.AsSlice()[:4])
	fmt.Printf("[DEBUG Commit] commitSecret first4: %x\n", commitSecret.AsSlice()[:4])
	newKS := schedule.NewKeySchedule(g.CipherSuite, g.EpochSecrets.InitSecret)
	newKS.SetCommitSecret(commitSecret)
	if _, err = newKS.ComputeJoinerSecret(newGCBytes); err != nil {
		return nil, fmt.Errorf("new epoch joiner secret: %w", err)
	}
	if _, err = newKS.ComputePskSecret(psks); err != nil {
		return nil, fmt.Errorf("new epoch psk secret: %w", err)
	}
	if _, err = newKS.ComputeEpochSecret(newGCBytes); err != nil {
		return nil, fmt.Errorf("new epoch epoch secret: %w", err)
	}
	newEpochSecrets, err := newKS.DeriveEpochSecrets()
	if err != nil {
		return nil, fmt.Errorf("deriving new epoch secrets: %w", err)
	}

	// confirmation_tag = MAC(confirmation_key, confirmed_transcript_hash) (RFC §8.2)
	confirmationTag := schedule.ComputeConfirmationTag(
		g.CipherSuite,
		newEpochSecrets.ConfirmationKey.AsSlice(),
		confirmedHash,
	)
	fmt.Printf("[DEBUG Commit] confirmationTag first4: %x\n", confirmationTag[:4])
	ac.Auth.ConfirmationTag = confirmationTag

	newInterimHash := schedule.ComputeInterimTranscriptHash(g.CipherSuite, confirmedHash, confirmationTag)

	// 7. Create StagedCommit with precomputed values for committer
	stagedCommit := &StagedCommit{
		Commit:                  commit,
		Proposals:               proposals,
		AuthenticatedContent:    ac,
		RootPathSecret:          commitSecret,
		PrecomputedEpochSecrets: newEpochSecrets,
		PrecomputedGroupContext: newGC,
		PrecomputedInterimHash:  newInterimHash,
	}

	g.PendingCommit = stagedCommit
	g.state = StatePendingCommit

	return stagedCommit, nil
}

// filteredDirectPathLevels returns the direct path, copath, and the subset of
// copath indices where the resolution is non-empty (RFC §12.4.1: UpdatePath.Nodes
// only covers parents whose sibling's resolution is non-empty).
func filteredDirectPathLevels(tree *treesync.RatchetTree, senderLeafIdx treesync.LeafIndex) (directPath, copath []treesync.NodeIndex, levels []int) {
	return filteredDirectPathLevelsExcluding(tree, senderLeafIdx, nil)
}

func filteredDirectPathLevelsExcluding(tree *treesync.RatchetTree, senderLeafIdx treesync.LeafIndex, excluded map[treesync.LeafIndex]bool) (directPath, copath []treesync.NodeIndex, levels []int) {
	directPath = tree.DirectPath(senderLeafIdx)
	copath = tree.Copath(senderLeafIdx)
	levels = make([]int, 0, len(copath))
	for i, copathNode := range copath {
		if len(tree.ResolutionWithExclusions(copathNode, excluded)) > 0 {
			levels = append(levels, i)
		}
	}
	return directPath, copath, levels
}

// createUpdatePath genera un UpdatePath real (RFC §12.4.1).
// Uses filtered direct path: only levels where the copath sibling has non-empty
// resolution get a new encryption key and an UpdatePathNode entry.
// Path secrets are indexed as pathSecrets[N-F+m] for filtered level m, so that
// DeriveSecret^(F-m)(pathSecrets[N-F+m]) == pathSecrets[N] == commitSecret.
func (g *Group) createUpdatePath(
	tree *treesync.RatchetTree,
	sigPrivKey *ciphersuite.SignaturePrivateKey,
	sigPubKey *ciphersuite.SignaturePublicKey,
	excluded map[treesync.LeafIndex]bool, // newly added leaves excluded from UpdatePath encryption (RFC §12.4.1)
) (*UpdatePath, *ciphersuite.Secret, error) {
	leafSecret, err := ciphersuite.NewSecretRandomCS(g.CipherSuite)
	if err != nil {
		return nil, nil, err
	}

	senderLeafIdx := treesync.LeafIndex(g.OwnLeafIndex)
	directPath := tree.DirectPath(senderLeafIdx)
	N := len(directPath) - 1

	// Derive path secrets for all N non-leaf levels.
	pathSecrets := make([]*ciphersuite.Secret, N+1)
	pathSecrets[0] = leafSecret
	for i := 1; i <= N; i++ {
		pathSecrets[i], err = pathSecrets[i-1].DeriveSecret(g.CipherSuite, "path")
		if err != nil {
			return nil, nil, err
		}
	}

	// Compute filtered levels excluding newly added leaves (RFC §12.4.1).
	// New members receive the commit_secret via Welcome, not via UpdatePath.
	_, copath, levels := filteredDirectPathLevelsExcluding(tree, senderLeafIdx, excluded)
	F := len(levels)

	// Apply encryption keys to filtered parent nodes (RFC §12.4.1).
	pubKeys := make([][]byte, F)
	for m, level := range levels {
		ps := pathSecrets[N-F+m]
		nodeSecret, _ := ps.DeriveSecret(g.CipherSuite, "node")
		privKey, _ := ciphersuite.DeriveKeyPair(g.CipherSuite, nodeSecret.AsSlice())
		pubKeys[m] = privKey.PublicKey().Bytes()

		nodeIdx := directPath[level+1]
		tree.Nodes[nodeIdx].EncryptionKey, _ = ecdh.P256().NewPublicKey(pubKeys[m])
		tree.Nodes[nodeIdx].State = treesync.NodeStatePresent
		tree.Nodes[nodeIdx].UnmergedLeaves = nil
	}

	// Compute parent hashes top-down (RFC §7.9).
	// Blank/empty parents pass through their parent_hash; present parents compute it.
	rootIdx := tree.Root()
	tree.Nodes[rootIdx].ParentHash = []byte{}
	for i := len(directPath) - 2; i >= 0; i-- {
		nodeIdx := directPath[i]
		parentIdx, _ := tree.Parent(nodeIdx)
		parent := &tree.Nodes[parentIdx]
		var ph []byte
		if parent.State == treesync.NodeStatePresent {
			var parentKey []byte
			if parent.EncryptionKey != nil {
				parentKey = parent.EncryptionKey.Bytes()
			}
			siblingIdx := tree.GetSibling(nodeIdx)
			siblingHash := tree.HashNode(siblingIdx)
			ph = treesync.ComputeParentHash(parentKey, parent.ParentHash, siblingHash)
		} else {
			ph = parent.ParentHash
		}
		tree.Nodes[nodeIdx].ParentHash = ph
	}

	var caps *treesync.LeafNodeCapabilities
	if ownLeaf := g.RatchetTree.GetLeaf(senderLeafIdx); ownLeaf != nil && ownLeaf.LeafData != nil {
		caps = ownLeaf.LeafData.Capabilities
	}
	if caps == nil {
		caps = &treesync.LeafNodeCapabilities{}
	}

	// Determine signature key bytes to embed in the leaf node.
	// For ECDSA: convert to *ecdsa.PublicKey (and keep raw bytes nil).
	// For Ed25519: store raw bytes only (SignatureKey stays nil).
	var sigPubKeyECDSA *ecdsa.PublicKey
	var sigPubKeyRaw []byte
	rawSigPub := sigPubKey.AsSlice()
	if len(rawSigPub) == 65 && rawSigPub[0] == 0x04 {
		// ECDSA uncompressed point
		converted, err := sigPubKey.ToECDSA()
		if err != nil {
			return nil, nil, fmt.Errorf("converting signature public key: %w", err)
		}
		sigPubKeyECDSA = converted
	} else {
		// Ed25519 or other: store raw bytes
		sigPubKeyRaw = append([]byte(nil), rawSigPub...)
	}

	// Derive leaf HPKE key pair from node_secret = DeriveSecret(leafSecret, "node") (RFC §12.4.2).
	leafNodeSecret, err := leafSecret.DeriveSecret(g.CipherSuite, "node")
	if err != nil {
		return nil, nil, fmt.Errorf("deriving leaf node secret: %w", err)
	}
	leafPrivKey, err := ciphersuite.DeriveKeyPair(g.CipherSuite, leafNodeSecret.AsSlice())
	if err != nil {
		return nil, nil, fmt.Errorf("deriving leaf key pair: %w", err)
	}
	leafNodeData := &treesync.LeafNodeData{
		EncryptionKey:   leafPrivKey.PublicKey().Bytes(),
		SignatureKey:    sigPubKeyECDSA,
		SignatureKeyRaw: sigPubKeyRaw,
		Credential:      g.Members[g.OwnLeafIndex].Credential,
		Capabilities:    caps,
		Lifetime:        &treesync.LeafNodeLifetime{},
		LeafNodeSource:  3,
		ParentHash:      tree.Nodes[directPath[0]].ParentHash,
	}
	// source=commit; TBS includes group_id + leaf_index per RFC §7.2.
	tbs := leafNodeData.MarshalTBSWithContext(g.GroupContext.GroupID.AsSlice(), uint32(senderLeafIdx))
	sig, err := ciphersuite.SignWithLabel(sigPrivKey, "LeafNodeTBS", tbs)
	if err != nil {
		return nil, nil, fmt.Errorf("signing leaf node TBS: %w", err)
	}
	leafNodeData.Signature = sig.AsSlice()

	fmt.Printf("[DEBUG sender] treeDiff hash before SetLeaf: %x\n", tree.TreeHash())
	// Apply leaf to tree for provisional tree hash computation.
	if err := tree.SetLeaf(senderLeafIdx, *leafNodeData); err != nil {
		return nil, nil, fmt.Errorf("setting leaf in tree: %w", err)
	}
	fmt.Printf("[DEBUG sender] treeDiff hash after SetLeaf: %x\n", tree.TreeHash())

	// Compute provisional GroupContext (RFC §12.4.1: next epoch + tree_hash_after).
	provGCBytes := (&GroupContext{
		Version:                 g.GroupContext.Version,
		CipherSuite:             g.GroupContext.CipherSuite,
		GroupID:                 g.GroupContext.GroupID,
		Epoch:                   NewGroupEpoch(g.GroupContext.Epoch.AsUint64() + 1),
		TreeHash:                tree.TreeHash(),
		ConfirmedTranscriptHash: g.GroupContext.ConfirmedTranscriptHash,
		Extensions:              g.GroupContext.Extensions,
	}).Marshal()
	fmt.Printf("[DEBUG createUpdatePath] provGCBytes: %x\n", provGCBytes)

	// Encrypt path secrets for each filtered level using provisional GC as context.
	nodes := make([]UpdatePathNode, F)
	for m, level := range levels {
		ps := pathSecrets[N-F+m]
		res := tree.ResolutionWithExclusions(copath[level], excluded)
		encryptedSecrets := make([]ciphersuite.HpkeCiphertext, len(res))
		for j, resIdx := range res {
			resNode := &tree.Nodes[resIdx]
			var encKeyBytes []byte
			if treesync.IsLeaf(resIdx) {
				if resNode.LeafData != nil {
					encKeyBytes = resNode.LeafData.EncryptionKey
				}
			} else if resNode.EncryptionKey != nil {
				encKeyBytes = resNode.EncryptionKey.Bytes()
			}
			if len(encKeyBytes) == 0 {
				continue
			}
			ct, err := ciphersuite.EncryptWithLabel(encKeyBytes, "UpdatePathNode", provGCBytes, ps.AsSlice(), g.CipherSuite)
			if err != nil {
				return nil, nil, err
			}
			fmt.Printf("[DEBUG enc] resIdx=%d j=%d encKey first4=%x kem first4=%x ciph first4=%x\n", resIdx, j, encKeyBytes[:min(4, len(encKeyBytes))], ct.KEMOutput[:min(4, len(ct.KEMOutput))], ct.Ciphertext[:min(4, len(ct.Ciphertext))])
			encryptedSecrets[j] = *ct
		}
		nodes[m] = UpdatePathNode{
			EncryptionKey:        pubKeys[m],
			EncryptedPathSecrets: encryptedSecrets,
		}
	}

	// Store new leaf private key so MergeCommit can update MyLeafEncryptionKey.
	g.MyLeafEncryptionKey = leafPrivKey.Bytes()

	commitSecret := pathSecrets[N]
	return &UpdatePath{LeafNode: leafNodeData, Nodes: nodes}, commitSecret, nil
}

// provisionalGroupContextBytes computes the GroupContext bytes with the provisional tree hash.
// RFC 9420 §12.4.1: UpdatePathNode HPKE context = serialized GroupContext where
// tree_hash = hash(tree after applying proposals + full UpdatePath).
// If treeAlreadyDiff != nil, uses that tree as the base (for external commits).
// buildProvisionalTree applies the UpdatePath changes to a tree:
// 1. Set committer's leaf from UpdatePath.LeafNode
// 2. Blank committer's direct path intermediates
// 3. Apply UpdatePath encryption keys at filtered levels
// 4. Recompute parent_hash fields
// The returned tree is a clone — the input tree is not modified.
func buildProvisionalTree(tree *treesync.RatchetTree, senderLeafIdx treesync.LeafIndex, path *UpdatePath, excluded map[treesync.LeafIndex]bool) *treesync.RatchetTree {
	provTree := tree.Clone()

	if path.LeafNode != nil {
		_ = provTree.SetLeaf(senderLeafIdx, *path.LeafNode)
	}

	// RFC §12.4.2 step 6: Blank ALL intermediate nodes on the committer's direct path.
	provDP := provTree.DirectPath(senderLeafIdx)
	for i := 1; i < len(provDP); i++ {
		provTree.BlankNode(provDP[i])
	}

	// Apply UpdatePath parent nodes using filtered direct path (RFC §12.4.1).
	provDP, _, provLevels := filteredDirectPathLevelsExcluding(provTree, senderLeafIdx, excluded)
	for m, level := range provLevels {
		if m >= len(path.Nodes) {
			break
		}
		dpNodeIdx := provDP[level+1]
		encKeyBytes := path.Nodes[m].EncryptionKey
		if len(encKeyBytes) > 0 {
			if pubKey, err := ecdh.P256().NewPublicKey(encKeyBytes); err == nil {
				provTree.Nodes[dpNodeIdx].EncryptionKey = pubKey
				provTree.Nodes[dpNodeIdx].State = treesync.NodeStatePresent
				provTree.Nodes[dpNodeIdx].UnmergedLeaves = nil
			}
		}
	}

	// Recompute parent_hash fields top-down for correct tree hash (RFC §7.9).
	if len(provDP) > 1 {
		rootIdx := provTree.Root()
		provTree.Nodes[rootIdx].ParentHash = []byte{}
		for k := len(provDP) - 2; k >= 0; k-- {
			childIdx := provDP[k]
			parentIdx := provDP[k+1]
			parent := &provTree.Nodes[parentIdx]
			var parentHash []byte
			if parent.State == treesync.NodeStatePresent {
				var parentKey []byte
				if parent.EncryptionKey != nil {
					parentKey = parent.EncryptionKey.Bytes()
				}
				siblingIdx := provTree.GetSibling(childIdx)
				siblingHash := provTree.HashNode(siblingIdx)
				parentHash = treesync.ComputeParentHash(parentKey, parent.ParentHash, siblingHash)
			} else {
				parentHash = parent.ParentHash
			}
			if !treesync.IsLeaf(childIdx) {
				provTree.Nodes[childIdx].ParentHash = parentHash
			}
		}
	}

	return provTree
}

// provisionalGroupContextBytesFromTree computes the provisional GroupContext
// from an already-built provisional tree.
func (g *Group) provisionalGroupContextBytesFromTree(provTree *treesync.RatchetTree) []byte {
	provGC := &GroupContext{
		Version:                 g.GroupContext.Version,
		CipherSuite:             g.GroupContext.CipherSuite,
		GroupID:                 g.GroupContext.GroupID,
		Epoch:                   NewGroupEpoch(g.GroupContext.Epoch.AsUint64() + 1),
		TreeHash:                provTree.TreeHash(),
		ConfirmedTranscriptHash: g.GroupContext.ConfirmedTranscriptHash,
		Extensions:              g.GroupContext.Extensions,
	}
	return provGC.Marshal()
}

// applyProposalToTree applies a proposal to a specific RatchetTree.
func (g *Group) applyProposalToTree(proposal *Proposal, tree *treesync.RatchetTree, senderIdx LeafNodeIndex) error {
	switch proposal.Type {
	case ProposalTypeAdd:
		leafData := *keyPackageLeafToTreeSync(proposal.Add.KeyPackage.LeafNode)
		tree.AddLeaf(leafData)
	case ProposalTypeRemove:
		removedLeaf := treesync.LeafIndex(proposal.Remove.Removed)
		for _, nodeIdx := range tree.DirectPath(removedLeaf) {
			tree.BlankNode(nodeIdx)
		}
		tree.TruncateTrailingBlanks()
	case ProposalTypeUpdate:
		leafIdx := treesync.LeafIndex(senderIdx)
		leafData := *keyPackageLeafToTreeSync(proposal.Update.LeafNode)
		if err := tree.SetLeaf(leafIdx, leafData); err != nil {
			return fmt.Errorf("setting leaf for update proposal: %w", err)
		}
		path := tree.DirectPath(leafIdx)
		for i := 1; i < len(path); i++ {
			tree.BlankNode(path[i])
		}
	case ProposalTypeGroupContextExtensions:
		if proposal.GroupContextExtensions != nil {
			g.GroupContext.Extensions = proposal.GroupContextExtensions.Extensions
		}
	}
	return nil
}

// ProcessCommit processes a received commit.
// RFC 9420 §12.4.2
func (g *Group) ProcessCommit(stagedCommit *StagedCommit) error {
	if stagedCommit.AuthenticatedContent == nil {
		return fmt.Errorf("missing authenticated content")
	}
	return g.MergeCommit(stagedCommit)
}

// StoreProposal stores a proposal indexed by hash reference for future resolution (RFC 9420 §12.4).
// acBytes must be the serialized AuthenticatedContent of the proposal's PublicMessage.
func (g *Group) StoreProposal(p *Proposal, sender LeafNodeIndex, acBytes []byte) []byte {
	if g.ProposalByRef == nil {
		g.ProposalByRef = make(map[string]*Proposal)
	}
	ref := ComputeProposalRef(acBytes, g.CipherSuite)
	g.ProposalByRef[string(ref)] = p
	g.Proposals.AddProposal(p, sender)
	return ref
}

// ProcessReceivedCommit processes a commit sent by another member.
// Decrypts the path secret using the receiver's private HPKE key,
// then advances the group state. RFC 9420 §12.4.2
func (g *Group) ProcessReceivedCommit(
	ac *framing.AuthenticatedContent,
	senderLeafIdx treesync.LeafIndex,
	myHpkePrivKeyBytes []byte,
) error {
	// RFC §12.4.1: validar GroupID y epoch antes de cualquier trabajo costoso.
	if !bytes.Equal(ac.Content.GroupID, g.GroupContext.GroupID.AsSlice()) {
		return fmt.Errorf("group_id mismatch: message has %x, group is %x",
			ac.Content.GroupID, g.GroupContext.GroupID.AsSlice())
	}
	if ac.Content.Epoch != g.GroupContext.Epoch.AsUint64() {
		return fmt.Errorf("epoch mismatch: commit has %d, group is at %d",
			ac.Content.Epoch, g.GroupContext.Epoch.AsUint64())
	}

	commitBody, ok := ac.Content.Body.(framing.CommitBody)
	if !ok {
		return fmt.Errorf("not a commit message")
	}

	commit, err := UnmarshalCommit(commitBody.Data)
	if err != nil {
		return fmt.Errorf("unmarshaling commit: %w", err)
	}

	switch ac.Content.Sender.Type {
	case framing.SenderTypeMember:
		// RFC §12.4.2: verify signature using the sender's leaf key from the tree.
		senderLeaf := g.RatchetTree.GetLeaf(senderLeafIdx)
		if senderLeaf == nil || senderLeaf.LeafData == nil {
			return fmt.Errorf("missing sender signature key")
		}
		rawKey := senderLeaf.LeafData.SigKeyBytes()
		if len(rawKey) == 0 {
			return fmt.Errorf("missing sender signature key")
		}
		pubKey := ciphersuite.NewOpenMlsSignaturePublicKey(rawKey, g.CipherSuite.SignatureScheme())
		if err := ciphersuite.VerifyWithLabel(pubKey, "FramedContentTBS", ac.MarshalTBS(), ac.Auth.Signature); err != nil {
			return fmt.Errorf("commit signature verification failed: %w", err)
		}
	case framing.SenderTypeNewMemberCommit:
		// RFC §12.4.3.2: external committer's key is in the UpdatePath LeafNode.
		if commit.Path == nil || commit.Path.LeafNode == nil {
			return fmt.Errorf("external commit missing leaf node signature key")
		}
		rawKey := commit.Path.LeafNode.SigKeyBytes()
		if len(rawKey) == 0 {
			return fmt.Errorf("external commit missing leaf node signature key")
		}
		pubKey := ciphersuite.NewOpenMlsSignaturePublicKey(rawKey, g.CipherSuite.SignatureScheme())
		if err := ciphersuite.VerifyWithLabel(pubKey, "FramedContentTBS", ac.MarshalTBS(), ac.Auth.Signature); err != nil {
			return fmt.Errorf("external commit signature verification failed: %w", err)
		}
	}

	// Resolver proposals: inline o por referencia hash.
	// Also collect per-proposal sender so we can apply them correctly to the tree.
	proposals := make([]*Proposal, 0, len(commit.Proposals))
	proposalSenders := make([]LeafNodeIndex, 0, len(commit.Proposals))
	for _, por := range commit.Proposals {
		if por.Proposal != nil {
			proposals = append(proposals, por.Proposal)
			proposalSenders = append(proposalSenders, LeafNodeIndex(senderLeafIdx))
		} else if len(por.ProposalRef) > 0 {
			if p, ok := g.ProposalByRef[string(por.ProposalRef)]; ok {
				proposals = append(proposals, p)
				// Look up sender stored when the proposal was received.
				sender := LeafNodeIndex(senderLeafIdx) // fallback: committer
				for _, sp := range g.Proposals.Proposals {
					if sp.Proposal == p {
						sender = sp.Sender
						break
					}
				}
				proposalSenders = append(proposalSenders, sender)
			} else {
				return fmt.Errorf("unknown proposal reference in commit")
			}
		}
	}

	// RFC §12.4.2: Sort proposals by type before applying.
	// Order: GCE → Update → Remove → Add → PSK → ReInit → ExternalInit.
	sortProposalsByRFCOrder(proposals, proposalSenders)

	// Build tree with proposals applied, tracking newly added leaves (exclusion list).
	fmt.Printf("[DEBUG ProcessReceivedCommit] g.RatchetTree.TreeHash before proposals: %x\n", g.RatchetTree.TreeHash())
	treeAfterProposals := g.RatchetTree.Clone()
	excluded := make(map[treesync.LeafIndex]bool)
	for i, p := range proposals {
		if p.Type == ProposalTypeAdd && p.Add != nil && p.Add.KeyPackage != nil && p.Add.KeyPackage.LeafNode != nil {
			leafData := *keyPackageLeafToTreeSync(p.Add.KeyPackage.LeafNode)
			addedIdx, _ := treeAfterProposals.AddLeaf(leafData)
			excluded[addedIdx] = true
		} else {
			if err := g.applyProposalToTree(p, treeAfterProposals, proposalSenders[i]); err != nil {
				return fmt.Errorf("applying proposal %d to provisional tree: %w", i, err)
			}
		}
	}

	// Decrypt path secret with our HPKE private key.
	var rootPathSecret *ciphersuite.Secret
	if ac.Content.Sender.Type == framing.SenderTypeNewMemberCommit {
		if commit.Path == nil || commit.Path.LeafNode == nil {
			return fmt.Errorf("external commit missing update path")
		}
		extLeafIdx, _ := treeAfterProposals.AddLeaf(*commit.Path.LeafNode)
		senderLeafIdx = extLeafIdx
		provTree := buildProvisionalTree(treeAfterProposals, senderLeafIdx, commit.Path, excluded)
		provGCBytes := g.provisionalGroupContextBytesFromTree(provTree)
		rootPathSecret, err = g.decryptPathSecret(provTree, senderLeafIdx, commit.Path, myHpkePrivKeyBytes, provGCBytes, excluded)
		if err != nil {
			return fmt.Errorf("decrypting path secret (external): %w", err)
		}
	} else if commit.Path != nil {
		fmt.Printf("[DEBUG receiver] treeAfterProposals hash: %x\n", treeAfterProposals.TreeHash())
		provTree := buildProvisionalTree(treeAfterProposals, senderLeafIdx, commit.Path, excluded)
		provGCBytes := g.provisionalGroupContextBytesFromTree(provTree)
		fmt.Printf("[DEBUG ProcessReceivedCommit] provGCBytes: %x\n", provGCBytes)
		rootPathSecret, err = g.decryptPathSecret(provTree, senderLeafIdx, commit.Path, myHpkePrivKeyBytes, provGCBytes, excluded)
		if err != nil {
			return fmt.Errorf("decrypting path secret: %w", err)
		}
	}

	staged := &StagedCommit{
		Commit:               commit,
		Proposals:            proposals,
		ProposalSenders:      proposalSenders,
		AuthenticatedContent: ac,
		RootPathSecret:       rootPathSecret,
	}
	return g.MergeCommit(staged)
}

// decryptPathSecret decrypts the path secret from an UpdatePath for this receiver.
// Traverse the sender's filtered copath looking for the receiver's node in the resolution,
// decrypts with HPKE and derives forward to obtain the commit_secret.
// RFC 9420 §12.4.1: UpdatePath.Nodes has F entries (filtered levels only);
// nodes[m] encrypts pathSecrets[N-F+m], so derive F-m times to reach commitSecret.
func (g *Group) decryptPathSecret(
	tree *treesync.RatchetTree,
	senderLeafIdx treesync.LeafIndex,
	updatePath *UpdatePath,
	myPrivKeyBytes []byte,
	gcBytes []byte, // provisional GroupContext bytes (RFC §12.4.1: context for HPKE)
	excluded map[treesync.LeafIndex]bool, // newly added leaves to exclude from resolution
) (*ciphersuite.Secret, error) {
	_, copath, levels := filteredDirectPathLevelsExcluding(tree, senderLeafIdx, excluded)
	F := len(levels)
	myNodeIdx := treesync.LeafIndexToNodeIndex(treesync.LeafIndex(g.OwnLeafIndex))

	for m, level := range levels {
		res := tree.ResolutionWithExclusions(copath[level], excluded)
		for j, resIdx := range res {
			if resIdx != myNodeIdx {
				continue
			}
			if m >= len(updatePath.Nodes) || j >= len(updatePath.Nodes[m].EncryptedPathSecrets) {
				return nil, fmt.Errorf("path secret index out of bounds at filtered level %d", m)
			}
			ct := &updatePath.Nodes[m].EncryptedPathSecrets[j]
			fmt.Printf("[DEBUG dec] m=%d j=%d kem first4=%x ciph first4=%x myPriv first4=%x\n", m, j, ct.KEMOutput[:min(4, len(ct.KEMOutput))], ct.Ciphertext[:min(4, len(ct.Ciphertext))], myPrivKeyBytes[:min(4, len(myPrivKeyBytes))])
			psBytes, err := ciphersuite.DecryptWithLabel(
				myPrivKeyBytes,
				"UpdatePathNode",
				gcBytes,
				ct,
				g.CipherSuite,
			)
			if err != nil {
				return nil, fmt.Errorf("decrypting path secret at level %d: %w", level+1, err)
			}
			// Derive forward F-m times to reach commitSecret = pathSecrets[N].
			pathSecret := ciphersuite.NewSecret(psBytes)
			for k := m; k < F; k++ {
				pathSecret, err = pathSecret.DeriveSecret(g.CipherSuite, "path")
				if err != nil {
					return nil, err
				}
			}
			return pathSecret, nil
		}
	}
	return nil, fmt.Errorf("own leaf not found in any copath resolution")
}

// MergeCommit applies a commit and advances the protocol state
// RFC 9420 §12.4.2
func (g *Group) MergeCommit(stagedCommit *StagedCommit) error {
	if g.state != StatePendingCommit && g.state != StateOperational {
		return fmt.Errorf("group not in valid state for commit: %w", ErrInvalidGroupState)
	}

	// PHASE 1.2: Epoch validation (RFC 9420 §12.4.1)
	// PHASE 1.3: GroupID validation (RFC 9420 §12.4.1)
	if stagedCommit.AuthenticatedContent != nil {
		// Validar GroupID
		if !bytes.Equal(stagedCommit.AuthenticatedContent.Content.GroupID, g.GroupContext.GroupID.AsSlice()) {
			return fmt.Errorf("group_id mismatch: message has %x, group is %x",
				stagedCommit.AuthenticatedContent.Content.GroupID, g.GroupContext.GroupID.AsSlice())
		}

		// Validar epoch
		if stagedCommit.AuthenticatedContent.Content.Epoch != g.GroupContext.Epoch.AsUint64() {
			return fmt.Errorf("epoch mismatch: commit has %d, group is at %d",
				stagedCommit.AuthenticatedContent.Content.Epoch, g.GroupContext.Epoch.AsUint64())
		}

		// PHASE 1.1: Signature verification for member commits
		// (external commits are already verified when processing the UpdatePath)
		senderType := stagedCommit.AuthenticatedContent.Content.Sender.Type
		if senderType == framing.SenderTypeMember {
			senderLeafIdx := treesync.LeafIndex(stagedCommit.AuthenticatedContent.Content.Sender.LeafIndex)
			senderLeaf := g.RatchetTree.GetLeaf(senderLeafIdx)
			if senderLeaf == nil || senderLeaf.LeafData == nil {
				return fmt.Errorf("missing sender signature key for commit verification")
			}
			rawKey := senderLeaf.LeafData.SigKeyBytes()
			if len(rawKey) == 0 {
				return fmt.Errorf("missing sender signature key for commit verification")
			}
			pubKey := ciphersuite.NewOpenMlsSignaturePublicKey(rawKey, g.CipherSuite.SignatureScheme())
			ac := &framing.AuthenticatedContent{
				WireFormat:   stagedCommit.AuthenticatedContent.WireFormat,
				Content:      stagedCommit.AuthenticatedContent.Content,
				Auth:         stagedCommit.AuthenticatedContent.Auth,
				GroupContext: g.GroupContext.Marshal(),
			}
			if err := ciphersuite.VerifyWithLabel(pubKey, "FramedContentTBS", ac.MarshalTBS(), stagedCommit.AuthenticatedContent.Auth.Signature); err != nil {
				return fmt.Errorf("commit signature verification failed: %w", err)
			}
		}
	}

	// 1. Apply proposals to the ratchet tree
	senderIdx := g.OwnLeafIndex
	if stagedCommit.AuthenticatedContent != nil {
		if stagedCommit.AuthenticatedContent.Content.Sender.Type == framing.SenderTypeNewMemberCommit {
			if stagedCommit.Commit == nil || stagedCommit.Commit.Path == nil || stagedCommit.Commit.Path.LeafNode == nil {
				return fmt.Errorf("external commit missing update path")
			}

			fmt.Printf("[DEBUG MergeCommit] Before AddLeaf: NumLeaves=%d, tree size=%d\n", g.RatchetTree.NumLeaves, len(g.RatchetTree.Nodes))
			extLeafIdx, extNodeIdx := g.RatchetTree.AddLeaf(*stagedCommit.Commit.Path.LeafNode)
			senderIdx = LeafNodeIndex(extLeafIdx)
			fmt.Printf("[DEBUG MergeCommit] After AddLeaf: extLeafIdx=%d, extNodeIdx=%d, NumLeaves=%d, tree size=%d\n", extLeafIdx, extNodeIdx, g.RatchetTree.NumLeaves, len(g.RatchetTree.Nodes))
			fmt.Printf("[DEBUG MergeCommit] External commit sender leaf node index: %d\n", senderIdx)
		} else {
			senderIdx = LeafNodeIndex(stagedCommit.AuthenticatedContent.Content.Sender.LeafIndex)
		}
	}
	for i, proposal := range stagedCommit.Proposals {
		// Use per-proposal sender if available (from ProcessReceivedCommit),
		// otherwise fall back to committer index (self-commit path).
		proposalSender := senderIdx
		if len(stagedCommit.ProposalSenders) > i {
			proposalSender = stagedCommit.ProposalSenders[i]
		}
		if err := g.applyProposal(proposal, proposalSender); err != nil {
			return fmt.Errorf("applying proposal: %w", err)
		}
	}

	hasReInit := false
	for _, proposal := range stagedCommit.Proposals {
		if proposal.Type == ProposalTypeReInit {
			hasReInit = true
			break
		}
	}

	var psks []schedule.Psk
	for _, proposal := range stagedCommit.Proposals {
		if proposal.Type == ProposalTypePreSharedKey && proposal.PreSharedKey != nil {
			pid := proposal.PreSharedKey.PskID
			var pskBytes []byte
			var err error
			if pid.PskType == 2 { // Resumption PSK
				resumptionKey := resumptionPskCacheKey(pid.PskGroupID, pid.PskEpoch)
				var ok bool
				pskBytes, ok = g.CachedPsks[resumptionKey]
				if !ok {
					// Try to resolve from PSKStore if available
					if g.PSKStore != nil {
						resolver := NewPSKResolver(g.PSKStore)
						pskBytes, err = resolver.ResolvePSK(&pid)
						if err != nil {
							return fmt.Errorf("resolving resumption PSK: %w", err)
						}
					} else {
						return fmt.Errorf("missing resumption PSK for group=%x epoch=%d", pid.PskGroupID, pid.PskEpoch)
					}
				}
				psks = append(psks, schedule.Psk{
					Psk:        pskBytes,
					PskID:      pid.ID,
					PskNonce:   pid.Nonce,
					PskType:    schedule.PskType(pid.PskType),
					Usage:      pid.Usage,
					PskGroupID: pid.PskGroupID,
					PskEpoch:   pid.PskEpoch,
				})
			} else { // External o Branch PSK
				pskBytes, ok := g.CachedPsks[string(pid.ID)]
				if !ok && g.PSKStore != nil {
					pskBytes, err = g.PSKStore.GetPSK(pid.ID)
					if err != nil {
						return fmt.Errorf("resolving PSK from store: %w", err)
					}
				} else if !ok {
					return fmt.Errorf("missing PSK for proposal: %x", pid.ID)
				}
				psks = append(psks, schedule.Psk{
					Psk:      pskBytes,
					PskID:    pid.ID,
					PskNonce: pid.Nonce,
					PskType:  schedule.PskType(pid.PskType),
					Usage:    pid.Usage,
				})
			}
		}
	}

	// 1.2 Aplicar UpdatePath si existe
	if stagedCommit.Commit.Path != nil {
		senderLeafIdx := treesync.LeafIndex(senderIdx)
		leafNodeData := stagedCommit.Commit.Path.LeafNode

		// RFC §12.4.2: verificar firma del nuevo leaf node del committer (source=commit,
		// TBS incluye group_id y leaf_index per RFC §7.2).
		if err := leafNodeData.VerifyWithContext(g.CipherSuite, g.GroupContext.GroupID.AsSlice(), uint32(senderLeafIdx)); err != nil {
			return fmt.Errorf("UpdatePath leaf node signature invalid: %w", err)
		}

		// Update the sender leaf
		if err := g.RatchetTree.SetLeaf(senderLeafIdx, *leafNodeData); err != nil {
			return fmt.Errorf("setting sender leaf: %w", err)
		}

		// RFC §12.4.2 step 6: Blank ALL intermediate nodes on the committer's
		// direct path before applying the UpdatePath encryption keys.
		mergeDP := g.RatchetTree.DirectPath(senderLeafIdx)
		for i := 1; i < len(mergeDP); i++ {
			g.RatchetTree.BlankNode(mergeDP[i])
		}

		// Update ancestors with new encryption keys (filtered direct path).
		// Re-compute filtered levels after blanking.
		mergeDP, _, mergeLevels := filteredDirectPathLevels(g.RatchetTree, senderLeafIdx)
		for m, level := range mergeLevels {
			if m >= len(stagedCommit.Commit.Path.Nodes) {
				break
			}
			nodeIdx := mergeDP[level+1]
			updateNode := stagedCommit.Commit.Path.Nodes[m]
			node := &g.RatchetTree.Nodes[nodeIdx]
			node.EncryptionKey, _ = ecdh.P256().NewPublicKey(updateNode.EncryptionKey)
			node.State = treesync.NodeStatePresent
			node.UnmergedLeaves = nil
		}

		// Compute parent hashes de arriba abajo y verificar (RFC §7.9)
		// NOTE: For External Commits, we do NOT verify parent hashes because the external
		// sender computed them over their provisional RatchetTree (with their leaf added), which is
		// different from the receiver's RatchetTree before applying the commit.
		if len(mergeDP) > 1 && stagedCommit.AuthenticatedContent.Content.Sender.Type != framing.SenderTypeNewMemberCommit {
			rootIdx := g.RatchetTree.Root()
			g.RatchetTree.Nodes[rootIdx].ParentHash = []byte{}

			for i := len(mergeDP) - 2; i >= 0; i-- {
				nodeIdx := mergeDP[i]
				parentIdx := mergeDP[i+1]
				parent := &g.RatchetTree.Nodes[parentIdx]

				// RFC §7.9: blank/empty parent → pass through; present → compute.
				var ph []byte
				if parent.State == treesync.NodeStatePresent {
					var parentKey []byte
					if parent.EncryptionKey != nil {
						parentKey = parent.EncryptionKey.Bytes()
					}
					siblingIdx := g.RatchetTree.GetSibling(nodeIdx)
					siblingHash := g.RatchetTree.HashNode(siblingIdx)
					ph = treesync.ComputeParentHash(parentKey, parent.ParentHash, siblingHash)
				} else {
					ph = parent.ParentHash
				}

				// Store parent hash in ALL nodes of the direct path (including the leaf)
				g.RatchetTree.Nodes[nodeIdx].ParentHash = ph
			}

			// Verify that direct path parent hashes match with the calculated ones (RFC §7.9)
			if err := g.RatchetTree.VerifyParentHashes(senderLeafIdx); err != nil {
				return fmt.Errorf("parent hash verification failed: %w", err)
			}
		}
	}

	// 2. Recompute TreeHash from treesync
	treeHash := g.RatchetTree.TreeHash()

	// 3. Compute ConfirmedTranscriptHash nuevo
	cthi, err := framing.NewConfirmedTranscriptHashInput(stagedCommit.AuthenticatedContent)
	if err != nil {
		return fmt.Errorf("creating transcript hash input: %w", err)
	}

	confirmedTranscriptHash, err := cthi.Compute(
		g.CipherSuite,
		g.InterimTranscriptHash,
	)
	if err != nil {
		return fmt.Errorf("calculating confirmed transcript hash: %w", err)
	}
	// 4. Compute InterimTranscriptHash nuevo
	itHashInput := &framing.InterimTranscriptHashInput{
		ConfirmationTag: stagedCommit.AuthenticatedContent.Auth.ConfirmationTag,
	}

	interimTranscriptHash := itHashInput.Compute(
		g.CipherSuite,
		confirmedTranscriptHash,
	)

	// 5. Update GroupContext (RFC §8.1)
	g.GroupContext.IncrementEpoch()
	g.GroupContext.UpdateTreeHash(treeHash)
	g.GroupContext.UpdateConfirmedTranscriptHash(confirmedTranscriptHash)

	// Also update Group directly
	g.Epoch = g.GroupContext.Epoch
	g.InterimTranscriptHash = interimTranscriptHash
	g.ConfirmationTag = stagedCommit.AuthenticatedContent.Auth.ConfirmationTag
	// 6. Advance key schedule → new EpochSecrets
	if stagedCommit.PrecomputedEpochSecrets != nil {
		// Committer: use precomputed epoch secrets from Commit()
		g.EpochSecrets = stagedCommit.PrecomputedEpochSecrets
	} else {
		// Receiver: derive from init_secret of the current epoch
		fmt.Printf("[DEBUG MergeCommit receiver] g.EpochSecrets ptr: %p, InitSecret ptr: %p\n", g.EpochSecrets, g.EpochSecrets.InitSecret)
		if g.EpochSecrets.InitSecret != nil {
			fmt.Printf("[DEBUG MergeCommit receiver] InitSecret value[:4]: %x\n", g.EpochSecrets.InitSecret.AsSlice()[:min(4, len(g.EpochSecrets.InitSecret.AsSlice()))])
		}
		initSecretForNewEpoch := g.EpochSecrets.InitSecret
		for _, proposal := range stagedCommit.Proposals {
			if proposal.Type != ProposalTypeExternalInit || proposal.ExternalInit == nil {
				continue
			}
			externalPriv, deriveErr := ciphersuite.DeriveKeyPair(
				g.CipherSuite,
				g.EpochSecrets.ExternalSecret.AsSlice(),
			)
			if deriveErr != nil {
				return fmt.Errorf("deriving external key pair: %w", deriveErr)
			}

			sharedSecretBytes, decapErr := ciphersuite.DecapToBytes(
				proposal.ExternalInit.KemOutput,
				externalPriv.Bytes(),
				g.CipherSuite,
			)
			if decapErr != nil {
				return fmt.Errorf("HPKE decap for external commit: %w", decapErr)
			}

			initSecretForNewEpoch = ciphersuite.NewSecret(sharedSecretBytes)
			break
		}

		var commitSecret *ciphersuite.Secret
		if stagedCommit.Commit != nil && stagedCommit.Commit.Path != nil {
			commitSecret = stagedCommit.RootPathSecret
		} else {
			commitSecret = ciphersuite.ZeroSecret(g.CipherSuite.HashLength())
		}

		newGCBytes := g.GroupContext.Marshal()
		fmt.Printf("[DEBUG MergeCommit] treeHash: %x\n", treeHash)
		fmt.Printf("[DEBUG MergeCommit] confirmedTranscriptHash: %x\n", confirmedTranscriptHash)
		fmt.Printf("[DEBUG MergeCommit] newGCBytes: %x\n", newGCBytes)
		fmt.Printf("[DEBUG MergeCommit] initSecret first4: %x\n", initSecretForNewEpoch.AsSlice()[:4])
		fmt.Printf("[DEBUG MergeCommit] commitSecret first4: %x\n", commitSecret.AsSlice()[:4])
		newKS := schedule.NewKeySchedule(g.CipherSuite, initSecretForNewEpoch)
		newKS.SetCommitSecret(commitSecret)
		if _, err = newKS.ComputeJoinerSecret(newGCBytes); err != nil {
			return fmt.Errorf("computing joiner secret: %w", err)
		}
		if _, err = newKS.ComputePskSecret(psks); err != nil {
			return fmt.Errorf("computing psk secret: %w", err)
		}
		if _, err = newKS.ComputeEpochSecret(newGCBytes); err != nil {
			return fmt.Errorf("computing epoch secret: %w", err)
		}
		var newEpochSecrets *schedule.EpochSecrets
		newEpochSecrets, err = newKS.DeriveEpochSecrets()
		if err != nil {
			return fmt.Errorf("deriving epoch secrets: %w", err)
		}

		// Verify commit confirmation_tag (RFC §12.4.2)
		expectedTag := schedule.ComputeConfirmationTag(
			g.CipherSuite,
			newEpochSecrets.ConfirmationKey.AsSlice(),
			confirmedTranscriptHash,
		)
		fmt.Printf("[DEBUG MergeCommit] expectedTag first4: %x\n", expectedTag[:4])
		fmt.Printf("[DEBUG MergeCommit] commitTag first4: %x\n", stagedCommit.AuthenticatedContent.Auth.ConfirmationTag[:4])
		if !ciphersuite.EqualCT(expectedTag, stagedCommit.AuthenticatedContent.Auth.ConfirmationTag) {
			return fmt.Errorf("confirmation tag mismatch")
		}
		g.EpochSecrets = newEpochSecrets
	}
	// Inicializar key schedule para el próximo epoch
	g.KeySchedule = schedule.NewKeySchedule(g.CipherSuite, g.EpochSecrets.InitSecret)

	// Update secret tree for new epoch
	g.SecretTree, err = secrettree.NewTree(g.EpochSecrets.EncryptionSecret, g.RatchetTree.NumLeaves, g.CipherSuite)
	if err != nil {
		return fmt.Errorf("updating secret tree: %w", err)
	}

	// Cache resumption secret for this epoch (keyed by group_id + epoch)
	// so future resumption PSK proposals can resolve it.
	if g.EpochSecrets.ResumptionSecret != nil {
		if g.CachedPsks == nil {
			g.CachedPsks = make(map[string][]byte)
		}
		rKey := resumptionPskCacheKey(g.GroupContext.GroupID.AsSlice(), g.GroupContext.Epoch.AsUint64())
		g.CachedPsks[rKey] = append([]byte(nil), g.EpochSecrets.ResumptionSecret.AsSlice()...)
	}

	// 7. Clean up state
	g.Proposals.Clear()
	g.ProposalByRef = make(map[string]*Proposal)
	g.PendingCommit = nil
	if hasReInit {
		g.state = StateInactive
	} else {
		g.state = StateOperational
	}
	return nil
}

// resumptionPskCacheKey builds a compound cache key for resumption PSKs
// from (group_id, epoch) per RFC 9420 §8.4.
func resumptionPskCacheKey(groupID []byte, epoch uint64) string {
	buf := make([]byte, len(groupID)+8)
	copy(buf, groupID)
	buf[len(groupID)] = byte(epoch >> 56)
	buf[len(groupID)+1] = byte(epoch >> 48)
	buf[len(groupID)+2] = byte(epoch >> 40)
	buf[len(groupID)+3] = byte(epoch >> 32)
	buf[len(groupID)+4] = byte(epoch >> 24)
	buf[len(groupID)+5] = byte(epoch >> 16)
	buf[len(groupID)+6] = byte(epoch >> 8)
	buf[len(groupID)+7] = byte(epoch)
	return string(buf)
}

// ProcessPublicMessage processes a received PublicMessage (RFC 9420 §6).
//
// This handles proposals and commits sent as public messages, verifying
// signatures and membership tags before processing the content.
func (g *Group) ProcessPublicMessage(pm *framing.PublicMessage) error {
	if pm == nil {
		return fmt.Errorf("public message is nil")
	}

	if err := g.VerifyPublicMessage(pm); err != nil {
		return err
	}

	switch pm.Content.ContentType() {
	case framing.ContentTypeProposal:
		sender := LeafNodeIndex(pm.Content.Sender.LeafIndex)
		if pm.Content.Sender.Type == framing.SenderTypeExternal {
			sender = LeafNodeIndex(g.RatchetTree.NumLeaves + pm.Content.Sender.SenderIndex)
		}
		// Create AuthenticatedContent for validation
		ac := &framing.AuthenticatedContent{
			WireFormat:   framing.WireFormatPublicMessage,
			Content:      pm.Content,
			Auth:         pm.Auth,
			GroupContext: g.GroupContext.Marshal(),
		}
		// Use shared function to process the proposal
		return g.processProposalContent(ac, sender)
	case framing.ContentTypeCommit:
		ac := &framing.AuthenticatedContent{
			WireFormat:   framing.WireFormatPublicMessage,
			Content:      pm.Content,
			Auth:         pm.Auth,
			GroupContext: g.GroupContext.Marshal(),
		}
		senderLeafIdx := treesync.LeafIndex(pm.Content.Sender.LeafIndex)
		return g.ProcessReceivedCommit(ac, senderLeafIdx, g.MyLeafEncryptionKey)
	case framing.ContentTypeApplication:
		return fmt.Errorf("public application messages are not supported")
	default:
		return fmt.Errorf("unsupported public message content type: %d", pm.Content.ContentType())
	}
}

// ProcessPrivateMessage processes a PrivateMessage (proposal or commit) (RFC 9420 §6.3, §12.4).
// Extracts the sender from the encrypted MLSSenderData, verifies the signature, and processes the content.
func (g *Group) ProcessPrivateMessage(pm *framing.PrivateMessage) error {
	if pm == nil {
		return fmt.Errorf("private message is nil")
	}

	if g.EpochSecrets == nil || g.EpochSecrets.SenderDataSecret == nil {
		return fmt.Errorf("sender_data_secret not available")
	}

	// RFC 9420 §6: rechazar mensajes de otra época
	if pm.Epoch != g.GroupContext.Epoch.AsUint64() {
		return fmt.Errorf("wrong epoch: got %d, want %d", pm.Epoch, g.GroupContext.Epoch.AsUint64())
	}

	// decrypt the message and get sender from MLSSenderData
	ac, senderLeafIdx, err := g.decryptPrivateMessage(pm)
	if err != nil {
		return fmt.Errorf("decrypting private message: %w", err)
	}

	// process according to content type
	switch ac.Content.ContentType() {
	case framing.ContentTypeProposal:
		return g.processProposalContent(ac, LeafNodeIndex(senderLeafIdx))
	case framing.ContentTypeCommit:
		return g.ProcessReceivedCommit(ac, senderLeafIdx, g.MyLeafEncryptionKey)
	default:
		return fmt.Errorf("private message with content type %d is not a proposal or commit", ac.Content.ContentType())
	}
}

// decryptPrivateMessage decrypts a PrivateMessage and returns the AuthenticatedContent
// along with the sender leaf index extracted from the MLSSenderData.
func (g *Group) decryptPrivateMessage(pm *framing.PrivateMessage) (*framing.AuthenticatedContent, treesync.LeafIndex, error) {
	// decrypt without verifying signature (sender encrypted in MLSSenderData, still unknown)
	ac, err := framing.Decrypt(pm, framing.DecryptParams{
		CipherSuite:      g.CipherSuite,
		SenderDataSecret: g.EpochSecrets.SenderDataSecret,
		SecretTree:       g.SecretTree,
		SigPubKey:        nil,
		GroupContext:     g.GroupContext.Marshal(),
	})
	if err != nil {
		return nil, 0, err
	}

	// extract sender leaf index from FramedContent (which came from MLSSenderData)
	senderLeafIdx := treesync.LeafIndex(ac.Content.Sender.LeafIndex)

	// verify that the sender exists in the RatchetTree and is active
	senderLeaf := g.RatchetTree.GetLeaf(senderLeafIdx)
	if senderLeaf == nil || senderLeaf.State != treesync.NodeStatePresent {
		return nil, 0, fmt.Errorf("sender %d is not an active member", senderLeafIdx)
	}

	// RFC 9420 §6.1: verificar firma del FramedContent con la clave pública del sender
	rawKey := senderLeaf.LeafData.SigKeyBytes()
	if len(rawKey) == 0 {
		return nil, 0, fmt.Errorf("missing sender signature key")
	}
	pubKey := ciphersuite.NewOpenMlsSignaturePublicKey(rawKey, g.CipherSuite.SignatureScheme())
	if err := ciphersuite.VerifyWithLabel(pubKey, "FramedContentTBS", ac.MarshalTBS(), ac.Auth.Signature); err != nil {
		return nil, 0, fmt.Errorf("private message signature invalid: %w", err)
	}

	return ac, senderLeafIdx, nil
}

// processProposalContent processes the content of a proposal (shared between Public and Private).
func (g *Group) processProposalContent(ac *framing.AuthenticatedContent, sender LeafNodeIndex) error {
	body, ok := ac.Content.Body.(framing.ProposalBody)
	if !ok {
		return fmt.Errorf("invalid proposal body")
	}

	proposal, err := UnmarshalProposal(body.Data)
	if err != nil {
		return fmt.Errorf("unmarshaling proposal: %w", err)
	}

	// RFC 9420 §12.2: Validate proposal immediately upon receiving it
	switch proposal.Type {
	case ProposalTypeAdd:
		if proposal.Add != nil && proposal.Add.KeyPackage != nil && proposal.Add.KeyPackage.LeafNode != nil {
			leafData := keyPackageLeafToTreeSync(proposal.Add.KeyPackage.LeafNode)
			if err := treesync.ValidateLeafNodeLifetime(leafData.Lifetime); err != nil {
				return fmt.Errorf("invalid add proposal lifetime: %w", err)
			}
			if err := validateCapabilitiesCompatible(g.CipherSuite, leafData.Capabilities); err != nil {
				return fmt.Errorf("invalid add proposal capabilities: %w", err)
			}
			// RFC §12.2: Verify KeyPackage signature
			if err := proposal.Add.KeyPackage.Verify(g.CipherSuite); err != nil {
				return fmt.Errorf("add proposal keypackage signature invalid: %w", err)
			}
		}
	case ProposalTypeUpdate:
		// RFC §12.2: Verify that sender is an active member
		senderLeaf := g.RatchetTree.GetLeaf(treesync.LeafIndex(sender))
		if senderLeaf == nil || senderLeaf.State != treesync.NodeStatePresent {
			return fmt.Errorf("update proposal sender %d is not an active member", sender)
		}
		if proposal.Update != nil && proposal.Update.LeafNode != nil {
			leafData := keyPackageLeafToTreeSync(proposal.Update.LeafNode)
			if err := treesync.ValidateLeafNodeLifetime(leafData.Lifetime); err != nil {
				return fmt.Errorf("invalid update proposal lifetime: %w", err)
			}
			if err := validateCapabilitiesCompatible(g.CipherSuite, leafData.Capabilities); err != nil {
				return fmt.Errorf("invalid update proposal capabilities: %w", err)
			}
			// RFC §12.2, §7.3: Verify LeafNode signature with context
			if err := leafData.VerifyWithContext(g.CipherSuite, g.GroupContext.GroupID.AsSlice(), uint32(sender)); err != nil {
				return fmt.Errorf("update leaf node signature invalid: %w", err)
			}
		}
	}

	// RFC 9420 §12.4: ProposalRef = RefHash("MLS 1.0 Proposal Reference", Marshal(AuthenticatedContent))
	acForRef := &framing.AuthenticatedContent{
		WireFormat: framing.WireFormatPrivateMessage,
		Content:    ac.Content,
		Auth:       ac.Auth,
	}
	g.StoreProposal(proposal, sender, acForRef.Marshal())
	return nil
}

// applyProposal applies a single proposal to the group state.
func (g *Group) applyProposal(proposal *Proposal, senderIdx LeafNodeIndex) error {
	switch proposal.Type {
	case ProposalTypeAdd:
		return g.applyAddProposal(proposal.Add)
	case ProposalTypeUpdate:
		return g.applyUpdateProposal(proposal.Update, senderIdx)
	case ProposalTypeRemove:
		return g.applyRemoveProposal(proposal.Remove)
	case ProposalTypePreSharedKey:
		// PSK proposals affect key schedule only; no tree modification.
		return nil
	case ProposalTypeExternalInit:
		return nil
	case ProposalTypeReInit:
		return nil
	case ProposalTypeGroupContextExtensions:
		// GroupContextExtensions proposals update group context extensions.
		// RFC 9420 §12.4.2: Apply GCE to the group context.
		if proposal.GroupContextExtensions != nil {
			g.GroupContext.Extensions = proposal.GroupContextExtensions.Extensions
		}
		return nil
	default:
		return fmt.Errorf("unsupported proposal type: %d", proposal.Type)
	}
}

// applyAddProposal applies an Add proposal.
// RFC 9420 §12.4.2: The new member's LeafNode from the KeyPackage is added to the tree.
// We use keyPackageLeafToTreeSync to ensure consistency with applyProposalToTree.
func (g *Group) applyAddProposal(add *AddProposal) error {
	if add == nil {
		return ErrNilAddProposal
	}
	if add.KeyPackage == nil {
		return ErrNilKeyPackage
	}

	// Validate KeyPackage
	if err := add.KeyPackage.Validate(); err != nil {
		return fmt.Errorf("invalid key package: %w", err)
	}
	if add.KeyPackage.LeafNode == nil {
		return fmt.Errorf("invalid key package leaf node")
	}

	// Use keyPackageLeafToTreeSync for consistency with applyProposalToTree.
	// This correctly uses LeafNode.EncryptionKey (not KeyPackage.InitKey).
	leafData := keyPackageLeafToTreeSync(add.KeyPackage.LeafNode)
	if err := leafData.Validate(); err != nil {
		return fmt.Errorf("invalid add leaf node: %w", err)
	}

	leafIdx, _ := g.RatchetTree.AddLeaf(*leafData)
	leafIndex := LeafNodeIndex(leafIdx)

	// Add to Members
	g.Members[leafIndex] = &Member{
		LeafIndex:  leafIndex,
		KeyPackage: add.KeyPackage,
		Credential: add.KeyPackage.LeafNode.Credential,
		Active:     true,
	}

	return nil
}

// applyUpdateProposal applies an Update proposal.
// RFC 9420 §12.4.2: Update replaces the sender's leaf and blanks the direct path ancestors.
// Must match behavior of applyProposalToTree.
func (g *Group) applyUpdateProposal(update *UpdateProposal, senderIdx LeafNodeIndex) error {
	if update == nil || update.LeafNode == nil {
		return fmt.Errorf("invalid Update proposal")
	}
	leafData := keyPackageLeafToTreeSync(update.LeafNode)
	if err := leafData.Validate(); err != nil {
		return fmt.Errorf("invalid update leaf node: %w", err)
	}

	leafIdx := treesync.LeafIndex(senderIdx)
	if err := g.RatchetTree.SetLeaf(leafIdx, *leafData); err != nil {
		return err
	}

	// Blank the direct path ancestors (skip the leaf node itself at index 0).
	path := g.RatchetTree.DirectPath(leafIdx)
	for i := 1; i < len(path); i++ {
		g.RatchetTree.BlankNode(path[i])
	}

	return nil
}

// applyRemoveProposal applies a Remove proposal.
// RFC 9420 §12.4.2: Remove blanks the leaf and its entire direct path.
// Must match behavior of applyProposalToTree.
func (g *Group) applyRemoveProposal(remove *RemoveProposal) error {
	if remove == nil {
		return fmt.Errorf("invalid Remove proposal")
	}

	// Blank the leaf and its entire direct path (matches applyProposalToTree).
	removedLeaf := treesync.LeafIndex(remove.Removed)
	for _, nodeIdx := range g.RatchetTree.DirectPath(removedLeaf) {
		g.RatchetTree.BlankNode(nodeIdx)
	}
	g.RatchetTree.TruncateTrailingBlanks()

	// Mark member as inactive
	if member, ok := g.Members[remove.Removed]; ok {
		member.Active = false
	}

	return nil
}

// GetMember returns a member by leaf index.
func (g *Group) GetMember(leafIndex LeafNodeIndex) (*Member, bool) {
	member, ok := g.Members[leafIndex]
	return member, ok
}

// GetMembers returns all active members.
func (g *Group) GetMembers() []*Member {
	members := make([]*Member, 0)
	for _, member := range g.Members {
		if member.Active {
			members = append(members, member)
		}
	}
	return members
}

// MemberCount returns the number of active members.
func (g *Group) MemberCount() int {
	count := 0
	for _, member := range g.Members {
		if member.Active {
			count++
		}
	}
	return count
}

// State returns the current state of the group.
func (g *Group) State() GroupState {
	return g.state
}

// EpochAuthenticator returns the epoch authenticator bytes (RFC 9420 §8).
//
// In this implementation, epoch_authenticator maps to authentication_secret.
func (g *Group) EpochAuthenticator() []byte {
	if g == nil || g.EpochSecrets == nil || g.EpochSecrets.AuthenticationSecret == nil {
		return nil
	}
	return append([]byte(nil), g.EpochSecrets.AuthenticationSecret.AsSlice()...)
}

// NewGroupFromReInit creates a successor group from a ReInit proposal.
func NewGroupFromReInit(
	reInit *ReInitProposal,
	resumptionSecret *ciphersuite.Secret,
	myKP *keypackages.KeyPackage,
	myPriv *keypackages.KeyPackagePrivateKeys,
) (*Group, error) {
	if reInit == nil {
		return nil, fmt.Errorf("reinit proposal is nil")
	}
	if resumptionSecret == nil {
		return nil, fmt.Errorf("resumption secret is nil")
	}
	if myKP == nil || myPriv == nil {
		return nil, fmt.Errorf("key package/private keys are nil")
	}
	if myKP.LeafNode == nil {
		return nil, fmt.Errorf("key package leaf node is nil")
	}

	cs := ciphersuite.CipherSuite(reInit.CipherSuite)
	ratchetTree := treesync.NewRatchetTree(1)
	leafData := treesync.LeafNodeData{
		EncryptionKey:   myKP.InitKey,
		SignatureKey:    myKP.LeafNode.SignatureKey,
		SignatureKeyRaw: append([]byte(nil), myKP.LeafNode.SignatureKeyBytes...),
		Credential:      myKP.LeafNode.Credential,
		Capabilities:    toTreeSyncCapabilities(myKP.LeafNode.Capabilities),
		Lifetime:        keyPackageToTreeSyncLifetime(myKP.LeafNode.Lifetime),
		Extensions:      keyPackageExtensionsToTreeSync(myKP.LeafNode.Extensions),
		LeafNodeSource:  1,
		ParentHash:      append([]byte(nil), myKP.LeafNode.ParentHash...),
		Signature:       append([]byte(nil), myKP.LeafNode.Signature...),
	}
	if leafData.Capabilities == nil {
		leafData.Capabilities = &treesync.LeafNodeCapabilities{}
	}
	if err := leafData.Validate(); err != nil {
		return nil, fmt.Errorf("invalid reinit leaf node: %w", err)
	}
	_, _ = ratchetTree.AddLeaf(leafData)

	groupContext := &GroupContext{
		Version:                 reInit.Version,
		CipherSuite:             cs,
		GroupID:                 NewGroupID(reInit.GroupID),
		Epoch:                   NewGroupEpoch(0),
		TreeHash:                ratchetTree.TreeHash(),
		ConfirmedTranscriptHash: []byte{},
		Extensions:              reInit.Extensions,
	}

	initSecret := ciphersuite.ZeroSecret(cs.HashLength())
	keySchedule := schedule.NewKeySchedule(cs, initSecret)
	commitSecret := ciphersuite.ZeroSecret(cs.HashLength())
	keySchedule.SetCommitSecret(commitSecret)

	groupContextBytes := groupContext.Marshal()
	if _, err := keySchedule.ComputeJoinerSecret(groupContextBytes); err != nil {
		return nil, fmt.Errorf("computing joiner secret: %w", err)
	}

	resumptionPsk := schedule.Psk{
		PskType: schedule.PskTypeResumption,
		PskID:   reInit.GroupID,
		Psk:     resumptionSecret.AsSlice(),
	}
	if _, err := keySchedule.ComputePskSecret([]schedule.Psk{resumptionPsk}); err != nil {
		return nil, fmt.Errorf("computing reinit psk secret: %w", err)
	}
	if _, err := keySchedule.ComputeEpochSecret(groupContextBytes); err != nil {
		return nil, fmt.Errorf("computing reinit epoch secret: %w", err)
	}
	epochSecrets, err := keySchedule.DeriveEpochSecrets()
	if err != nil {
		return nil, fmt.Errorf("deriving reinit epoch secrets: %w", err)
	}
	group := &Group{
		GroupID:               groupContext.GroupID,
		Epoch:                 groupContext.Epoch,
		CipherSuite:           cs,
		GroupContext:          groupContext,
		RatchetTree:           ratchetTree,
		OwnLeafIndex:          NewLeafNodeIndex(0),
		EpochSecrets:          epochSecrets,
		Proposals:             NewProposalStore(),
		ProposalByRef:         make(map[string]*Proposal),
		KeySchedule:           keySchedule,
		InterimTranscriptHash: []byte{},
		Members:               make(map[LeafNodeIndex]*Member),
		state:                 StateOperational,
		CachedPsks:            make(map[string][]byte),
	}
	group.CachedPsks[string(reInit.GroupID)] = resumptionSecret.AsSlice()
	group.SecretTree, err = secrettree.NewTree(epochSecrets.EncryptionSecret, ratchetTree.NumLeaves, cs)
	if err != nil {
		return nil, fmt.Errorf("initializing secret tree: %w", err)
	}
	group.Members[NewLeafNodeIndex(0)] = &Member{
		LeafIndex:  NewLeafNodeIndex(0),
		KeyPackage: myKP,
		Credential: myKP.LeafNode.Credential,
		Active:     true,
	}
	return group, nil
}

// GetGroupInfo returns a signed GroupInfo for the current epoch (RFC 9420 §12.4.3.2).
func (g *Group) GetGroupInfo(
	signerPrivKey *ciphersuite.SignaturePrivateKey,
) (*GroupInfo, error) {
	if g.state != StateOperational {
		return nil, fmt.Errorf("group not operational")
	}
	return g.buildSignedGroupInfo(signerPrivKey)
}

func (g *Group) buildSignedGroupInfo(
	signerPrivKey *ciphersuite.SignaturePrivateKey,
) (*GroupInfo, error) {
	if signerPrivKey == nil {
		return nil, fmt.Errorf("signer private key is nil")
	}

	extensions := make([]Extension, len(g.GroupContext.Extensions))
	copy(extensions, g.GroupContext.Extensions)

	groupInfo := &GroupInfo{
		GroupContext:    g.GroupContext,
		Extensions:      extensions,
		ConfirmationTag: g.ConfirmationTag,
		Signer:          g.OwnLeafIndex,
		RatchetTree:     g.RatchetTree,
	}

	// ratchet_tree 0x0002
	groupInfo.Extensions = append(groupInfo.Extensions, Extension{
		Type: 0x0002,
		Data: g.RatchetTree.MarshalTree(),
	})

	// external_pub 0x0001
	externalPriv, err := ciphersuite.DeriveKeyPair(
		g.CipherSuite,
		g.EpochSecrets.ExternalSecret.AsSlice(),
	)
	if err != nil {
		return nil, fmt.Errorf("deriving external key pair: %w", err)
	}
	groupInfo.Extensions = append(groupInfo.Extensions, Extension{
		Type: 0x0001,
		Data: externalPriv.PublicKey().Bytes(),
	})

	tbs := groupInfo.MarshalTBS()
	sig, err := ciphersuite.SignWithLabel(signerPrivKey, "GroupInfoTBS", tbs)
	if err != nil {
		return nil, fmt.Errorf("signing group info: %w", err)
	}
	groupInfo.Signature = sig.AsSlice()

	return groupInfo, nil
}

// VerifyPublicMessage verifies a PublicMessage signature and membership tag (RFC 9420 §6.1).
//
// This verifies that the message was sent by a valid group member and
// that the membership tag is correct.
func (g *Group) VerifyPublicMessage(pm *framing.PublicMessage) error {
	if pm == nil {
		return fmt.Errorf("public message is nil")
	}

	switch pm.Content.Sender.Type {
	case framing.SenderTypeMember:
		senderIdx := LeafNodeIndex(pm.Content.Sender.LeafIndex)
		leaf := g.RatchetTree.GetLeaf(treesync.LeafIndex(senderIdx))
		if leaf == nil || leaf.LeafData == nil {
			return fmt.Errorf("missing sender signature key")
		}

		rawKey := leaf.LeafData.SigKeyBytes()
		if len(rawKey) == 0 {
			return fmt.Errorf("missing sender signature key")
		}
		pubKey := ciphersuite.NewOpenMlsSignaturePublicKey(rawKey, g.CipherSuite.SignatureScheme())
		ac := &framing.AuthenticatedContent{
			WireFormat:   framing.WireFormatPublicMessage,
			Content:      pm.Content,
			Auth:         pm.Auth,
			GroupContext: g.GroupContext.Marshal(),
		}
		if err := ciphersuite.VerifyWithLabel(pubKey, "FramedContentTBS", ac.MarshalTBS(), pm.Auth.Signature); err != nil {
			return fmt.Errorf("public message signature verification failed: %w", err)
		}

		if g.EpochSecrets == nil || g.EpochSecrets.MembershipKey == nil {
			return fmt.Errorf("membership_key not available")
		}
		return pm.VerifyMembershipTagWithContext(g.CipherSuite, g.EpochSecrets.MembershipKey, g.GroupContext.Marshal())
	case framing.SenderTypeExternal:
		// RFC §12.1.8.1: external senders sign with their own key, listed in the
		// ExternalSenders extension (0x0005) of the GroupContext.
		sigKey, err := g.getExternalSenderSigningKey(pm.Content.Sender.SenderIndex)
		if err != nil {
			return fmt.Errorf("external sender: %w", err)
		}
		pubKey := ciphersuite.NewOpenMlsSignaturePublicKey(sigKey, g.CipherSuite.SignatureScheme())
		ac := &framing.AuthenticatedContent{
			WireFormat:   framing.WireFormatPublicMessage,
			Content:      pm.Content,
			Auth:         pm.Auth,
			GroupContext: g.GroupContext.Marshal(),
		}
		if err := ciphersuite.VerifyWithLabel(pubKey, "FramedContentTBS", ac.MarshalTBS(), pm.Auth.Signature); err != nil {
			return fmt.Errorf("external public message signature verification failed: %w", err)
		}
		return nil
	case framing.SenderTypeNewMemberProposal, framing.SenderTypeNewMemberCommit:
		return nil
	default:
		return nil
	}
}

// getExternalSenderSigningKey returns the signature public key for the external
// sender at senderIndex, as listed in the ExternalSenders extension (0x0005) of
// the GroupContext (RFC 9420 §12.1.8.1).
func (g *Group) getExternalSenderSigningKey(senderIndex uint32) ([]byte, error) {
	const extTypeExternalSenders = 0x0005
	for _, ext := range g.GroupContext.Extensions {
		if ext.Type != extTypeExternalSenders {
			continue
		}
		senders, err := parseExternalSenders(ext.Data)
		if err != nil {
			return nil, fmt.Errorf("parsing ExternalSenders extension: %w", err)
		}
		if int(senderIndex) >= len(senders) {
			return nil, fmt.Errorf("sender index %d out of range (have %d external senders)", senderIndex, len(senders))
		}
		return senders[senderIndex].SignatureKey, nil
	}
	return nil, fmt.Errorf("ExternalSenders extension not found in GroupContext")
}

// LoadPsk loads a pre-shared key into the group's PSK cache.
//
// This is used for external PSKs that are referenced in PreSharedKey proposals.
func (g *Group) LoadPsk(pskID, pskBytes []byte) {
	if g.CachedPsks == nil {
		g.CachedPsks = make(map[string][]byte)
	}
	g.CachedPsks[string(pskID)] = pskBytes
}

func keyPackageToTreeSyncLifetime(lifetime *keypackages.Lifetime) *treesync.LeafNodeLifetime {
	if lifetime == nil {
		return nil
	}
	return &treesync.LeafNodeLifetime{NotBefore: lifetime.NotBefore, NotAfter: lifetime.NotAfter}
}

func keyPackageExtensionsToTreeSync(exts []keypackages.Extension) [][]byte {
	if len(exts) == 0 {
		return nil
	}
	out := make([][]byte, len(exts))
	for i, ext := range exts {
		w := tls.NewWriter()
		w.WriteUint16(ext.Type)
		w.WriteVLBytes(ext.Data)
		out[i] = w.Bytes()
	}
	return out
}

func treeSyncToKeyPackageCapabilities(caps *treesync.LeafNodeCapabilities) *keypackages.Capabilities {
	if caps == nil {
		return nil
	}

	versions := make([]keypackages.ProtocolVersion, len(caps.ProtocolVersions))
	for i, v := range caps.ProtocolVersions {
		versions[i] = keypackages.ProtocolVersion(v)
	}

	cipherSuites := make([]keypackages.CipherSuite, len(caps.CipherSuites))
	for i, cs := range caps.CipherSuites {
		cipherSuites[i] = keypackages.CipherSuite(cs)
	}

	return &keypackages.Capabilities{
		ProtocolVersions: versions,
		CipherSuites:     cipherSuites,
		Extensions:       append([]uint16(nil), caps.Extensions...),
		Proposals:        append([]uint16(nil), caps.Proposals...),
		Credentials:      append([]uint16(nil), caps.Credentials...),
	}
}

func treeSyncToKeyPackageLifetime(lifetime *treesync.LeafNodeLifetime) *keypackages.Lifetime {
	if lifetime == nil {
		return nil
	}
	return &keypackages.Lifetime{NotBefore: lifetime.NotBefore, NotAfter: lifetime.NotAfter}
}

// sortProposalsByRFCOrder sorts proposals (and their parallel senders slice)
// according to RFC 9420 §12.4.2 application order:
// GroupContextExtensions → Update → Remove → Add → PreSharedKey → ReInit → ExternalInit.
// The sort is stable so proposals of the same type retain their original order.
func sortProposalsByRFCOrder(proposals []*Proposal, senders []LeafNodeIndex) {
	rfcPriority := map[ProposalType]int{
		ProposalTypeGroupContextExtensions: 1,
		ProposalTypeUpdate:                 2,
		ProposalTypeRemove:                 3,
		ProposalTypeAdd:                    4,
		ProposalTypePreSharedKey:           5,
		ProposalTypeReInit:                 6,
		ProposalTypeExternalInit:           7,
	}

	// Build index slice and stable-sort it.
	indices := make([]int, len(proposals))
	for i := range indices {
		indices[i] = i
	}
	sort.SliceStable(indices, func(a, b int) bool {
		pa := rfcPriority[proposals[indices[a]].Type]
		pb := rfcPriority[proposals[indices[b]].Type]
		return pa < pb
	})

	// Reorder in place using the sorted indices.
	sortedP := make([]*Proposal, len(proposals))
	sortedS := make([]LeafNodeIndex, len(senders))
	for i, idx := range indices {
		sortedP[i] = proposals[idx]
		if idx < len(senders) {
			sortedS[i] = senders[idx]
		}
	}
	copy(proposals, sortedP)
	copy(senders, sortedS)
}

func keyPackageLeafToTreeSync(leaf *keypackages.LeafNode) *treesync.LeafNodeData {
	if leaf == nil {
		return nil
	}
	leafData := &treesync.LeafNodeData{
		EncryptionKey:   leaf.EncryptionKey,
		SignatureKey:    leaf.SignatureKey,
		SignatureKeyRaw: append([]byte(nil), leaf.SignatureKeyBytes...),
		Credential:      leaf.Credential,
		Capabilities:    toTreeSyncCapabilities(leaf.Capabilities),
		Lifetime:        keyPackageToTreeSyncLifetime(leaf.Lifetime),
		Extensions:      keyPackageExtensionsToTreeSync(leaf.Extensions),
		LeafNodeSource:  leaf.LeafNodeSource,
		ParentHash:      append([]byte(nil), leaf.ParentHash...),
		Signature:       append([]byte(nil), leaf.Signature...),
	}
	if leafData.Capabilities == nil {
		leafData.Capabilities = &treesync.LeafNodeCapabilities{}
	}
	return leafData
}

// Export derives an external key using MLS Exporter (RFC 9420 §8.5).
// Useful for applications that need to derive session keys (e.g., DAVE media keys).
// The label should be unique for the application. The context may be nil.
func (g *Group) Export(label string, context []byte, length int) ([]byte, error) {
	if g.EpochSecrets == nil || g.EpochSecrets.ExporterSecret == nil {
		return nil, fmt.Errorf("exporter_secret not available")
	}

	if g.state != StateOperational {
		return nil, fmt.Errorf("group not operational")
	}

	// RFC 9420 §8.5 = HKDF-Expand-Label(exporter_secret, label, context, length)
	return schedule.Exporter(g.EpochSecrets.ExporterSecret, g.CipherSuite, schedule.ExporterLabel(label), context, length)
}
