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
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/framing"
	"github.com/openmls/go/internal/tls"
	keypackages "github.com/openmls/go/keypackages"
	"github.com/openmls/go/schedule"
	"github.com/openmls/go/secrettree"
	"github.com/openmls/go/treesync"
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
}

// NewGroup This is the entry point for creating a new group.
func NewGroup(
	groupID *GroupID,
	cipherSuite ciphersuite.CipherSuite,
	keyPackage *keypackages.KeyPackage,
	privateKeys *keypackages.KeyPackagePrivateKeys,
) (*Group, error) {
	// Create ratchet tree with 1 leaf
	ratchetTree := treesync.NewRatchetTree(1)

	// Add our leaf
	leafData := treesync.LeafNodeData{
		EncryptionKey:  keyPackage.InitKey,
		SignatureKey:   &privateKeys.SignatureKey.PublicKey,
		Credential:     keyPackage.LeafNode.Credential,
		Capabilities:   &treesync.LeafNodeCapabilities{},
		Lifetime:       &treesync.LeafNodeLifetime{},
		LeafNodeSource: 1, // key_package
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
		InterimTranscriptHash: []byte{}, // string vacio
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
	if privateKeys.SignatureKey == nil {
		return nil, fmt.Errorf("signature key is nil")
	}

	// source = 2 (update) y firmar el TBS con el label del RFC
	newLeafNode.LeafNodeSource = 2
	sigKey := ciphersuite.NewSignaturePrivateKey(privateKeys.SignatureKey)
	tbs := newLeafNode.MarshalTBS()
	sig, err := ciphersuite.SignWithLabel(sigKey, "LeafNodeTBS", tbs)
	if err != nil {
		return nil, fmt.Errorf("signing leaf node: %w", err)
	}
	newLeafNode.Signature = sig.AsSlice()

	// Convert treesync leaf data to keypackages leaf node.
	kpLeafNode := &keypackages.LeafNode{
		EncryptionKey: newLeafNode.EncryptionKey,
		SignatureKey:  newLeafNode.SignatureKey,
		Credential:    newLeafNode.Credential,
		Capabilities:  treeSyncToKeyPackageCapabilities(newLeafNode.Capabilities),
		Lifetime:      treeSyncToKeyPackageLifetime(newLeafNode.Lifetime),
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
func (g *Group) Commit(
	sigPrivKey *ciphersuite.SignaturePrivateKey,
	sigPubKey *ciphersuite.SignaturePublicKey,
	psks []schedule.Psk,
) (*StagedCommit, error) {
	if g.state != StateOperational {
		return nil, fmt.Errorf("group not in operational state: %w", ErrInvalidGroupState)
	}

	if len(g.Proposals.Proposals) == 0 {
		return nil, fmt.Errorf("no proposals to commit")
	}

	// 1. Filtrar y validar proposals (RFC §12.2)
	filtered, err := g.FilterProposalsForCommit(nil)
	if err != nil {
		return nil, fmt.Errorf("filtering proposals: %w", err)
	}

	proposals := make([]*Proposal, len(filtered))
	for i, fp := range filtered {
		proposals[i] = fp.Proposal
	}

	// 2. Clonar árbol, aplicar proposals provisoriamente
	treeDiff := g.RatchetTree.Clone()
	for _, fp := range filtered {
		if err := g.applyProposalToTree(fp.Proposal, treeDiff, fp.Sender); err != nil {
			return nil, fmt.Errorf("applying proposal to tree: %w", err)
		}
	}

	// 3. Generar UpdatePath si es necesario (RFC §12.4.1)
	var updatePath *UpdatePath
	var commitSecret *ciphersuite.Secret

	// Generar UpdatePath
	updatePath, commitSecret, err = g.createUpdatePath(treeDiff, sigPrivKey, sigPubKey)
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

	// 5. Crear AuthenticatedContent y firmar
	content := framing.FramedContent{
		GroupID: g.GroupID.AsSlice(),
		Epoch:   g.Epoch.AsUint64(),
		Sender:  framing.Sender{Type: framing.SenderTypeMember, LeafIndex: uint32(g.OwnLeafIndex)},
		Body:    framing.CommitBody{Data: commit.Marshal()},
	}

	groupContextBytes := g.GroupContext.Marshal()
	ac := &framing.AuthenticatedContent{
		WireFormat:   framing.WireFormatPublicMessage,
		Content:      content,
		GroupContext: groupContextBytes,
	}

	// Firmar el TBS con label (RFC §6.1 / §5.1.2)
	sig, err := ciphersuite.SignWithLabel(sigPrivKey, "FramedContentTBS", ac.MarshalTBS())
	if err != nil {
		return nil, fmt.Errorf("signing commit: %w", err)
	}
	ac.Auth.Signature = sig

	// 6. Calcular confirmed_transcript_hash (RFC §8.2)
	cthi, err := framing.NewConfirmedTranscriptHashInput(ac)
	if err != nil {
		return nil, fmt.Errorf("creating transcript hash input: %w", err)
	}
	confirmedHash, err := cthi.Compute(g.CipherSuite, g.InterimTranscriptHash)
	if err != nil {
		return nil, fmt.Errorf("computing confirmed transcript hash: %w", err)
	}

	// Construir GroupContext provisional para el nuevo epoch
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

	// Avanzar key schedule para calcular confirmation_key del nuevo epoch
	newGCBytes := newGC.Marshal()
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
	ac.Auth.ConfirmationTag = confirmationTag

	newInterimHash := schedule.ComputeInterimTranscriptHash(g.CipherSuite, confirmedHash, confirmationTag)

	// 7. Crear StagedCommit con datos precalculados para el committer
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

// createUpdatePath genera un UpdatePath real (RFC §12.4.1).
func (g *Group) createUpdatePath(
	tree *treesync.RatchetTree,
	sigPrivKey *ciphersuite.SignaturePrivateKey,
	sigPubKey *ciphersuite.SignaturePublicKey,
) (*UpdatePath, *ciphersuite.Secret, error) {
	leafSecret, err := ciphersuite.NewSecretRandomCS(g.CipherSuite)
	if err != nil {
		return nil, nil, err
	}

	directPath := tree.DirectPath(treesync.LeafIndex(g.OwnLeafIndex))
	pathSecrets := make([]*ciphersuite.Secret, len(directPath))
	pathSecrets[0] = leafSecret

	for i := 1; i < len(directPath); i++ {
		pathSecrets[i], err = pathSecrets[i-1].DeriveSecret(g.CipherSuite, "path")
		if err != nil {
			return nil, nil, err
		}
	}

	nodes := make([]UpdatePathNode, len(directPath)-1)
	copath := tree.Copath(treesync.LeafIndex(g.OwnLeafIndex))

	for i := 1; i < len(directPath); i++ {
		pathSecret := pathSecrets[i]
		nodeSecret, _ := pathSecret.DeriveSecret(g.CipherSuite, "node")
		privKey, _ := ciphersuite.DeriveKeyPair(g.CipherSuite, nodeSecret.AsSlice())
		pubKey := privKey.PublicKey().Bytes()

		res := tree.Resolution(copath[i-1])
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

			ct, err := ciphersuite.EncryptWithLabel(
				encKeyBytes,
				"UpdatePathNode",
				[]byte{},
				pathSecret.AsSlice(),
				g.CipherSuite,
			)
			if err != nil {
				return nil, nil, err
			}
			encryptedSecrets[j] = *ct
		}

		nodes[i-1] = UpdatePathNode{
			EncryptionKey:        pubKey,
			EncryptedPathSecrets: encryptedSecrets,
		}

		node := &tree.Nodes[directPath[i]]
		node.EncryptionKey, _ = ecdh.P256().NewPublicKey(pubKey)
		node.State = treesync.NodeStatePresent
	}

	// Calcular parent hashes (RFC §7.9)
	rootIdx := tree.Root()
	tree.Nodes[rootIdx].ParentHash = []byte{}

	for i := len(directPath) - 2; i >= 0; i-- {
		nodeIdx := directPath[i]
		parentIdx, _ := tree.Parent(nodeIdx)

		parent := &tree.Nodes[parentIdx]
		siblingIdx := tree.GetSibling(nodeIdx)
		siblingHash := tree.HashNode(siblingIdx)

		var parentKey []byte
		if parent.EncryptionKey != nil {
			parentKey = parent.EncryptionKey.Bytes()
		}

		ph := treesync.ComputeParentHash(parentKey, parent.ParentHash, siblingHash)
		tree.Nodes[nodeIdx].ParentHash = ph
	}

	sigPubKeyECDSA, err := sigPubKey.ToECDSA()
	if err != nil {
		return nil, nil, fmt.Errorf("converting signature public key: %w", err)
	}

	var caps *treesync.LeafNodeCapabilities
	if ownLeaf := g.RatchetTree.GetLeaf(treesync.LeafIndex(g.OwnLeafIndex)); ownLeaf != nil && ownLeaf.LeafData != nil {
		caps = ownLeaf.LeafData.Capabilities
	}
	if caps == nil {
		caps = &treesync.LeafNodeCapabilities{}
	}

	leafNodeData := &treesync.LeafNodeData{
		EncryptionKey:  leafSecret.AsSlice(),
		SignatureKey:   sigPubKeyECDSA,
		Credential:     g.Members[g.OwnLeafIndex].Credential,
		Capabilities:   caps,
		Lifetime:       &treesync.LeafNodeLifetime{},
		LeafNodeSource: 3, // commit
		ParentHash:     tree.Nodes[directPath[0]].ParentHash,
	}

	tbs := leafNodeData.MarshalTBS()
	sig, err := ciphersuite.SignWithLabel(sigPrivKey, "LeafNodeTBS", tbs)
	if err != nil {
		return nil, nil, fmt.Errorf("signing leaf node TBS: %w", err)
	}
	leafNodeData.Signature = sig.AsSlice()

	commitSecret := pathSecrets[len(pathSecrets)-1]

	return &UpdatePath{
		LeafNode: leafNodeData,
		Nodes:    nodes,
	}, commitSecret, nil
}

// applyProposalToTree aplica un proposal a un árbol específico.
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
		tree.SetLeaf(leafIdx, leafData)
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

// ProcessCommit procesa un commit recibido.
// RFC 9420 §12.4.2
func (g *Group) ProcessCommit(stagedCommit *StagedCommit) error {
	if stagedCommit.AuthenticatedContent == nil {
		return fmt.Errorf("missing authenticated content")
	}
	return g.MergeCommit(stagedCommit)
}

// StoreProposal almacena un proposal indexado por referencia hash para resolución futura (RFC 9420 §12.4).
func (g *Group) StoreProposal(p *Proposal, sender LeafNodeIndex) []byte {
	if g.ProposalByRef == nil {
		g.ProposalByRef = make(map[string]*Proposal)
	}
	ref := ComputeProposalRef(p, g.CipherSuite)
	g.ProposalByRef[string(ref)] = p
	g.Proposals.AddProposal(p, sender)
	return ref
}

// ProcessReceivedCommit procesa un commit enviado por otro miembro.
// Descifra el path secret usando la clave HPKE privada del receptor,
// luego avanza el estado del grupo. RFC 9420 §12.4.2
func (g *Group) ProcessReceivedCommit(
	ac *framing.AuthenticatedContent,
	senderLeafIdx treesync.LeafIndex,
	myHpkePrivKeyBytes []byte,
) error {
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
		if senderLeaf == nil || senderLeaf.LeafData == nil || senderLeaf.LeafData.SignatureKey == nil {
			return fmt.Errorf("missing sender signature key")
		}
		rawKey := treesync.MarshalSignatureKey(senderLeaf.LeafData.SignatureKey)
		pubKey := ciphersuite.NewOpenMlsSignaturePublicKey(rawKey, ciphersuite.ECDSA_SECP256R1_SHA256)
		if err := ciphersuite.VerifyWithLabel(pubKey, "FramedContentTBS", ac.MarshalTBS(), ac.Auth.Signature); err != nil {
			return fmt.Errorf("commit signature verification failed: %w", err)
		}
	case framing.SenderTypeNewMemberCommit:
		// RFC §12.4.3.2: external committer's key is in the UpdatePath LeafNode.
		if commit.Path == nil || commit.Path.LeafNode == nil || commit.Path.LeafNode.SignatureKey == nil {
			return fmt.Errorf("external commit missing leaf node signature key")
		}
		rawKey := treesync.MarshalSignatureKey(commit.Path.LeafNode.SignatureKey)
		pubKey := ciphersuite.NewOpenMlsSignaturePublicKey(rawKey, ciphersuite.ECDSA_SECP256R1_SHA256)
		if err := ciphersuite.VerifyWithLabel(pubKey, "FramedContentTBS", ac.MarshalTBS(), ac.Auth.Signature); err != nil {
			return fmt.Errorf("external commit signature verification failed: %w", err)
		}
	}

	// Resolver proposals: inline o por referencia hash
	proposals := make([]*Proposal, 0, len(commit.Proposals))
	for _, por := range commit.Proposals {
		if por.Proposal != nil {
			proposals = append(proposals, por.Proposal)
		} else if len(por.ProposalRef) > 0 {
			if p, ok := g.ProposalByRef[string(por.ProposalRef)]; ok {
				proposals = append(proposals, p)
			} else {
				return fmt.Errorf("unknown proposal reference in commit")
			}
		}
	}

	// Descifrar path secret con nuestra clave HPKE privada
	var rootPathSecret *ciphersuite.Secret
	if ac.Content.Sender.Type == framing.SenderTypeNewMemberCommit {
		if commit.Path == nil || commit.Path.LeafNode == nil {
			return fmt.Errorf("external commit missing update path")
		}
		treeDiff := g.RatchetTree.Clone()
		extLeafIdx, _ := treeDiff.AddLeaf(*commit.Path.LeafNode)
		senderLeafIdx = extLeafIdx
		rootPathSecret, err = g.decryptPathSecret(treeDiff, senderLeafIdx, commit.Path, myHpkePrivKeyBytes)
		if err != nil {
			return fmt.Errorf("decrypting path secret (external): %w", err)
		}
	} else if commit.Path != nil {
		rootPathSecret, err = g.decryptPathSecret(g.RatchetTree, senderLeafIdx, commit.Path, myHpkePrivKeyBytes)
		if err != nil {
			return fmt.Errorf("decrypting path secret: %w", err)
		}
	}

	staged := &StagedCommit{
		Commit:               commit,
		Proposals:            proposals,
		AuthenticatedContent: ac,
		RootPathSecret:       rootPathSecret,
	}
	return g.MergeCommit(staged)
}

// decryptPathSecret descifra el path secret de un UpdatePath para este receptor.
// Recorre el copath del emisor buscando el nodo del receptor en la resolución,
// descifra con HPKE y deriva hacia adelante hasta obtener el commit_secret.
// RFC 9420 §12.4.1
func (g *Group) decryptPathSecret(
	tree *treesync.RatchetTree,
	senderLeafIdx treesync.LeafIndex,
	updatePath *UpdatePath,
	myPrivKeyBytes []byte,
) (*ciphersuite.Secret, error) {
	directPath := tree.DirectPath(senderLeafIdx)
	copath := tree.Copath(senderLeafIdx)
	myNodeIdx := treesync.LeafIndexToNodeIndex(treesync.LeafIndex(g.OwnLeafIndex))

	for i := 1; i < len(directPath); i++ {
		res := tree.Resolution(copath[i-1])
		for j, resIdx := range res {
			if resIdx != myNodeIdx {
				continue
			}
			nodeIdx := i - 1
			if nodeIdx >= len(updatePath.Nodes) || j >= len(updatePath.Nodes[nodeIdx].EncryptedPathSecrets) {
				return nil, fmt.Errorf("path secret index out of bounds at level %d", i)
			}
			ct := &updatePath.Nodes[nodeIdx].EncryptedPathSecrets[j]
			psBytes, err := ciphersuite.DecryptWithLabel(
				myPrivKeyBytes,
				"UpdatePathNode",
				[]byte{},
				ct,
				g.CipherSuite,
			)
			if err != nil {
				return nil, fmt.Errorf("decrypting path secret at level %d: %w", i, err)
			}
			pathSecret := ciphersuite.NewSecret(psBytes)
			for k := i + 1; k < len(directPath); k++ {
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

// MergeCommit aplica un commit y avanza el estado del protocolo
// RFC 9420 §12.4.2
func (g *Group) MergeCommit(stagedCommit *StagedCommit) error {
	if g.state != StatePendingCommit && g.state != StateOperational {
		return fmt.Errorf("group not in valid state for commit: %w", ErrInvalidGroupState)
	}
	// 1. Aplicar proposals al ratchet tree
	senderIdx := g.OwnLeafIndex
	if stagedCommit.AuthenticatedContent != nil {
		if stagedCommit.AuthenticatedContent.Content.Sender.Type == framing.SenderTypeNewMemberCommit {
			if stagedCommit.Commit == nil || stagedCommit.Commit.Path == nil || stagedCommit.Commit.Path.LeafNode == nil {
				return fmt.Errorf("external commit missing update path")
			}

			extLeafIdx, _ := g.RatchetTree.AddLeaf(*stagedCommit.Commit.Path.LeafNode)
			senderIdx = LeafNodeIndex(extLeafIdx)
		} else {
			senderIdx = LeafNodeIndex(stagedCommit.AuthenticatedContent.Content.Sender.LeafIndex)
		}
	}
	for _, proposal := range stagedCommit.Proposals {
		if err := g.applyProposal(proposal, senderIdx); err != nil {
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
			pskID := proposal.PreSharedKey.PskID.ID
			pskBytes, ok := g.CachedPsks[string(pskID)]
			if !ok {
				return fmt.Errorf("missing PSK for proposal: %x", pskID)
			}
			psks = append(psks, schedule.Psk{
				Psk:      pskBytes,
				PskId:    pskID,
				PskNonce: proposal.PreSharedKey.PskID.Nonce,
				PskType:  schedule.PskType(proposal.PreSharedKey.PskID.PskType),
			})
		}
	}

	// 1.2 Aplicar UpdatePath si existe
	if stagedCommit.Commit.Path != nil {
		senderLeafIdx := treesync.LeafIndex(senderIdx)
		leafNodeData := stagedCommit.Commit.Path.LeafNode

		// Verificar firma del leaf node del emisor (RFC §12.4.2)
		if leafNodeData.SignatureKey != nil {
			if err := leafNodeData.Verify(g.CipherSuite); err != nil {
				return fmt.Errorf("leaf node signature verification failed: %w", err)
			}
		}

		// Actualizar la hoja del emisor
		g.RatchetTree.SetLeaf(senderLeafIdx, *leafNodeData)

		// Actualizar ancestros con nuevas claves de cifrado
		path := g.RatchetTree.DirectPath(senderLeafIdx)
		for i := 1; i < len(path) && i-1 < len(stagedCommit.Commit.Path.Nodes); i++ {
			nodeIdx := path[i]
			updateNode := stagedCommit.Commit.Path.Nodes[i-1]

			node := &g.RatchetTree.Nodes[nodeIdx]
			node.EncryptionKey, _ = ecdh.P256().NewPublicKey(updateNode.EncryptionKey)
			node.State = treesync.NodeStatePresent
		}

		// Calcular parent hashes de arriba abajo y verificar (RFC §7.9)
		if len(path) > 1 {
			rootIdx := g.RatchetTree.Root()
			g.RatchetTree.Nodes[rootIdx].ParentHash = []byte{}

			for i := len(path) - 2; i >= 0; i-- {
				nodeIdx := path[i]
				parentIdx := path[i+1]
				parent := &g.RatchetTree.Nodes[parentIdx]
				siblingIdx := g.RatchetTree.GetSibling(nodeIdx)
				siblingHash := g.RatchetTree.HashNode(siblingIdx)

				var parentKey []byte
				if parent.EncryptionKey != nil {
					parentKey = parent.EncryptionKey.Bytes()
				}
				ph := treesync.ComputeParentHash(parentKey, parent.ParentHash, siblingHash)

				// Almacenar en nodos intermedios; la hoja ya tiene su parent hash del wire
				if !treesync.IsLeaf(nodeIdx) {
					g.RatchetTree.Nodes[nodeIdx].ParentHash = ph
				}
			}

			// Verificar que el parent hash de la hoja coincide con lo calculado (RFC §7.9)
			if err := g.RatchetTree.VerifyParentHashes(senderLeafIdx); err != nil {
				return fmt.Errorf("parent hash verification failed: %w", err)
			}
		}
	}

	// 2. Recomputar TreeHash desde treesync
	treeHash := g.RatchetTree.TreeHash()

	// 3. Calcular ConfirmedTranscriptHash nuevo
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
	// 4. Calcular InterimTranscriptHash nuevo
	itHashInput := &framing.InterimTranscriptHashInput{
		ConfirmationTag: stagedCommit.AuthenticatedContent.Auth.ConfirmationTag,
	}

	interimTranscriptHash := itHashInput.Compute(
		g.CipherSuite,
		confirmedTranscriptHash,
	)

	// 5. Actualizar GroupContext (RFC §8.1)
	g.GroupContext.IncrementEpoch()
	g.GroupContext.UpdateTreeHash(treeHash)
	g.GroupContext.UpdateConfirmedTranscriptHash(confirmedTranscriptHash)

	// Actualizar también Group directamente
	g.Epoch = g.GroupContext.Epoch
	g.InterimTranscriptHash = interimTranscriptHash
	g.ConfirmationTag = stagedCommit.AuthenticatedContent.Auth.ConfirmationTag
	// 6. Avanzar key schedule → nuevos EpochSecrets
	if stagedCommit.PrecomputedEpochSecrets != nil {
		// Committer: usar epoch secrets precalculados en Commit()
		g.EpochSecrets = stagedCommit.PrecomputedEpochSecrets
	} else {
		// Receptor: derivar desde init_secret del epoch actual
		initSecretForNewEpoch := g.EpochSecrets.InitSecret
		for _, proposal := range stagedCommit.Proposals {
			if proposal.Type == ProposalTypeExternalInit && proposal.ExternalInit != nil {
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
		}

		var commitSecret *ciphersuite.Secret
		if stagedCommit.Commit != nil && stagedCommit.Commit.Path != nil {
			commitSecret = stagedCommit.RootPathSecret
		} else {
			commitSecret = ciphersuite.ZeroSecret(g.CipherSuite.HashLength())
		}

		newGCBytes := g.GroupContext.Marshal()
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

		// Verificar confirmation_tag del commit (RFC §12.4.2)
		expectedTag := schedule.ComputeConfirmationTag(
			g.CipherSuite,
			newEpochSecrets.ConfirmationKey.AsSlice(),
			confirmedTranscriptHash,
		)
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

	// 7. Limpiar estado
	g.Proposals.Clear()
	g.PendingCommit = nil
	if hasReInit {
		g.state = StateInactive
	} else {
		g.state = StateOperational
	}
	return nil
}

func (g *Group) ProcessPublicMessage(pm *framing.PublicMessage) error {
	if pm == nil {
		return fmt.Errorf("public message is nil")
	}

	if err := g.VerifyPublicMessage(pm); err != nil {
		return err
	}

	switch pm.Content.ContentType() {
	case framing.ContentTypeProposal:
		body, ok := pm.Content.Body.(framing.ProposalBody)
		if !ok {
			return fmt.Errorf("invalid proposal body")
		}
		proposal, err := UnmarshalProposal(body.Data)
		if err != nil {
			return fmt.Errorf("unmarshaling proposal: %w", err)
		}
		sender := LeafNodeIndex(pm.Content.Sender.LeafIndex)
		if pm.Content.Sender.Type == framing.SenderTypeExternal {
			sender = LeafNodeIndex(g.RatchetTree.NumLeaves + pm.Content.Sender.SenderIndex)
		}
		g.StoreProposal(proposal, sender)
		return nil
	case framing.ContentTypeCommit:
		body, ok := pm.Content.Body.(framing.CommitBody)
		if !ok {
			return fmt.Errorf("invalid commit body")
		}
		commit, err := UnmarshalCommit(body.Data)
		if err != nil {
			return fmt.Errorf("unmarshaling commit: %w", err)
		}
		// Si hay UpdatePath, este flow necesita la HPKE private key del receptor.
		if commit.Path != nil {
			return fmt.Errorf("public commit with update path requires ProcessReceivedCommit")
		}
		ac := &framing.AuthenticatedContent{
			WireFormat:   framing.WireFormatPublicMessage,
			Content:      pm.Content,
			Auth:         pm.Auth,
			GroupContext: g.GroupContext.Marshal(),
		}
		return g.ProcessReceivedCommit(ac, treesync.LeafIndex(pm.Content.Sender.LeafIndex), nil)
	case framing.ContentTypeApplication:
		return fmt.Errorf("public application messages are not supported")
	default:
		return fmt.Errorf("unsupported public message content type: %d", pm.Content.ContentType())
	}
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
	case ProposalTypeExternalInit:
		return nil
	case ProposalTypeReInit:
		return nil
	default:
		return fmt.Errorf("unsupported proposal type: %d", proposal.Type)
	}
}

// applyAddProposal applies an Add proposal.
func (g *Group) applyAddProposal(add *AddProposal) error {
	if add == nil {
		return ErrNilAddProposal
	}
	if add.KeyPackage == nil {
		return ErrNilKeyPackage
	}

	// Validar KeyPackage
	if err := add.KeyPackage.Validate(); err != nil {
		return fmt.Errorf("invalid key package: %w", err)
	}
	if add.KeyPackage.LeafNode == nil {
		return fmt.Errorf("invalid key package leaf node")
	}

	// Insertar en el árbol
	leafData := treesync.LeafNodeData{
		EncryptionKey:  add.KeyPackage.InitKey,
		SignatureKey:   add.KeyPackage.LeafNode.SignatureKey,
		Credential:     add.KeyPackage.LeafNode.Credential,
		Capabilities:   toTreeSyncCapabilities(add.KeyPackage.LeafNode.Capabilities),
		Lifetime:       keyPackageToTreeSyncLifetime(add.KeyPackage.LeafNode.Lifetime),
		LeafNodeSource: 1,
		Signature:      append([]byte(nil), add.KeyPackage.LeafNode.Signature...),
	}
	if leafData.Capabilities == nil {
		leafData.Capabilities = &treesync.LeafNodeCapabilities{}
	}

	if err := keyPackageLeafToTreeSync(add.KeyPackage.LeafNode).Validate(); err != nil {
		return fmt.Errorf("invalid add leaf node: %w", err)
	}

	leafIdx, _ := g.RatchetTree.AddLeaf(leafData)
	leafIndex := LeafNodeIndex(leafIdx)

	// Agregar a Members
	g.Members[leafIndex] = &Member{
		LeafIndex:  leafIndex,
		KeyPackage: add.KeyPackage,
		Credential: add.KeyPackage.LeafNode.Credential,
		Active:     true,
	}

	return nil
}

// applyUpdateProposal applies an Update proposal.
func (g *Group) applyUpdateProposal(update *UpdateProposal, senderIdx LeafNodeIndex) error {
	if update == nil || update.LeafNode == nil {
		return fmt.Errorf("invalid Update proposal")
	}
	if err := keyPackageLeafToTreeSync(update.LeafNode).Validate(); err != nil {
		return fmt.Errorf("invalid update leaf node: %w", err)
	}
	leafData := treesync.LeafNodeData{
		EncryptionKey: update.LeafNode.EncryptionKey,
		SignatureKey:  update.LeafNode.SignatureKey,
		Credential:    update.LeafNode.Credential,
		Capabilities:  toTreeSyncCapabilities(update.LeafNode.Capabilities),
		Lifetime:      keyPackageToTreeSyncLifetime(update.LeafNode.Lifetime),
		Signature:     append([]byte(nil), update.LeafNode.Signature...),
	}
	if leafData.Capabilities == nil {
		leafData.Capabilities = &treesync.LeafNodeCapabilities{}
	}
	return g.RatchetTree.SetLeaf(treesync.LeafIndex(senderIdx), leafData)
}

// applyRemoveProposal applies a Remove proposal.
func (g *Group) applyRemoveProposal(remove *RemoveProposal) error {
	if remove == nil {
		return fmt.Errorf("invalid Remove proposal")
	}

	// Blank the node
	nodeIndex := treesync.LeafIndexToNodeIndex(treesync.LeafIndex(remove.Removed))
	g.RatchetTree.BlankNode(nodeIndex)
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
		EncryptionKey:  myKP.InitKey,
		SignatureKey:   myKP.LeafNode.SignatureKey,
		Credential:     myKP.LeafNode.Credential,
		Capabilities:   toTreeSyncCapabilities(myKP.LeafNode.Capabilities),
		Lifetime:       keyPackageToTreeSyncLifetime(myKP.LeafNode.Lifetime),
		Extensions:     keyPackageExtensionsToTreeSync(myKP.LeafNode.Extensions),
		LeafNodeSource: 1,
		ParentHash:     append([]byte(nil), myKP.LeafNode.ParentHash...),
		Signature:      append([]byte(nil), myKP.LeafNode.Signature...),
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
		PskId:   reInit.GroupID,
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

func (g *Group) VerifyPublicMessage(pm *framing.PublicMessage) error {
	if pm == nil {
		return fmt.Errorf("public message is nil")
	}

	switch pm.Content.Sender.Type {
	case framing.SenderTypeMember:
		senderIdx := LeafNodeIndex(pm.Content.Sender.LeafIndex)
		leaf := g.RatchetTree.GetLeaf(treesync.LeafIndex(senderIdx))
		if leaf == nil || leaf.LeafData == nil || leaf.LeafData.SignatureKey == nil {
			return fmt.Errorf("missing sender signature key")
		}

		rawKey := treesync.MarshalSignatureKey(leaf.LeafData.SignatureKey)
		pubKey := ciphersuite.NewOpenMlsSignaturePublicKey(rawKey, ciphersuite.ECDSA_SECP256R1_SHA256)
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
		pubKey := ciphersuite.NewOpenMlsSignaturePublicKey(sigKey, ciphersuite.ECDSA_SECP256R1_SHA256)
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

func (g *Group) LoadPsk(pskID []byte, pskBytes []byte) {
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
