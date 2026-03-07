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

	_, err := keySchedule.ComputeJoinerSecret()
	if err != nil {
		return nil, fmt.Errorf("computing joiner secret: %w", err)
	}

	_, err = keySchedule.ComputePskSecret([]schedule.Psk{})
	if err != nil {
		return nil, fmt.Errorf("computing psk secret: %w", err)
	}

	groupContextBytes := groupContext.Marshal()
	_, err = keySchedule.ComputeIntermediateSecret(groupContextBytes)
	if err != nil {
		return nil, fmt.Errorf("computing intermediate secret: %w", err)
	}

	_, err = keySchedule.ComputeEpochSecret()
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
		KeySchedule:           keySchedule,
		InterimTranscriptHash: []byte{}, // string vacio
		Members:               make(map[LeafNodeIndex]*Member),
		state:                 StateOperational,
	}

	// Initialize secret tree
	group.SecretTree, err = secrettree.NewTree(epochSecrets.EncryptionSecret, 1)
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
	g.Proposals.AddProposal(proposal)

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

	// Create Update proposal
	proposal := &Proposal{
		Type: ProposalTypeUpdate,
		Update: &UpdateProposal{
			LeafNode: nil, // TODO: Convert treesync.LeafNodeData to keypackages.LeafNode
		},
	}

	// Store proposal
	g.Proposals.AddProposal(proposal)

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
	g.Proposals.AddProposal(proposal)

	return proposal, nil
}

// Commit applies all pending proposals and creates a new epoch.
//
// This is the main function to advance the group to a new epoch.
// RFC 9420 §12.4
func (g *Group) Commit(
	sigPrivKey *ciphersuite.SignaturePrivateKey,
	sigPubKey *ciphersuite.SignaturePublicKey,
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
	for _, prop := range proposals {
		if err := g.applyProposalToTree(prop, treeDiff); err != nil {
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

	// Firmar el TBS
	sig, err := sigPrivKey.Sign(ac.MarshalTBS())
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
	newKS := schedule.NewKeySchedule(g.CipherSuite, g.EpochSecrets.InitSecret)
	newKS.SetCommitSecret(commitSecret)
	if _, err = newKS.ComputeJoinerSecret(); err != nil {
		return nil, fmt.Errorf("new epoch joiner secret: %w", err)
	}
	if _, err = newKS.ComputePskSecret(nil); err != nil {
		return nil, fmt.Errorf("new epoch psk secret: %w", err)
	}
	if _, err = newKS.ComputeIntermediateSecret(newGC.Marshal()); err != nil {
		return nil, fmt.Errorf("new epoch intermediate secret: %w", err)
	}
	if _, err = newKS.ComputeEpochSecret(); err != nil {
		return nil, fmt.Errorf("new epoch epoch secret: %w", err)
	}
	newEpochSecrets, err := newKS.DeriveEpochSecrets()
	if err != nil {
		return nil, fmt.Errorf("deriving new epoch secrets: %w", err)
	}

	// confirmation_tag = MAC(confirmation_key, confirmed_transcript_hash) (RFC §8.2)
	confirmationTag := schedule.ComputeConfirmationTag(
		newEpochSecrets.ConfirmationKey.AsSlice(),
		confirmedHash,
	)
	ac.Auth.ConfirmationTag = confirmationTag

	newInterimHash := schedule.ComputeInterimTranscriptHash(confirmedHash, confirmationTag)

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

	leafNodeData := &treesync.LeafNodeData{
		EncryptionKey:  leafSecret.AsSlice(),
		SignatureKey:   sigPubKeyECDSA,
		Credential:     g.Members[g.OwnLeafIndex].Credential,
		Capabilities:   &treesync.LeafNodeCapabilities{},
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
func (g *Group) applyProposalToTree(proposal *Proposal, tree *treesync.RatchetTree) error {
	switch proposal.Type {
	case ProposalTypeAdd:
		leafData := treesync.LeafNodeData{
			EncryptionKey:  proposal.Add.KeyPackage.InitKey,
			SignatureKey:   proposal.Add.KeyPackage.LeafNode.SignatureKey,
			Credential:     proposal.Add.KeyPackage.LeafNode.Credential,
			Capabilities:   &treesync.LeafNodeCapabilities{},
			Lifetime:       &treesync.LeafNodeLifetime{},
			LeafNodeSource: 1, // key_package
		}
		tree.AddLeaf(leafData)
	case ProposalTypeRemove:
		nodeIdx := treesync.LeafIndexToNodeIndex(treesync.LeafIndex(proposal.Remove.Removed))
		tree.BlankNode(nodeIdx)
	case ProposalTypeUpdate:
		leafIdx := treesync.LeafIndex(g.OwnLeafIndex)
		leafData := treesync.LeafNodeData{
			EncryptionKey: proposal.Update.LeafNode.EncryptionKey,
			SignatureKey:  proposal.Update.LeafNode.SignatureKey,
			Credential:    proposal.Update.LeafNode.Credential,
		}
		tree.SetLeaf(leafIdx, leafData)
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
func (g *Group) StoreProposal(p *Proposal) []byte {
	if g.ProposalByRef == nil {
		g.ProposalByRef = make(map[string]*Proposal)
	}
	ref := ComputeProposalRef(p)
	g.ProposalByRef[string(ref)] = p
	g.Proposals.AddProposal(p)
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
	if commit.Path != nil {
		rootPathSecret, err = g.decryptPathSecret(senderLeafIdx, commit.Path, myHpkePrivKeyBytes)
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
	senderLeafIdx treesync.LeafIndex,
	updatePath *UpdatePath,
	myPrivKeyBytes []byte,
) (*ciphersuite.Secret, error) {
	directPath := g.RatchetTree.DirectPath(senderLeafIdx)
	copath := g.RatchetTree.Copath(senderLeafIdx)
	myNodeIdx := treesync.LeafIndexToNodeIndex(treesync.LeafIndex(g.OwnLeafIndex))

	for i := 1; i < len(directPath); i++ {
		res := g.RatchetTree.Resolution(copath[i-1])
		for j, resIdx := range res {
			if resIdx != myNodeIdx {
				continue
			}
			// Encontramos nuestra posición en la resolución
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

			// Derivar hacia adelante hasta el commit_secret (último path secret)
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
	for _, proposal := range stagedCommit.Proposals {
		if err := g.applyProposal(proposal); err != nil {
			return fmt.Errorf("applying proposal: %w", err)
		}
	}

	// 1.2 Aplicar UpdatePath si existe
	if stagedCommit.Commit.Path != nil {
		// Obtener índice de hoja del emisor desde AuthenticatedContent
		senderLeafIdx := treesync.LeafIndex(stagedCommit.AuthenticatedContent.Content.Sender.LeafIndex)
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
	// 6. Avanzar key schedule → nuevos EpochSecrets
	if stagedCommit.PrecomputedEpochSecrets != nil {
		// Committer: usar epoch secrets precalculados en Commit()
		g.EpochSecrets = stagedCommit.PrecomputedEpochSecrets
	} else {
		// Receptor: derivar desde init_secret del epoch actual
		var commitSecret *ciphersuite.Secret
		if stagedCommit.Commit != nil && stagedCommit.Commit.Path != nil {
			commitSecret = stagedCommit.RootPathSecret
		} else {
			commitSecret = ciphersuite.ZeroSecret(g.CipherSuite.HashLength())
		}

		newKS := schedule.NewKeySchedule(g.CipherSuite, g.EpochSecrets.InitSecret)
		newKS.SetCommitSecret(commitSecret)
		if _, err = newKS.ComputeJoinerSecret(); err != nil {
			return fmt.Errorf("computing joiner secret: %w", err)
		}
		if _, err = newKS.ComputePskSecret(nil); err != nil {
			return fmt.Errorf("computing psk secret: %w", err)
		}
		if _, err = newKS.ComputeIntermediateSecret(g.GroupContext.Marshal()); err != nil {
			return fmt.Errorf("computing intermediate secret: %w", err)
		}
		if _, err = newKS.ComputeEpochSecret(); err != nil {
			return fmt.Errorf("computing epoch secret: %w", err)
		}
		var newEpochSecrets *schedule.EpochSecrets
		newEpochSecrets, err = newKS.DeriveEpochSecrets()
		if err != nil {
			return fmt.Errorf("deriving epoch secrets: %w", err)
		}

		// Verificar confirmation_tag del commit (RFC §12.4.2)
		expectedTag := schedule.ComputeConfirmationTag(
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
	g.SecretTree, err = secrettree.NewTree(g.EpochSecrets.EncryptionSecret, g.RatchetTree.NumLeaves)
	if err != nil {
		return fmt.Errorf("updating secret tree: %w", err)
	}

	// 7. Limpiar estado
	g.Proposals.Clear()
	g.PendingCommit = nil
	g.state = StateOperational
	return nil
}

// applyProposal applies a single proposal to the group state.
func (g *Group) applyProposal(proposal *Proposal) error {
	switch proposal.Type {
	case ProposalTypeAdd:
		return g.applyAddProposal(proposal.Add)
	case ProposalTypeUpdate:
		return g.applyUpdateProposal(proposal.Update)
	case ProposalTypeRemove:
		return g.applyRemoveProposal(proposal.Remove)
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

	// Insertar en el árbol
	leafData := treesync.LeafNodeData{
		EncryptionKey:  add.KeyPackage.InitKey,
		SignatureKey:   add.KeyPackage.LeafNode.SignatureKey,
		Credential:     add.KeyPackage.LeafNode.Credential,
		Capabilities:   &treesync.LeafNodeCapabilities{},
		Lifetime:       &treesync.LeafNodeLifetime{},
		LeafNodeSource: 1, // key_package
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
func (g *Group) applyUpdateProposal(update *UpdateProposal) error {
	if update == nil || update.LeafNode == nil {
		return fmt.Errorf("invalid Update proposal")
	}
	leafData := treesync.LeafNodeData{
		EncryptionKey: update.LeafNode.EncryptionKey,
		SignatureKey:  update.LeafNode.SignatureKey,
		Credential:    update.LeafNode.Credential,
	}
	return g.RatchetTree.SetLeaf(treesync.LeafIndex(g.OwnLeafIndex), leafData)
}

// applyRemoveProposal applies a Remove proposal.
func (g *Group) applyRemoveProposal(remove *RemoveProposal) error {
	if remove == nil {
		return fmt.Errorf("invalid Remove proposal")
	}

	// Blank the node
	nodeIndex := treesync.LeafIndexToNodeIndex(treesync.LeafIndex(remove.Removed))
	g.RatchetTree.BlankNode(nodeIndex)

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

// EncryptApplicationMessage cifre un mensaje de aplicación.
func (g *Group) EncryptApplicationMessage(plaintext []byte) (*framing.MLSMessage, error) {
	if g.state != StateOperational {
		return nil, fmt.Errorf("group not operational")
	}

	// 1. Preparar FramedContent
	content := framing.FramedContent{
		GroupID: g.GroupID.AsSlice(),
		Epoch:   g.Epoch.AsUint64(),
		Sender:  framing.Sender{Type: framing.SenderTypeMember, LeafIndex: uint32(g.OwnLeafIndex)},
		Body:    framing.ApplicationData{Data: plaintext},
	}

	// 2. Encriptar usando framing
	// Necesitamos los secrets del SecretTree
	_, err := g.SecretTree.LeafForIndex(uint32(g.OwnLeafIndex))
	if err != nil {
		return nil, err
	}

	params := framing.EncryptParams{
		Content:          content,
		SenderLeafIndex:  uint32(g.OwnLeafIndex),
		CipherSuite:      g.CipherSuite,
		SenderDataSecret: g.EpochSecrets.SenderDataSecret,
		SecretTree:       g.SecretTree,
		SigKey:           nil, // TODO: Necesitamos clave de firma real
		GroupContext:     g.GroupContext.Marshal(),
	}

	// Por ahora delegamos a framing.Encrypt (esto retornará un PrivateMessage)
	privMsg, err := framing.Encrypt(params)
	if err != nil {
		return nil, err
	}

	return framing.NewMLSMessagePrivate(privMsg), nil
}

// DecryptApplicationMessage descifra un mensaje de aplicación.
func (g *Group) DecryptApplicationMessage(msg *framing.MLSMessage) ([]byte, error) {
	// 1. Validar tipo de mensaje
	privMsg, ok := msg.AsPrivate()
	if !ok {
		return nil, fmt.Errorf("not a private message")
	}

	// 2. Desencriptar usando framing
	params := framing.DecryptParams{
		CipherSuite:      g.CipherSuite,
		SenderDataSecret: g.EpochSecrets.SenderDataSecret,
		SecretTree:       g.SecretTree,
		GroupContext:     g.GroupContext.Marshal(),
	}

	ac, err := framing.Decrypt(privMsg, params)
	if err != nil {
		return nil, err
	}

	// 3. Extraer plaintext
	appData, ok := ac.Content.Body.(framing.ApplicationData)
	if !ok {
		return nil, fmt.Errorf("not application data")
	}

	return appData.Data, nil
}

// State returns the current state of the group.
func (g *Group) State() GroupState {
	return g.state
}
