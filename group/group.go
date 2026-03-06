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
	"crypto/rand"
	"fmt"

	"github.com/openmls/go/ciphersuite"
	keypackages "github.com/openmls/go/key_packages"
	"github.com/openmls/go/schedule"
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
	PendingCommit         *StagedCommit
	ConfirmationTag       []byte
	InterimTranscriptHash []byte
	KeySchedule           *schedule.KeySchedule
	Members               map[LeafNodeIndex]*Member
	state                 GroupState
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
	// Para ahora, usamos todos los del store. En una implementación más avanzada
	// filtraríamos según las reglas del RFC.
	proposals := g.Proposals.Proposals

	// 2. Aplicar proposals a una copia provisional del árbol
	treeDiff := g.RatchetTree.Clone()
	for _, prop := range proposals {
		if err := g.applyProposalToTree(prop, treeDiff); err != nil {
			return nil, fmt.Errorf("applying proposal to tree: %w", err)
		}
	}

	// 3. Generar UpdatePath si es necesario (RFC §12.4.1)
	// Para este commit, siempre generamos uno si hay cambios estructurales
	// o si se solicita explícitamente.
	var updatePath *UpdatePath
	var rootPathSecret *ciphersuite.Secret

	// Generar path secrets y UpdatePath
	// path_secret[root] -> random
	// path_secret[n] = DeriveSecret(path_secret[parent(n)], "path")
	// node_secret[n] = DeriveSecret(path_secret[n], "node")
	// node_key[n] = DeriveSecret(node_secret[n], "key")

	// Implementación simplificada del UpdatePath para cumplir con la estructura
	leafNode := &LeafNode{
		Index:         g.OwnLeafIndex,
		EncryptionKey: make([]byte, 32), // Mock
		SignatureKey:  sigPubKey.AsSlice(),
		Credential:    g.Members[g.OwnLeafIndex].Credential,
	}

	updatePath = &UpdatePath{
		LeafNode: leafNode,
		Nodes:    make([]UpdatePathNode, 0),
	}

	_ = rootPathSecret // Evitar warning de variable no usada

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

	// 5. Crear StagedCommit
	stagedCommit := &StagedCommit{
		Commit:             commit,
		Proposals:          proposals,
		WireFormat:         1, // PublicMessage
		FramedContentBytes: commit.Marshal(),
		Signature:          make([]byte, 64), // Mock
		ConfirmationTag:    make([]byte, 32), // Mock
		RootPathSecret:     ciphersuite.ZeroSecret(g.CipherSuite.HashLength()),
	}

	g.PendingCommit = stagedCommit
	g.state = StatePendingCommit

	return stagedCommit, nil
}

// applyProposalToTree aplica un proposal a un árbol específico.
func (g *Group) applyProposalToTree(proposal *Proposal, tree *treesync.RatchetTree) error {
	switch proposal.Type {
	case ProposalTypeAdd:
		leafData := treesync.LeafNodeData{
			EncryptionKey: proposal.Add.KeyPackage.InitKey,
			SignatureKey:  proposal.Add.KeyPackage.LeafNode.SignatureKey,
			Credential:    proposal.Add.KeyPackage.LeafNode.Credential,
		}
		tree.AddLeaf(leafData)
	case ProposalTypeRemove:
		nodeIdx := treesync.LeafIndexToNodeIndex(treesync.LeafIndex(proposal.Remove.Removed))
		tree.BlankNode(nodeIdx)
	case ProposalTypeUpdate:
		nodeIdx := treesync.LeafIndexToNodeIndex(treesync.LeafIndex(g.OwnLeafIndex))
		leafData := treesync.LeafNodeData{
			EncryptionKey: proposal.Update.LeafNode.EncryptionKey,
			SignatureKey:  proposal.Update.LeafNode.SignatureKey,
			Credential:    proposal.Update.LeafNode.Credential,
		}
		tree.SetLeaf(treesync.LeafIndex(uint32(nodeIdx)/2), leafData)
	}
	return nil
}

// ProcessCommit procesa un commit recibido.
func (g *Group) ProcessCommit(stagedCommit *StagedCommit) error {
	return g.MergeCommit(stagedCommit)
}

// MergeCommit aplica un commit y avanza el estado del protocolo
// RFC 9420 §12.4.2
func (g *Group) MergeCommit(stagedCommit *StagedCommit) error {
	if g.state != StatePendingCommit {
		return fmt.Errorf("group not in pending commit state: %w", ErrInvalidGroupState)
	}
	// 1. Aplicar proposals al ratchet tree
	for _, proposal := range stagedCommit.Proposals {
		if err := g.applyProposal(proposal); err != nil {
			return fmt.Errorf("applying proposal: %w", err)
		}
	}
	// 2. Recomputar TreeHash desde treesync
	treeHash := g.RatchetTree.TreeHash()
	// 3. Calcular ConfirmedTranscriptHash nuevo
	ctHashInput := &ConfirmedTranscriptHashInput{
		WireFormat: stagedCommit.WireFormat, // uint16
		Content:    stagedCommit.FramedContentBytes,
		Signature:  stagedCommit.Signature,
	}

	confirmedTranscriptHash, err := ctHashInput.Calculate(
		g.CipherSuite,
		g.InterimTranscriptHash,
	)
	if err != nil {
		return fmt.Errorf("calculating confirmed transcript hash: %w", err)
	}
	// 4. Calcular InterimTranscriptHash nuevo
	itHashInput := &InterimTranscriptHashInput{
		ConfirmationTag: stagedCommit.ConfirmationTag,
	}

	interimTranscriptHash, err := itHashInput.Calculate(
		g.CipherSuite,
		confirmedTranscriptHash,
	)
	if err != nil {
		return fmt.Errorf("calculating interim transcript hash: %w", err)
	}
	// 5. Actualizar GroupContext (RFC §8.1)
	g.GroupContext.IncrementEpoch()
	g.GroupContext.UpdateTreeHash(treeHash)
	g.GroupContext.UpdateConfirmedTranscriptHash(confirmedTranscriptHash)

	// Actualizar también Group directamente
	g.Epoch = g.GroupContext.Epoch
	g.InterimTranscriptHash = interimTranscriptHash
	// 6. Avanzar key schedule → nuevos EpochSecrets
	// Calcular commit_secret del UpdatePath si existe
	var commitSecret *ciphersuite.Secret
	if stagedCommit.Commit != nil && stagedCommit.Commit.Path != nil {
		// El commit_secret es el path_secret de la raíz
		commitSecret = stagedCommit.RootPathSecret
	} else {
		commitSecret = ciphersuite.ZeroSecret(g.CipherSuite.HashLength())
	}

	g.KeySchedule.SetCommitSecret(commitSecret)

	_, err = g.KeySchedule.ComputeJoinerSecret()
	if err != nil {
		return fmt.Errorf("computing joiner secret: %w", err)
	}

	_, err = g.KeySchedule.ComputePskSecret(nil) // o []Psk{} si hay PSKs
	if err != nil {
		return fmt.Errorf("computing psk secret: %w", err)
	}

	groupContextBytes := g.GroupContext.Marshal()
	_, err = g.KeySchedule.ComputeIntermediateSecret(groupContextBytes)
	if err != nil {
		return fmt.Errorf("computing intermediate secret: %w", err)
	}

	_, err = g.KeySchedule.ComputeEpochSecret()
	if err != nil {
		return fmt.Errorf("computing epoch secret: %w", err)
	}

	g.EpochSecrets, err = g.KeySchedule.DeriveEpochSecrets()
	if err != nil {
		return fmt.Errorf("deriving epoch secrets: %w", err)
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
	if update == nil {
		return fmt.Errorf("invalid Update proposal")
	}

	// TODO: Implement leaf update
	_ = update

	return nil
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

// State returns the current state of the group.
func (g *Group) State() GroupState {
	return g.state
}
