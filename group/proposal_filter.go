package group

import (
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/keypackages"
	"github.com/openmls/go/treesync"
)

// ProposalFilter valida y filtra proposals según RFC 9420 §12.2
type ProposalFilter struct {
	groupContext *GroupContext
	committer    LeafNodeIndex
	members      map[LeafNodeIndex]*Member
	cipherSuite  ciphersuite.CipherSuite
	tree         *treesync.RatchetTree
}

// NewProposalFilter crea un nuevo filtro de proposals.
func NewProposalFilter(
	groupContext *GroupContext,
	committer LeafNodeIndex,
	members map[LeafNodeIndex]*Member,
	cipherSuite ciphersuite.CipherSuite,
	tree *treesync.RatchetTree,
) *ProposalFilter {
	return &ProposalFilter{
		groupContext: groupContext,
		committer:    committer,
		members:      members,
		cipherSuite:  cipherSuite,
		tree:         tree,
	}
}

// FilteredProposal representa un proposal con su sender.
type FilteredProposal struct {
	Proposal *Proposal
	Sender   LeafNodeIndex
}

// FilterAndValidateProposals valida y filtra una lista de proposals.
// Retorna los proposals ordenados según RFC §12.4.2.
//
// RFC 9420 §12.2 reglas de validación:
// - No Update del committer mismo
// - No Remove del committer
// - ExternalInit solo de external senders
// - ReInit incompatible con otros (excepto PreSharedKey)
// - Validar KeyPackages de Add
// - No duplicados del mismo tipo para el mismo miembro
//
// RFC 9420 §12.4.2 orden de aplicación:
// 1. GroupContextExtensions
// 2. Update (del committer al final)
// 3. Remove
// 4. Add
// 5. PreSharedKey
// 6. ReInit
// 7. ExternalInit
func (pf *ProposalFilter) FilterAndValidateProposals(
	proposals []FilteredProposal,
	capabilities *keypackages.Capabilities,
) ([]FilteredProposal, error) {
	if len(proposals) == 0 {
		return nil, fmt.Errorf("no proposals to filter: %w", ErrInvalidProposal)
	}

	// Paso 1: Validar cada proposal individualmente
	validated := make([]FilteredProposal, 0, len(proposals))
	for _, fp := range proposals {
		if err := pf.validateSingleProposal(fp, capabilities); err != nil {
			return nil, fmt.Errorf("validating proposal from %d: %w", fp.Sender, err)
		}
		validated = append(validated, fp)
	}

	// Paso 2: Validar combinaciones y restricciones
	if err := pf.validateProposalCombinations(validated); err != nil {
		return nil, fmt.Errorf("validating proposal combinations: %w", err)
	}

	// Paso 3: Verificar duplicados
	if err := pf.checkDuplicates(validated); err != nil {
		return nil, fmt.Errorf("checking duplicates: %w", err)
	}

	// Paso 4: Ordenar según RFC §12.4.2
	sorted := pf.sortProposals(validated)

	return sorted, nil
}

// validateSingleProposal valida un proposal individual.
func (pf *ProposalFilter) validateSingleProposal(
	fp FilteredProposal,
	capabilities *keypackages.Capabilities,
) error {
	proposal := fp.Proposal
	if err := ValidateProposal(proposal, capabilities); err != nil {
		return err
	}
	switch proposal.Type {
	case ProposalTypeAdd:
		if proposal.Add != nil && proposal.Add.KeyPackage != nil && proposal.Add.KeyPackage.LeafNode != nil {
			if err := validateCapabilitiesCompatible(
				pf.cipherSuite,
				toTreeSyncCapabilities(proposal.Add.KeyPackage.LeafNode.Capabilities),
			); err != nil {
				return err
			}
			// RFC 9420 §12.2: Verificar firma del KeyPackage en Add proposals
			if err := proposal.Add.KeyPackage.Verify(pf.cipherSuite); err != nil {
				return fmt.Errorf("add proposal keypackage signature invalid: %w", err)
			}
		}
	case ProposalTypeUpdate:
		if fp.Sender == pf.committer {
			return fmt.Errorf("committer cannot update itself: %w", ErrInvalidProposal)
		}
		leaf := pf.tree.GetLeaf(treesync.LeafIndex(fp.Sender))
		if leaf == nil || leaf.State != treesync.NodeStatePresent {
			return fmt.Errorf("update proposal from non-present leaf %d: %w", fp.Sender, ErrInvalidProposal)
		}
		if proposal.Update != nil && proposal.Update.LeafNode != nil {
			if err := validateCapabilitiesCompatible(
				pf.cipherSuite,
				toTreeSyncCapabilities(proposal.Update.LeafNode.Capabilities),
			); err != nil {
				return err
			}
			// RFC 9420 §12.2, §7.3: Verificar firma del LeafNode en Update proposals
			// Usar VerifyWithContext para incluir group_id y leaf_index
			ln := keyPackageLeafToTreeSync(proposal.Update.LeafNode)
			if err := ln.VerifyWithContext(
				pf.cipherSuite,
				pf.groupContext.GroupID.AsSlice(),
				uint32(fp.Sender),
			); err != nil {
				return fmt.Errorf("update leaf node signature invalid: %w", err)
			}
		}
	case ProposalTypeRemove:
		if proposal.Remove != nil && proposal.Remove.Removed == pf.committer {
			return fmt.Errorf("cannot remove the committer: %w", ErrInvalidProposal)
		}
		if proposal.Remove != nil {
			if _, exists := pf.members[proposal.Remove.Removed]; !exists {
				return fmt.Errorf("removing non-existent member at index %d: %w",
					proposal.Remove.Removed, ErrInvalidProposal)
			}
		}
	case ProposalTypeExternalInit:
		if int(fp.Sender) < len(pf.members) {
			return fmt.Errorf("external init from internal sender: %w", ErrInvalidProposal)
		}
	}
	return nil
}

// validateProposalCombinations valida combinaciones de proposals.
func (pf *ProposalFilter) validateProposalCombinations(proposals []FilteredProposal) error {
	hasReInit := false
	hasOther := false

	for _, fp := range proposals {
		switch fp.Proposal.Type {
		case ProposalTypeReInit:
			hasReInit = true
		case ProposalTypePreSharedKey:
			// PreSharedKey es compatible con ReInit
		default:
			hasOther = true
		}
	}

	// RFC §12.2: ReInit es incompatible con otros tipos (excepto PreSharedKey)
	if hasReInit && hasOther {
		return fmt.Errorf("reinit incompatible with other proposal types: %w", ErrInvalidProposal)
	}

	return nil
}

// checkDuplicates verifica que no haya proposals duplicados.
func (pf *ProposalFilter) checkDuplicates(proposals []FilteredProposal) error {
	// Track updates por sender
	updatesBySender := make(map[LeafNodeIndex]bool)
	// Track removes por índice
	removesByIndex := make(map[LeafNodeIndex]bool)
	// Track adds por key package hash
	addsByKeyPackage := make(map[string]bool)
	// Track PSK IDs externos (RFC §12.2: no pueden repetirse)
	pskIDs := make(map[string]bool)

	for _, fp := range proposals {
		switch fp.Proposal.Type {
		case ProposalTypeUpdate:
			if updatesBySender[fp.Sender] {
				return fmt.Errorf("duplicate update from sender %d: %w",
					fp.Sender, ErrInvalidProposal)
			}
			updatesBySender[fp.Sender] = true

		case ProposalTypeRemove:
			if fp.Proposal.Remove != nil {
				if removesByIndex[fp.Proposal.Remove.Removed] {
					return fmt.Errorf("duplicate remove for index %d: %w",
						fp.Proposal.Remove.Removed, ErrInvalidProposal)
				}
				removesByIndex[fp.Proposal.Remove.Removed] = true
			}

		case ProposalTypeAdd:
			if fp.Proposal.Add != nil && fp.Proposal.Add.KeyPackage != nil {
				kpHash := hashKeyPackage(fp.Proposal.Add.KeyPackage)
				if addsByKeyPackage[kpHash] {
					return fmt.Errorf("duplicate add for key package: %w", ErrInvalidProposal)
				}
				addsByKeyPackage[kpHash] = true
			}

		case ProposalTypePreSharedKey:
			// RFC §12.2: PSK IDs must not repeat within a commit.
			if fp.Proposal.PreSharedKey != nil {
				pid := fp.Proposal.PreSharedKey.PskID
				key := string(pid.ID) + fmt.Sprintf(":%d:%x:%d", pid.PskType, pid.PskGroupID, pid.PskEpoch)
				if pskIDs[key] {
					return fmt.Errorf("duplicate PSK ID in proposals: %w", ErrInvalidProposal)
				}
				pskIDs[key] = true
			}
		}
	}

	// RFC §12.2 ValSem101–103: claves únicas en Add proposals.
	if err := pf.checkAddKeyUniqueness(proposals); err != nil {
		return err
	}

	return nil
}

// checkAddKeyUniqueness verifica que las claves de los Add proposals sean únicas
// respecto a otros Add proposals y a los miembros existentes del árbol (RFC §12.2).
//
// ValSem101: signature keys únicas en Adds y vs árbol existente.
// ValSem102: init keys únicas entre Adds.
// ValSem103: encryption keys únicas en Adds y vs árbol existente.
func (pf *ProposalFilter) checkAddKeyUniqueness(proposals []FilteredProposal) error {
	// Recolectar claves existentes del árbol (leaf nodes presentes).
	existingEncKeys := make(map[string]bool)
	existingSigKeys := make(map[string]bool)

	for i := range pf.tree.Nodes {
		node := &pf.tree.Nodes[i]
		if node.State != treesync.NodeStatePresent || node.LeafData == nil {
			continue
		}
		if len(node.LeafData.EncryptionKey) > 0 {
			existingEncKeys[string(node.LeafData.EncryptionKey)] = true
		}
		// SignatureKeyRaw contiene los bytes crudos de la clave de firma.
		if len(node.LeafData.SignatureKeyRaw) > 0 {
			existingSigKeys[string(node.LeafData.SignatureKeyRaw)] = true
		}
	}

	addEncKeys := make(map[string]bool)
	addInitKeys := make(map[string]bool)
	addSigKeys := make(map[string]bool)

	for _, fp := range proposals {
		if fp.Proposal.Type != ProposalTypeAdd || fp.Proposal.Add == nil {
			continue
		}
		kp := fp.Proposal.Add.KeyPackage
		if kp == nil {
			continue
		}

		// ValSem102: init key único entre Adds.
		if len(kp.InitKey) > 0 {
			k := string(kp.InitKey)
			if addInitKeys[k] {
				return fmt.Errorf("duplicate init key in Add proposals: %w", ErrInvalidProposal)
			}
			addInitKeys[k] = true
		}

		ln := kp.LeafNode
		if ln == nil {
			continue
		}

		// ValSem103: encryption key único en Adds y vs árbol.
		if len(ln.EncryptionKey) > 0 {
			k := string(ln.EncryptionKey)
			if addEncKeys[k] {
				return fmt.Errorf("duplicate encryption key in Add proposals: %w", ErrInvalidProposal)
			}
			if existingEncKeys[k] {
				return fmt.Errorf("encryption key in Add proposal already in use by tree member: %w", ErrInvalidProposal)
			}
			addEncKeys[k] = true
		}

		// ValSem101: signature key único en Adds y vs árbol.
		// Usamos SignatureKeyBytes (raw bytes parseados del wire) si está disponible.
		sigBytes := ln.SignatureKeyBytes
		if len(sigBytes) == 0 && ln.SignatureKey != nil {
			sigBytes = treesync.MarshalSignatureKey(ln.SignatureKey)
		}
		if len(sigBytes) > 0 {
			k := string(sigBytes)
			if addSigKeys[k] {
				return fmt.Errorf("duplicate signature key in Add proposals: %w", ErrInvalidProposal)
			}
			if existingSigKeys[k] {
				return fmt.Errorf("signature key in Add proposal already in use by tree member: %w", ErrInvalidProposal)
			}
			addSigKeys[k] = true
		}
	}

	return nil
}

// sortProposals ordena los proposals según RFC §12.4.2.
// Orden: GroupContextExtensions, Update, Remove, Add, PreSharedKey, ReInit, ExternalInit
func (pf *ProposalFilter) sortProposals(proposals []FilteredProposal) []FilteredProposal {
	// Crear copia para no modificar el original
	sorted := make([]FilteredProposal, len(proposals))
	copy(sorted, proposals)

	// Definir prioridad de tipos (menor número = aplicar primero)
	priority := map[ProposalType]int{
		ProposalTypeGroupContextExtensions: 1,
		ProposalTypeUpdate:                 2,
		ProposalTypeRemove:                 3,
		ProposalTypeAdd:                    4,
		ProposalTypePreSharedKey:           5,
		ProposalTypeReInit:                 6,
		ProposalTypeExternalInit:           7,
	}

	sort.SliceStable(sorted, func(i, j int) bool {
		pi := priority[sorted[i].Proposal.Type]
		pj := priority[sorted[j].Proposal.Type]

		// Si son del mismo tipo, Updates del committer van al final
		if pi == pj && sorted[i].Proposal.Type == ProposalTypeUpdate {
			// El committer va después que otros
			if sorted[i].Sender == pf.committer {
				return false
			}
			if sorted[j].Sender == pf.committer {
				return true
			}
		}

		return pi < pj
	})

	return sorted
}

// hashKeyPackage calcula un hash simple del key package.
func hashKeyPackage(kp *keypackages.KeyPackage) string {
	if kp == nil {
		return ""
	}
	h := sha256.Sum256(kp.Marshal())
	return string(h[:])
}

// FilterProposalsForCommit es una función helper que filtra proposals para un commit.
// Extrae proposals del ProposalStore y los prepara para el commit.
func (g *Group) FilterProposalsForCommit(
	capabilities *keypackages.Capabilities,
) ([]FilteredProposal, error) {
	filtered := make([]FilteredProposal, 0, len(g.Proposals.Proposals))
	for _, sp := range g.Proposals.Proposals {
		filtered = append(filtered, FilteredProposal{
			Proposal: sp.Proposal,
			Sender:   sp.Sender,
		})
	}

	pf := NewProposalFilter(
		g.GroupContext,
		g.OwnLeafIndex,
		g.Members,
		g.CipherSuite,
		g.RatchetTree,
	)

	return pf.FilterAndValidateProposals(filtered, capabilities)
}

func validateCapabilitiesCompatible(
	groupCS ciphersuite.CipherSuite,
	leafCaps *treesync.LeafNodeCapabilities,
) error {
	if leafCaps == nil {
		return fmt.Errorf("missing leaf capabilities: %w", ErrInvalidProposal)
	}

	supportsVersion := false
	for _, v := range leafCaps.ProtocolVersions {
		if v == 0x0001 {
			supportsVersion = true
			break
		}
	}
	if !supportsVersion {
		return fmt.Errorf("leaf does not support MLS 1.0: %w", ErrInvalidProposal)
	}

	supportCS := false
	for _, cs := range leafCaps.CipherSuites {
		if ciphersuite.CipherSuite(cs) == groupCS {
			supportCS = true
			break
		}
	}
	if !supportCS {
		return fmt.Errorf("leaf does not support group cipher suite: %d: %w", groupCS, ErrInvalidProposal)
	}

	return nil
}

func toTreeSyncCapabilities(caps *keypackages.Capabilities) *treesync.LeafNodeCapabilities {
	if caps == nil {
		return nil
	}

	versions := make([]uint16, len(caps.ProtocolVersions))
	for i, v := range caps.ProtocolVersions {
		versions[i] = uint16(v)
	}

	cipherSuites := make([]uint16, len(caps.CipherSuites))
	for i, cs := range caps.CipherSuites {
		cipherSuites[i] = uint16(cs)
	}

	return &treesync.LeafNodeCapabilities{
		ProtocolVersions: versions,
		CipherSuites:     cipherSuites,
		Extensions:       append([]uint16(nil), caps.Extensions...),
		Proposals:        append([]uint16(nil), caps.Proposals...),
		Credentials:      append([]uint16(nil), caps.Credentials...),
	}
}
