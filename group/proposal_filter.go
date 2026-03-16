package group

import (
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/extensions"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/treesync"
)

// ProposalFilter validates and filters proposals according to RFC 9420 §12.2.
//
// The filter enforces validation rules, checks for duplicates, and orders
// proposals according to the RFC-specified application order.
type ProposalFilter struct {
	groupContext *GroupContext
	committer    LeafNodeIndex
	members      map[LeafNodeIndex]*Member
	cipherSuite  ciphersuite.CipherSuite
	tree         *treesync.RatchetTree
}

// NewProposalFilter creates a new proposal filter.
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

// FilteredProposal represents a proposal with its sender.
type FilteredProposal struct {
	Proposal   *Proposal
	Sender     LeafNodeIndex
	IsExternal bool // true for SenderTypeExternal senders (not leaf-tree members)
}

// FilterAndValidateProposals validates and filters a list of proposals per RFC 9420 §12.2.
//
// # RFC 9420 §12.2 Validation Rules
//
//   - No Update of the committer itself
//   - No Remove of the committer
//   - ExternalInit only from external senders
//   - ReInit incompatible with other proposals (except PreSharedKey)
//   - Validate KeyPackages in Add proposals
//   - No duplicate proposals of the same type for the same member
//
// # RFC 9420 §12.4.2 Application Order
//
// Proposals are sorted in this order:
//
//  1. GroupContextExtensions
//  2. Update (committer's update last)
//  3. Remove
//  4. Add
//  5. PreSharedKey
//  6. ReInit
//  7. ExternalInit
func (pf *ProposalFilter) FilterAndValidateProposals(
	proposals []FilteredProposal,
	capabilities *keypackages.Capabilities,
) ([]FilteredProposal, error) {
	// Validate each proposal individually
	validated := make([]FilteredProposal, 0, len(proposals))
	for _, fp := range proposals {
		if err := pf.validateSingleProposal(fp, capabilities); err != nil {
			return nil, fmt.Errorf("validating proposal from %d: %w", fp.Sender, err)
		}
		validated = append(validated, fp)
	}

	// Validate combinations and restrictions
	if err := pf.validateProposalCombinations(validated); err != nil {
		return nil, fmt.Errorf("validating proposal combinations: %w", err)
	}

	// Check for duplicates
	if err := pf.checkDuplicates(validated); err != nil {
		return nil, fmt.Errorf("checking duplicates: %w", err)
	}

	// Sort according to RFC §12.4.2
	sorted := pf.sortProposals(validated)

	return sorted, nil
}

// validateSingleProposal validates an individual proposal.
func (pf *ProposalFilter) validateSingleProposal(
	fp FilteredProposal,
	capabilities *keypackages.Capabilities,
) error {
	proposal := fp.Proposal
	if err := ValidateProposal(proposal, capabilities); err != nil {
		return err
	}

	requiredCaps := pf.extractRequiredCapabilities()

	switch proposal.Type {
	case ProposalTypeAdd:
		if proposal.Add != nil && proposal.Add.KeyPackage != nil && proposal.Add.KeyPackage.LeafNode != nil {
			if err := validateCapabilitiesCompatible(
				pf.cipherSuite,
				toTreeSyncCapabilities(proposal.Add.KeyPackage.LeafNode.Capabilities),
				requiredCaps,
			); err != nil {
				return err
			}
			// RFC 9420 §12.2: Verify KeyPackage signature in Add proposals
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
			// RFC §7.3: leaf_node_source MUST be update (2) in an Update proposal
			if proposal.Update.LeafNode.LeafNodeSource != 2 {
				return fmt.Errorf("update proposal leaf_node_source is %d, want 2 (update): %w",
					proposal.Update.LeafNode.LeafNodeSource, ErrInvalidProposal)
			}
			if err := validateCapabilitiesCompatible(
				pf.cipherSuite,
				toTreeSyncCapabilities(proposal.Update.LeafNode.Capabilities),
				requiredCaps,
			); err != nil {
				return err
			}
			// RFC 9420 §12.2, §7.3: Verify LeafNode signature with context
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

	case ProposalTypePreSharedKey:
		// RFC §12.1.4: psk_nonce MUST be of length KDF.Nh
		if proposal.PreSharedKey != nil {
			nh := pf.cipherSuite.HashLength()
			if len(proposal.PreSharedKey.PskID.Nonce) != nh {
				return fmt.Errorf("PSK nonce length %d, want %d (KDF.Nh): %w",
					len(proposal.PreSharedKey.PskID.Nonce), nh, ErrInvalidProposal)
			}
		}

	case ProposalTypeExternalInit:
		// RFC §12.1.6: ExternalInit MUST be sent by an external sender (not a tree member)
		if !fp.IsExternal {
			return fmt.Errorf("external init from internal sender: %w", ErrInvalidProposal)
		}

	case ProposalTypeGroupContextExtensions:
		// RFC §12.1.7: verify all existing members support the new required_capabilities
		if proposal.GroupContextExtensions != nil {
			if err := pf.validateGCEMemberCompatibility(proposal.GroupContextExtensions.Extensions); err != nil {
				return err
			}
		}
	}

	return nil
}

// validateProposalCombinations validates combinations of proposals.
func (pf *ProposalFilter) validateProposalCombinations(proposals []FilteredProposal) error {
	hasReInit := false
	hasOther := false

	for _, fp := range proposals {
		switch fp.Proposal.Type {
		case ProposalTypeReInit:
			hasReInit = true
		case ProposalTypePreSharedKey:
			// PreSharedKey is compatible with ReInit
		default:
			hasOther = true
		}
	}

	// RFC §12.2: ReInit is incompatible with other types (except PreSharedKey)
	if hasReInit && hasOther {
		return fmt.Errorf("reinit incompatible with other proposal types: %w", ErrInvalidProposal)
	}

	return nil
}

// checkDuplicates checks for duplicate proposals.
func (pf *ProposalFilter) checkDuplicates(proposals []FilteredProposal) error {
	// Track updates by sender
	updatesBySender := make(map[LeafNodeIndex]bool)
	// Track removes by index
	removesByIndex := make(map[LeafNodeIndex]bool)
	// Track adds by key package hash
	addsByKeyPackage := make(map[string]bool)
	// Track PSK IDs (RFC §12.2: must not repeat)
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
			// RFC §12.2: PSK IDs must not repeat within a commit
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

	// RFC §12.2 ValSem101–103: unique keys in Add proposals
	return pf.checkAddKeyUniqueness(proposals)
}

// checkAddKeyUniqueness verifies that keys in Add proposals are unique.
//
// RFC 9420 §12.2 validation semantics:
//
//   - ValSem101: Unique signature keys in Adds and vs existing tree
//   - ValSem102: Unique init keys among Adds
//   - ValSem103: Unique encryption keys in Adds and vs existing tree
func (pf *ProposalFilter) checkAddKeyUniqueness(proposals []FilteredProposal) error {
	// Collect existing keys from tree
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

		// ValSem102: Unique init key among Adds
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

		// ValSem103: Unique encryption key in Adds and vs tree
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

		// ValSem101: Unique signature key in Adds and vs tree
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

// sortProposals sorts proposals according to RFC 9420 §12.4.2 application order.
//
// Order: GroupContextExtensions → Update → Remove → Add → PreSharedKey → ReInit → ExternalInit
func (pf *ProposalFilter) sortProposals(proposals []FilteredProposal) []FilteredProposal {
	// Create copy to avoid modifying original
	sorted := make([]FilteredProposal, len(proposals))
	copy(sorted, proposals)

	// Define priority (lower number = apply first)
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

		// For same type, committer's Update goes last
		if pi == pj && sorted[i].Proposal.Type == ProposalTypeUpdate {
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

// hashKeyPackage computes a simple hash of the key package.
func hashKeyPackage(kp *keypackages.KeyPackage) string {
	if kp == nil {
		return ""
	}
	h := sha256.Sum256(kp.Marshal())
	return string(h[:])
}

// FilterProposalsForCommit filters proposals from the ProposalStore for a commit.
//
// This is a helper that extracts proposals from the ProposalStore and prepares
// them for the commit operation.
func (g *Group) FilterProposalsForCommit(
	capabilities *keypackages.Capabilities,
) ([]FilteredProposal, error) {
	filtered := make([]FilteredProposal, 0, len(g.Proposals.Proposals))
	for _, sp := range g.Proposals.Proposals {
		filtered = append(filtered, FilteredProposal{Proposal: sp.Proposal, Sender: sp.Sender})
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

// validateCapabilitiesCompatible checks if leaf capabilities are compatible with the group.
//
// Validates:
//   - MLS 1.0 support
//   - Group cipher suite support
//   - All extensions/proposals/credentials listed in required_capabilities (RFC §11.1)
func validateCapabilitiesCompatible(
	groupCS ciphersuite.CipherSuite,
	leafCaps *treesync.LeafNodeCapabilities,
	required *extensions.RequiredCapabilitiesExtension,
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
		return fmt.Errorf("leaf does not support group cipher suite %d: %w", groupCS, ErrInvalidProposal)
	}

	if required == nil {
		return nil
	}

	// RFC §11.1: leaf MUST support all required extension types
	for _, reqExt := range required.Extensions {
		found := false
		for _, leafExt := range leafCaps.Extensions {
			if uint16(reqExt) == leafExt {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("leaf does not support required extension type %d: %w", reqExt, ErrInvalidProposal)
		}
	}

	// RFC §11.1: leaf MUST support all required proposal types
	for _, reqProp := range required.Proposals {
		found := false
		for _, leafProp := range leafCaps.Proposals {
			if reqProp == leafProp {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("leaf does not support required proposal type %d: %w", reqProp, ErrInvalidProposal)
		}
	}

	// RFC §11.1: leaf MUST support all required credential types
	for _, reqCred := range required.Credentials {
		found := false
		for _, leafCred := range leafCaps.Credentials {
			if uint16(reqCred) == leafCred {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("leaf does not support required credential type %d: %w", reqCred, ErrInvalidProposal)
		}
	}

	return nil
}

// extractRequiredCapabilities looks for a required_capabilities extension (type 0x0003)
// in the GroupContext and parses it. Returns nil if not present or unparseable.
func (pf *ProposalFilter) extractRequiredCapabilities() *extensions.RequiredCapabilitiesExtension {
	for _, ext := range pf.groupContext.Extensions {
		if ext.Type == uint16(extensions.ExtensionTypeRequiredCapabilities) {
			caps, err := extensions.UnmarshalRequiredCapabilities(ext.Data)
			if err != nil {
				return nil
			}
			return caps
		}
	}
	return nil
}

// validateGCEMemberCompatibility checks that all current tree members support any
// required_capabilities present in the proposed new GroupContext extensions (RFC §12.1.7).
func (pf *ProposalFilter) validateGCEMemberCompatibility(newExts []Extension) error {
	var reqCaps *extensions.RequiredCapabilitiesExtension
	for _, ext := range newExts {
		if ext.Type == uint16(extensions.ExtensionTypeRequiredCapabilities) {
			var err error
			reqCaps, err = extensions.UnmarshalRequiredCapabilities(ext.Data)
			if err != nil {
				// Unparseable required_capabilities — treat as no requirements
				// (forward-compatibility: unknown or malformed extension data is skipped).
				break
			}
			break
		}
	}
	if reqCaps == nil {
		return nil
	}
	for i, node := range pf.tree.Nodes {
		if node.State != treesync.NodeStatePresent || node.LeafData == nil {
			continue
		}
		if err := validateCapabilitiesCompatible(pf.cipherSuite, node.LeafData.Capabilities, reqCaps); err != nil {
			return fmt.Errorf("tree node %d incompatible with new required_capabilities: %w", i, err)
		}
	}
	return nil
}

// toTreeSyncCapabilities converts keypackage capabilities to treesync capabilities.
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
