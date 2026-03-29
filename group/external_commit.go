package group

import (
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	mlsext "github.com/thomas-vilte/mls-go/extensions"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/internal/tls"
	"github.com/thomas-vilte/mls-go/schedule"
	"github.com/thomas-vilte/mls-go/secrettree"
	"github.com/thomas-vilte/mls-go/treesync"
)

// ExternalCommit allows a client to join a group without a Welcome message (RFC 9420 §12.4.3.2).
// ExternalCommit allows a new member to join an existing group without a Welcome message.
//
// RFC 9420 §12.4.3.2
// The new member retrieves a signed GroupInfo, constructs an ExternalInit proposal
// and an UpdatePath, and creates an external commit that adds them to the group.
// Returns the resulting group state and the PublicMessage to broadcast to other members.
//
// If removePriorLeaf >= 0, a Remove proposal for that leaf index is included before
// the ExternalInit proposal (RFC §12.4.3.2: external commit may contain Remove proposals
// to remove prior appearance of this member).
func ExternalCommit(
	groupInfo *GroupInfo,
	cs ciphersuite.CipherSuite,
	sigPrivKey *ciphersuite.SignaturePrivateKey,
	sigPubKey *ciphersuite.SignaturePublicKey,
	removePriorLeaf int, // -1 means no removal; >= 0 is the leaf index to remove
	credential *credentials.Credential, // identity credential for the new leaf node
) (*Group, *StagedCommit, error) {
	if groupInfo == nil || groupInfo.GroupContext == nil {
		return nil, nil, fmt.Errorf("invalid group info")
	}
	if sigPrivKey == nil || sigPubKey == nil {
		return nil, nil, fmt.Errorf("missing signature keys")
	}

	// Obtain external_pub from GroupInfo extensions (RFC 9420 §11.2.4, type=0x0004).
	// HPKEPublicKey is VLBytes in TLS encoding; unwrap VL prefix to get raw key bytes.
	var externalPubBytes []byte
	for _, ext := range groupInfo.Extensions {
		if ext.Type == mlsext.ExtensionTypeExternalPub {
			r := tls.NewReader(ext.Data)
			raw, err := r.ReadVLBytes()
			if err == nil && len(raw) > 0 {
				externalPubBytes = raw // VL-wrapped (RFC-format)
			} else {
				externalPubBytes = ext.Data // fallback: raw bytes (legacy self-interop)
			}
			break
		}
	}
	if len(externalPubBytes) == 0 {
		return nil, nil, fmt.Errorf("external_pub not found in GroupInfo extensions")
	}

	// Rebuild ratchet tree from extension if needed.
	// RFC §7.4.1: wire format is minimal (no trailing blanks). Internally we
	// use power-of-2 leaf count for parent/copath indexing. Expand if the
	// parsed tree_hash doesn't match GroupInfo's tree_hash.
	tree := groupInfo.RatchetTree
	for _, ext := range groupInfo.Extensions {
		if ext.Type == mlsext.ExtensionTypeRatchetTree {
			parsed, err := treesync.UnmarshalTreeFromExtension(ext.Data, groupInfo.GroupContext.CipherSuite)
			if err != nil {
				return nil, nil, fmt.Errorf("unmarshaling ratchet tree: %w", err)
			}
			parsed = parsed.ExpandToPowerOf2()
			tree = parsed
			break
		}
	}
	if tree == nil {
		return nil, nil, fmt.Errorf("ratchet tree not present in GroupInfo")
	}
	if err := verifyGroupInfoSignature(groupInfo, tree); err != nil {
		return nil, nil, err
	}

	// HPKE Encap to external_pub.
	kemOutput, sharedSecret, err := ciphersuite.EncapToBytes(externalPubBytes, cs)
	if err != nil {
		return nil, nil, fmt.Errorf("HPKE encap to external_pub: %w", err)
	}

	// Build ExternalInit proposal.
	externalInitProposal := &Proposal{
		Type: ProposalTypeExternalInit,
		ExternalInit: &ExternalInitProposal{
			KemOutput: kemOutput,
		},
	}

	// Clone tree. If removing a prior leaf, blank it first (RFC §12.4.3.2).
	treeDiff := tree.Clone()
	var removeProposal *Proposal
	if removePriorLeaf >= 0 {
		priorLeaf := treesync.LeafIndex(removePriorLeaf)
		removeProposal = &Proposal{
			Type:   ProposalTypeRemove,
			Remove: &RemoveProposal{Removed: LeafNodeIndex(priorLeaf)},
		}
		for _, nodeIdx := range treeDiff.DirectPath(priorLeaf) {
			treeDiff.BlankNode(nodeIdx)
		}
		treeDiff.TruncateTrailingBlanks()
	}

	leafSecret, err := ciphersuite.NewSecretRandomCS(cs)
	if err != nil {
		return nil, nil, fmt.Errorf("generating leaf secret: %w", err)
	}

	// Derive leaf HPKE key pair from node_secret = DeriveSecret(leafSecret, "node") (RFC §12.4.2).
	leafNodeSecret, err := leafSecret.DeriveSecret(cs, "node")
	if err != nil {
		return nil, nil, fmt.Errorf("deriving leaf node secret: %w", err)
	}
	leafPrivKey, err := ciphersuite.DeriveKeyPair(cs, leafNodeSecret.AsSlice())
	if err != nil {
		return nil, nil, fmt.Errorf("deriving leaf key pair: %w", err)
	}

	// Build leaf node using raw signature key bytes (works for both Ed25519 and P-256).
	sigPubKeyRaw := sigPubKey.AsSlice()
	ownLeafData := &treesync.LeafNodeData{
		EncryptionKey:   leafPrivKey.PublicKey().Bytes(),
		SignatureKeyRaw: sigPubKeyRaw,
		Credential:      credential,
		Capabilities: &treesync.LeafNodeCapabilities{
			ProtocolVersions: []uint16{0x0001}, // MLS 1.0
			CipherSuites:     []uint16{uint16(cs)},
			Credentials:      []uint16{0x0001}, // BasicCredential
		},
		Lifetime:       nil, // source=commit: Lifetime not included in TBS (RFC §7.2)
		LeafNodeSource: 3,   // commit
	}
	// For ECDSA (P-256), also populate the typed key field.
	if cs.SignatureScheme() == ciphersuite.ECDSA_SECP256R1_SHA256 {
		if ecKey, err2 := sigPubKey.ToECDSA(); err2 == nil {
			ownLeafData.SignatureKey = ecKey
		}
	}

	tbsInitial := ownLeafData.MarshalTBS()
	sig, err := ciphersuite.SignWithLabel(sigPrivKey, "LeafNodeTBS", tbsInitial)
	if err != nil {
		return nil, nil, fmt.Errorf("signing leaf node: %w", err)
	}
	ownLeafData.Signature = sig.AsSlice()

	ownLeafIdx, _ := treeDiff.AddLeaf(*ownLeafData)
	treeDiff = treeDiff.ExpandToPowerOf2()
	ownLeafIndex := LeafNodeIndex(ownLeafIdx)
	excluded := map[treesync.LeafIndex]bool{ownLeafIdx: true}

	// Build UpdatePath (RFC §12.4.1, filtered direct path).
	directPath := treeDiff.DirectPath(ownLeafIdx)
	if len(directPath) == 0 {
		return nil, nil, fmt.Errorf("invalid direct path for external commit")
	}
	N := len(directPath) - 1

	// Derive path secrets for all N non-leaf levels, plus one extra commit_secret.
	pathSecrets := make([]*ciphersuite.Secret, N+2)
	pathSecrets[0] = leafSecret
	for i := 1; i <= N+1; i++ {
		pathSecrets[i], err = pathSecrets[i-1].DeriveSecret(cs, "path")
		if err != nil {
			return nil, nil, fmt.Errorf("deriving path secret: %w", err)
		}
	}

	// Compute filtered levels BEFORE modifying the tree.
	_, copath, levels := filteredDirectPathLevels(treeDiff, ownLeafIdx)
	F := len(levels)

	// RFC 9420 §12.4.2 step 6: Blank ALL intermediate nodes on the committer's
	// direct path before applying the UpdatePath encryption keys.
	for i := 1; i < len(directPath); i++ {
		treeDiff.BlankNode(directPath[i])
	}

	// Apply encryption keys to filtered parent nodes.
	pubKeys := make([][]byte, F)
	for m, level := range levels {
		ps := pathSecrets[N-F+m+1]
		nodeSecret, err := ps.DeriveSecret(cs, "node")
		if err != nil {
			return nil, nil, fmt.Errorf("deriving node secret: %w", err)
		}
		privKey, err := ciphersuite.DeriveKeyPair(cs, nodeSecret.AsSlice())
		if err != nil {
			return nil, nil, fmt.Errorf("deriving path key pair: %w", err)
		}
		pubKeys[m] = privKey.PublicKey().Bytes()

		nodeIdx := directPath[level+1]
		treeDiff.Nodes[nodeIdx].EncryptionKey, err = cs.Curve().NewPublicKey(pubKeys[m])
		if err != nil {
			return nil, nil, fmt.Errorf("parsing update path public key: %w", err)
		}
		treeDiff.Nodes[nodeIdx].State = treesync.NodeStatePresent
		treeDiff.Nodes[nodeIdx].UnmergedLeaves = nil
	}

	// Compute parent hashes.
	rootIdx := treeDiff.Root()
	treeDiff.Nodes[rootIdx].ParentHash = []byte{}
	for i := len(directPath) - 2; i >= 0; i-- {
		nodeIdx := directPath[i]
		parentIdx, err := treeDiff.Parent(nodeIdx)
		if err != nil {
			return nil, nil, fmt.Errorf("getting parent for node %d: %w", nodeIdx, err)
		}
		parent := &treeDiff.Nodes[parentIdx]
		siblingIdx := treeDiff.GetSibling(nodeIdx)
		siblingHash := treeDiff.HashNode(siblingIdx)
		var ph []byte
		if parent.State == treesync.NodeStatePresent {
			var parentKey []byte
			if parent.EncryptionKey != nil {
				parentKey = parent.EncryptionKey.Bytes()
			}
			ph = treesync.ComputeParentHash(parentKey, parent.ParentHash, siblingHash, cs.HashFunction())
		} else {
			ph = parent.ParentHash
		}
		treeDiff.Nodes[nodeIdx].ParentHash = ph
	}

	ownLeafData.ParentHash = treeDiff.Nodes[directPath[0]].ParentHash
	// source=commit; TBS incluye group_id + leaf_index per RFC §7.2.
	tbs := ownLeafData.MarshalTBSWithContext(groupInfo.GroupContext.GroupID.AsSlice(), uint32(ownLeafIdx))
	sig2, err := ciphersuite.SignWithLabel(sigPrivKey, "LeafNodeTBS", tbs)
	if err != nil {
		return nil, nil, fmt.Errorf("re-signing leaf node with parent hash: %w", err)
	}
	ownLeafData.Signature = sig2.AsSlice()
	if err := treeDiff.SetLeaf(ownLeafIdx, *ownLeafData); err != nil {
		return nil, nil, fmt.Errorf("setting own leaf in tree: %w", err)
	}

	// Compute provisional GroupContext (current epoch, tree_hash_after).
	// RFC 9420 §12.4.1: provisional GroupContext uses the NEXT epoch (current + 1).
	provGCBytes := (&GroupContext{
		Version:                 groupInfo.GroupContext.Version,
		CipherSuite:             cs,
		GroupID:                 groupInfo.GroupContext.GroupID,
		Epoch:                   NewGroupEpoch(groupInfo.GroupContext.Epoch.AsUint64() + 1),
		TreeHash:                treeDiff.TreeHash(),
		ConfirmedTranscriptHash: groupInfo.GroupContext.ConfirmedTranscriptHash,
		Extensions:              groupInfo.GroupContext.Extensions,
	}).Marshal()

	// Encrypt path secrets for filtered levels using provisional GC as context.
	nodes := make([]UpdatePathNode, F)
	for m, level := range levels {
		ps := pathSecrets[N-F+m+1]
		res := treeDiff.ResolutionWithExclusions(copath[level], excluded)
		encryptedSecrets := make([]ciphersuite.HpkeCiphertext, len(res))
		for j, resIdx := range res {
			resNode := &treeDiff.Nodes[resIdx]
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
			ct, err := ciphersuite.EncryptWithLabel(encKeyBytes, "UpdatePathNode", provGCBytes, ps.AsSlice(), cs)
			if err != nil {
				return nil, nil, fmt.Errorf("encrypting path secret: %w", err)
			}
			encryptedSecrets[j] = *ct
		}
		nodes[m] = UpdatePathNode{
			EncryptionKey:        pubKeys[m],
			EncryptedPathSecrets: encryptedSecrets,
		}
	}

	updatePath := &UpdatePath{
		LeafNode: ownLeafData,
		Nodes:    nodes,
	}

	// Build and sign commit.
	groupContext := groupInfo.GroupContext
	proposals := []ProposalOrRef{{Proposal: externalInitProposal}}
	if removeProposal != nil {
		// Remove proposals come before ExternalInit per RFC §12.4.3.2
		proposals = []ProposalOrRef{{Proposal: removeProposal}, {Proposal: externalInitProposal}}
	}
	commit := &Commit{
		Proposals: proposals,
		Path:      updatePath,
	}

	content := framing.FramedContent{
		GroupID: groupContext.GroupID.AsSlice(),
		Epoch:   groupContext.Epoch.AsUint64(),
		Sender:  framing.Sender{Type: framing.SenderTypeNewMemberCommit},
		Body:    framing.CommitBody{Data: commit.Marshal()},
	}
	ac := &framing.AuthenticatedContent{
		WireFormat:   framing.WireFormatPublicMessage,
		Content:      content,
		GroupContext: groupContext.Marshal(),
	}

	acSig, err := ciphersuite.SignWithLabel(sigPrivKey, "FramedContentTBS", ac.MarshalTBS())
	if err != nil {
		return nil, nil, fmt.Errorf("signing external commit: %w", err)
	}
	ac.Auth.Signature = acSig

	// Compute confirmed transcript hash and new GroupContext before key schedule.
	cthi, err := framing.NewConfirmedTranscriptHashInput(ac)
	if err != nil {
		return nil, nil, fmt.Errorf("creating transcript hash input: %w", err)
	}
	// RFC 9420 §6.2: always compute the interim transcript hash from the
	// GroupInfo, even when ConfirmationTag is empty (initial epoch). For
	// epoch 0, this gives Hash(CTH=[] || VL(tag=[])) = SHA256([0x00]).
	interimHashForNewMember := schedule.ComputeInterimTranscriptHash(
		cs,
		groupContext.ConfirmedTranscriptHash,
		groupInfo.ConfirmationTag,
	)
	confirmedHash, err := cthi.Compute(cs, interimHashForNewMember)
	if err != nil {
		return nil, nil, fmt.Errorf("computing confirmed transcript hash: %w", err)
	}

	newTreeHash := treeDiff.TreeHash()
	newGC := &GroupContext{
		Version:                 groupContext.Version,
		CipherSuite:             cs,
		GroupID:                 groupContext.GroupID,
		Epoch:                   NewGroupEpoch(groupContext.Epoch.AsUint64() + 1),
		TreeHash:                newTreeHash,
		ConfirmedTranscriptHash: confirmedHash,
		Extensions:              groupContext.Extensions,
	}
	newGCBytes := newGC.Marshal()

	// Advance key schedule with init_secret = sharedSecret.
	initSecret := ciphersuite.NewSecret(sharedSecret)
	newKS := schedule.NewKeySchedule(cs, initSecret)
	commitSecret := pathSecrets[len(pathSecrets)-1]
	newKS.SetCommitSecret(commitSecret)
	if _, err = newKS.ComputeJoinerSecret(newGCBytes); err != nil {
		return nil, nil, fmt.Errorf("computing joiner secret: %w", err)
	}
	if _, err = newKS.ComputePskSecret(nil); err != nil {
		return nil, nil, fmt.Errorf("computing psk secret: %w", err)
	}

	if _, err = newKS.ComputeEpochSecret(newGCBytes); err != nil {
		return nil, nil, fmt.Errorf("computing epoch secret: %w", err)
	}
	epochSecrets, err := newKS.DeriveEpochSecrets()
	if err != nil {
		return nil, nil, fmt.Errorf("deriving epoch secrets: %w", err)
	}

	confirmationTag := schedule.ComputeConfirmationTag(
		cs,
		epochSecrets.ConfirmationKey.AsSlice(),
		confirmedHash,
	)
	ac.Auth.ConfirmationTag = confirmationTag
	newInterimHash := schedule.ComputeInterimTranscriptHash(cs, confirmedHash, confirmationTag)

	// Populate PathNodePrivKeys for all filtered direct path nodes.
	// The external committer created the UpdatePath and has all path secrets,
	// so they can derive private keys for every node on their filtered direct path.
	pathNodePrivKeys := make(map[treesync.NodeIndex][]byte)
	for m, level := range levels {
		ps := pathSecrets[N-F+m+1]
		nodeSecret, nsErr := ps.DeriveSecret(cs, "node")
		if nsErr == nil {
			nodeIdx := directPath[level+1]
			privKey, pkErr := ciphersuite.DeriveKeyPair(cs, nodeSecret.AsSlice())
			if pkErr == nil {
				pathNodePrivKeys[nodeIdx] = privKey.Bytes()
			}
		}
	}

	// Build local group state for the new member.
	group := &Group{
		groupID:               groupContext.GroupID,
		epoch:                 NewGroupEpoch(groupContext.Epoch.AsUint64() + 1),
		cipherSuite:           cs,
		groupContext:          newGC,
		ratchetTree:           treeDiff,
		ownLeafIndex:          ownLeafIndex,
		epochSecrets:          epochSecrets,
		proposals:             NewProposalStore(),
		proposalByRef:         make(map[string]*Proposal),
		keySchedule:           schedule.NewKeySchedule(cs, epochSecrets.InitSecret),
		interimTranscriptHash: newInterimHash,
		members:               make(map[LeafNodeIndex]*Member),
		state:                 StateOperational,
		cachedPsks:            make(map[string][]byte),
		myLeafEncryptionKey:   leafPrivKey.Bytes(),
		pathNodePrivKeys:      pathNodePrivKeys,
	}

	group.secretTree, err = secrettree.NewTree(epochSecrets.EncryptionSecret, treeDiff.NumLeaves, cs)
	if err != nil {
		return nil, nil, fmt.Errorf("initializing secret tree: %w", err)
	}

	for i := treesync.LeafIndex(0); i < treesync.LeafIndex(treeDiff.NumLeaves); i++ {
		leaf := treeDiff.GetLeaf(i)
		if leaf != nil && leaf.LeafData != nil && leaf.State == treesync.NodeStatePresent {
			leafIdx := LeafNodeIndex(i)
			group.members[leafIdx] = &Member{
				LeafIndex:  leafIdx,
				Credential: leaf.LeafData.Credential,
				Active:     true,
			}
		}
	}

	stagedCommit := &StagedCommit{
		commit:                  commit,
		proposals:               []*Proposal{externalInitProposal},
		authenticatedContent:    ac,
		rootPathSecret:          commitSecret,
		precomputedEpochSecrets: epochSecrets,
		precomputedGroupContext: newGC,
		precomputedInterimHash:  newInterimHash,
	}

	return group, stagedCommit, nil
}
