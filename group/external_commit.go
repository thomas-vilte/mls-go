package group

import (
	"crypto/ecdh"
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/schedule"
	"github.com/thomas-vilte/mls-go/secrettree"
	"github.com/thomas-vilte/mls-go/treesync"
)

// ExternalCommit allows a client to join a group without a Welcome message (RFC 9420 §12.4.3.2).
func ExternalCommit(
	groupInfo *GroupInfo,
	cs ciphersuite.CipherSuite,
	sigPrivKey *ciphersuite.SignaturePrivateKey,
	sigPubKey *ciphersuite.SignaturePublicKey,
) (*Group, *StagedCommit, error) {
	if groupInfo == nil || groupInfo.GroupContext == nil {
		return nil, nil, fmt.Errorf("invalid group info")
	}
	if sigPrivKey == nil || sigPubKey == nil {
		return nil, nil, fmt.Errorf("missing signature keys")
	}

	// Obtain external_pub from GroupInfo extensions.
	const extTypeExternalPub = uint16(0x0001)
	const extTypeRatchetTree = uint16(0x0002)

	var externalPubBytes []byte
	for _, ext := range groupInfo.Extensions {
		if ext.Type == extTypeExternalPub {
			externalPubBytes = ext.Data
			break
		}
	}
	if len(externalPubBytes) == 0 {
		return nil, nil, fmt.Errorf("external_pub not found in GroupInfo extensions")
	}

	// Rebuild ratchet tree from extension if needed.
	tree := groupInfo.RatchetTree
	for _, ext := range groupInfo.Extensions {
		if ext.Type == extTypeRatchetTree {
			parsed, err := treesync.UnmarshalTree(ext.Data)
			if err != nil {
				return nil, nil, fmt.Errorf("unmarshaling ratchet tree: %w", err)
			}
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

	// Clone tree and append our leaf.
	treeDiff := tree.Clone()
	sigPubKeyECDSA, err := sigPubKey.ToECDSA()
	if err != nil {
		return nil, nil, fmt.Errorf("converting signature public key: %w", err)
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
	ownLeafData := &treesync.LeafNodeData{
		EncryptionKey:  leafPrivKey.PublicKey().Bytes(),
		SignatureKey:   sigPubKeyECDSA,
		Capabilities:   &treesync.LeafNodeCapabilities{},
		Lifetime:       &treesync.LeafNodeLifetime{},
		LeafNodeSource: 3, // commit
	}

	tbsInitial := ownLeafData.MarshalTBS()
	sig, err := ciphersuite.SignWithLabel(sigPrivKey, "LeafNodeTBS", tbsInitial)
	if err != nil {
		return nil, nil, fmt.Errorf("signing leaf node: %w", err)
	}
	ownLeafData.Signature = sig.AsSlice()

	ownLeafIdx, _ := treeDiff.AddLeaf(*ownLeafData)
	ownLeafIndex := LeafNodeIndex(ownLeafIdx)

	// Build UpdatePath (RFC §12.4.1, filtered direct path).
	directPath := treeDiff.DirectPath(ownLeafIdx)
	if len(directPath) == 0 {
		return nil, nil, fmt.Errorf("invalid direct path for external commit")
	}
	N := len(directPath) - 1

	// Derive path secrets for all N non-leaf levels.
	pathSecrets := make([]*ciphersuite.Secret, N+1)
	pathSecrets[0] = leafSecret
	for i := 1; i <= N; i++ {
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
		ps := pathSecrets[N-F+m]
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
		treeDiff.Nodes[nodeIdx].EncryptionKey, err = ecdh.P256().NewPublicKey(pubKeys[m])
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
			ph = treesync.ComputeParentHash(parentKey, parent.ParentHash, siblingHash)
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
		ps := pathSecrets[N-F+m]
		res := treeDiff.Resolution(copath[level])
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
	commit := &Commit{
		Proposals: []ProposalOrRef{{Proposal: externalInitProposal}},
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
	var interimHashForNewMember []byte
	if len(groupInfo.ConfirmationTag) > 0 {
		interimHashForNewMember = schedule.ComputeInterimTranscriptHash(
			cs,
			groupContext.ConfirmedTranscriptHash,
			groupInfo.ConfirmationTag,
		)
	}
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

	// Build local group state for the new member.
	group := &Group{
		GroupID:               groupContext.GroupID,
		Epoch:                 NewGroupEpoch(groupContext.Epoch.AsUint64() + 1),
		CipherSuite:           cs,
		GroupContext:          newGC,
		RatchetTree:           treeDiff,
		OwnLeafIndex:          ownLeafIndex,
		EpochSecrets:          epochSecrets,
		Proposals:             NewProposalStore(),
		ProposalByRef:         make(map[string]*Proposal),
		KeySchedule:           schedule.NewKeySchedule(cs, epochSecrets.InitSecret),
		InterimTranscriptHash: newInterimHash,
		Members:               make(map[LeafNodeIndex]*Member),
		state:                 StateOperational,
		CachedPsks:            make(map[string][]byte),
		MyLeafEncryptionKey:   leafPrivKey.Bytes(),
	}

	group.SecretTree, err = secrettree.NewTree(epochSecrets.EncryptionSecret, treeDiff.NumLeaves, cs)
	if err != nil {
		return nil, nil, fmt.Errorf("initializing secret tree: %w", err)
	}

	for i := treesync.LeafIndex(0); i < treesync.LeafIndex(treeDiff.NumLeaves); i++ {
		leaf := treeDiff.GetLeaf(i)
		if leaf != nil && leaf.LeafData != nil && leaf.State == treesync.NodeStatePresent {
			leafIdx := LeafNodeIndex(i)
			group.Members[leafIdx] = &Member{
				LeafIndex:  leafIdx,
				Credential: leaf.LeafData.Credential,
				Active:     true,
			}
		}
	}

	stagedCommit := &StagedCommit{
		Commit:                  commit,
		Proposals:               []*Proposal{externalInitProposal},
		AuthenticatedContent:    ac,
		RootPathSecret:          commitSecret,
		PrecomputedEpochSecrets: epochSecrets,
		PrecomputedGroupContext: newGC,
		PrecomputedInterimHash:  newInterimHash,
	}

	return group, stagedCommit, nil
}
