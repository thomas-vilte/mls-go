package group

import (
	"crypto/ecdh"
	"fmt"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/framing"
	"github.com/openmls/go/schedule"
	"github.com/openmls/go/secrettree"
	"github.com/openmls/go/treesync"
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

	// 1. Obtain external_pub from GroupInfo extensions.
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

	// 2. HPKE Encap to external_pub.
	kemOutput, sharedSecret, err := ciphersuite.EncapToBytes(externalPubBytes, cs)
	if err != nil {
		return nil, nil, fmt.Errorf("HPKE encap to external_pub: %w", err)
	}

	// 3. Build ExternalInit proposal.
	externalInitProposal := &Proposal{
		Type: ProposalTypeExternalInit,
		ExternalInit: &ExternalInitProposal{
			KemOutput: kemOutput,
		},
	}

	// 4. Clone tree and append our leaf.
	treeDiff := tree.Clone()
	sigPubKeyECDSA, err := sigPubKey.ToECDSA()
	if err != nil {
		return nil, nil, fmt.Errorf("converting signature public key: %w", err)
	}

	leafSecret, err := ciphersuite.NewSecretRandomCS(cs)
	if err != nil {
		return nil, nil, fmt.Errorf("generating leaf secret: %w", err)
	}

	ownLeafData := &treesync.LeafNodeData{
		EncryptionKey:  leafSecret.AsSlice(),
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

	// 5. Build UpdatePath.
	directPath := treeDiff.DirectPath(treesync.LeafIndex(ownLeafIdx))
	if len(directPath) == 0 {
		return nil, nil, fmt.Errorf("invalid direct path for external commit")
	}

	pathSecrets := make([]*ciphersuite.Secret, len(directPath))
	pathSecrets[0] = leafSecret
	for i := 1; i < len(directPath); i++ {
		pathSecrets[i], err = pathSecrets[i-1].DeriveSecret(cs, "path")
		if err != nil {
			return nil, nil, fmt.Errorf("deriving path secret: %w", err)
		}
	}

	nodes := make([]UpdatePathNode, len(directPath)-1)
	copath := treeDiff.Copath(treesync.LeafIndex(ownLeafIdx))

	for i := 1; i < len(directPath); i++ {
		pathSecret := pathSecrets[i]
		nodeSecret, err := pathSecret.DeriveSecret(cs, "node")
		if err != nil {
			return nil, nil, fmt.Errorf("deriving node secret: %w", err)
		}

		privKey, err := ciphersuite.DeriveKeyPair(cs, nodeSecret.AsSlice())
		if err != nil {
			return nil, nil, fmt.Errorf("deriving path key pair: %w", err)
		}
		pubKey := privKey.PublicKey().Bytes()

		res := treeDiff.Resolution(copath[i-1])
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

			ct, err := ciphersuite.EncryptWithLabel(
				encKeyBytes,
				"UpdatePathNode",
				[]byte{},
				pathSecret.AsSlice(),
				cs,
			)
			if err != nil {
				return nil, nil, fmt.Errorf("encrypting path secret: %w", err)
			}
			encryptedSecrets[j] = *ct
		}

		nodes[i-1] = UpdatePathNode{
			EncryptionKey:        pubKey,
			EncryptedPathSecrets: encryptedSecrets,
		}

		node := &treeDiff.Nodes[directPath[i]]
		node.EncryptionKey, err = ecdh.P256().NewPublicKey(pubKey)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing update path public key: %w", err)
		}
		node.State = treesync.NodeStatePresent
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

		var parentKey []byte
		if parent.EncryptionKey != nil {
			parentKey = parent.EncryptionKey.Bytes()
		}

		ph := treesync.ComputeParentHash(parentKey, parent.ParentHash, siblingHash)
		treeDiff.Nodes[nodeIdx].ParentHash = ph
	}

	ownLeafData.ParentHash = treeDiff.Nodes[directPath[0]].ParentHash
	tbs := ownLeafData.MarshalTBS()
	sig2, err := ciphersuite.SignWithLabel(sigPrivKey, "LeafNodeTBS", tbs)
	if err != nil {
		return nil, nil, fmt.Errorf("re-signing leaf node with parent hash: %w", err)
	}
	ownLeafData.Signature = sig2.AsSlice()
	if err := treeDiff.SetLeaf(treesync.LeafIndex(ownLeafIdx), *ownLeafData); err != nil {
		return nil, nil, fmt.Errorf("setting own leaf in tree: %w", err)
	}

	updatePath := &UpdatePath{
		LeafNode: ownLeafData,
		Nodes:    nodes,
	}

	// 6. Build and sign commit.
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

	// 7. Compute confirmed transcript hash and new GroupContext before key schedule.
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

	// 8. Build local group state for the new member.
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
	}

	group.SecretTree, err = secrettree.NewTree(epochSecrets.EncryptionSecret, treeDiff.NumLeaves)
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
