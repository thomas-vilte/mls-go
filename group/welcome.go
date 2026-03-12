package group

import (
	"bytes"
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/internal/tls"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/schedule"
	"github.com/thomas-vilte/mls-go/secrettree"
	"github.com/thomas-vilte/mls-go/treesync"
)

// Welcome represents an MLS Welcome message (RFC 9420 §12.4.3.1).
//
//	struct {
//	    ProtocolVersion version = mls10;
//	    CipherSuite cipher_suite;
//	    EncryptedGroupSecrets secrets<V>;
//	    opaque encrypted_group_info<V>;
//	} Welcome;
type Welcome struct {
	Version            uint16
	CipherSuite        ciphersuite.CipherSuite
	Secrets            []EncryptedGroupSecrets
	EncryptedGroupInfo []byte
	GroupInfo          *GroupInfo
}

// EncryptedGroupSecrets represents encrypted group secrets for a new member.
//
//	struct {
//	    opaque key_package_ref<V>;
//	    HPKECiphertext encrypted_group_secrets;
//	} EncryptedGroupSecrets;
type EncryptedGroupSecrets struct {
	NewMember             []byte
	EncryptedGroupSecrets ciphersuite.HpkeCiphertext
}

// GroupSecrets represents the secrets needed to join a group.
//
//	struct {
//	    opaque joiner_secret<V>;
//	    optional<PathSecret> path_secret;
//	    PreSharedKeyID psks<V>;
//	} GroupSecrets;
type GroupSecrets struct {
	JoinerSecret *ciphersuite.Secret
	PathSecret   []byte
	Psks         []PskID
}

// Marshal serializes GroupSecrets to TLS format.
func (gs *GroupSecrets) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteVLBytes(gs.JoinerSecret.AsSlice())

	// PathSecret (optional)
	if gs.PathSecret != nil {
		w.WriteUint8(1)
		w.WriteVLBytes(gs.PathSecret)
	} else {
		w.WriteUint8(0)
	}

	pskBuf := tls.NewWriter()
	for _, psk := range gs.Psks {
		pskBuf.WriteUint8(psk.PskType)
		if psk.PskType == 2 { // resumption
			pskBuf.WriteUint8(psk.Usage)
			pskBuf.WriteVLBytes(psk.PskGroupID)
			pskBuf.WriteUint64(psk.PskEpoch)
		} else { // external (1) or branch (3)
			pskBuf.WriteVLBytes(psk.ID)
		}
		pskBuf.WriteVLBytes(psk.Nonce)
	}
	w.WriteVLBytes(pskBuf.Bytes())

	return w.Bytes()
}

// UnmarshalGroupSecrets deserializes GroupSecrets from TLS format.
func UnmarshalGroupSecrets(data []byte) (*GroupSecrets, error) {
	r := tls.NewReader(data)

	joinerSecretData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	joinerSecret := ciphersuite.NewSecret(joinerSecretData)

	// PathSecret (optional)
	pathSecretPresent, err := r.ReadUint8()
	if err != nil {
		return nil, err
	}

	var pathSecret []byte
	if pathSecretPresent == 1 {
		pathSecret, err = r.ReadVLBytes()
		if err != nil {
			return nil, err
		}
	}

	pskData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	pskReader := tls.NewReader(pskData)
	var psks []PskID
	for pskReader.Remaining() > 0 {
		pskType, readErr := pskReader.ReadUint8()
		if readErr != nil {
			return nil, readErr
		}
		pskID := PskID{PskType: pskType}
		if pskType == 2 { // resumption
			usage, readErr := pskReader.ReadUint8()
			if readErr != nil {
				return nil, readErr
			}
			pskGroupID, readErr := pskReader.ReadVLBytes()
			if readErr != nil {
				return nil, readErr
			}
			pskEpoch, readErr := pskReader.ReadUint64()
			if readErr != nil {
				return nil, readErr
			}
			pskID.Usage = usage
			pskID.PskGroupID = pskGroupID
			pskID.PskEpoch = pskEpoch
		} else { // external (1) or branch (3)
			id, readErr := pskReader.ReadVLBytes()
			if readErr != nil {
				return nil, readErr
			}
			pskID.ID = id
		}
		pskNonce, readErr := pskReader.ReadVLBytes()
		if readErr != nil {
			return nil, readErr
		}
		pskID.Nonce = pskNonce
		psks = append(psks, pskID)
	}

	return &GroupSecrets{
		JoinerSecret: joinerSecret,
		PathSecret:   pathSecret,
		Psks:         psks,
	}, nil
}

// GroupInfo represents the group information sent in a Welcome.
//
//	struct {
//	    GroupContext group_context;
//	    Extension extensions<V>;
//	    ConfirmationTag confirmation_tag;
//	    uint32 signer;
//	    opaque signature<V>;
//	} GroupInfo;
type GroupInfo struct {
	GroupContext    *GroupContext
	Extensions      []Extension
	ConfirmationTag []byte
	Signer          LeafNodeIndex
	Signature       []byte
	RatchetTree     *treesync.RatchetTree
}

// MarshalTBS serializes the fields to sign of GroupInfo (excludes Signature).
func (gi *GroupInfo) MarshalTBS() []byte {
	w := tls.NewWriter()
	w.WriteRaw(gi.GroupContext.Marshal())
	extBuf := tls.NewWriter()
	for _, ext := range gi.Extensions {
		extBuf.WriteUint16(ext.Type)
		extBuf.WriteVLBytes(ext.Data)
	}
	w.WriteVLBytes(extBuf.Bytes())
	w.WriteVLBytes(gi.ConfirmationTag)
	w.WriteUint32(uint32(gi.Signer))
	return w.Bytes()
}

// Marshal serializes GroupInfo to TLS format.
func (gi *GroupInfo) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteRaw(gi.GroupContext.Marshal())

	// Extensions
	extBuf := tls.NewWriter()
	for _, ext := range gi.Extensions {
		extBuf.WriteUint16(ext.Type)
		extBuf.WriteVLBytes(ext.Data)
	}
	w.WriteVLBytes(extBuf.Bytes())

	w.WriteVLBytes(gi.ConfirmationTag)
	w.WriteUint32(uint32(gi.Signer))
	w.WriteVLBytes(gi.Signature)

	return w.Bytes()
}

// UnmarshalGroupInfo deserializes GroupInfo from TLS format.
func UnmarshalGroupInfo(data []byte) (*GroupInfo, error) {
	r := tls.NewReader(data)

	version, err := r.ReadUint16()
	if err != nil {
		return nil, err
	}
	cipherSuite, err := r.ReadUint16()
	if err != nil {
		return nil, err
	}
	groupID, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	epoch, err := r.ReadUint64()
	if err != nil {
		return nil, err
	}
	treeHash, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	confirmedTranscriptHash, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	gcExtensionsData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	gcExtensions, err := parseExtensions(gcExtensionsData)
	if err != nil {
		return nil, fmt.Errorf("parsing group context extensions: %w", err)
	}

	groupContext := &GroupContext{
		Version:                 keypackages.ProtocolVersion(version),
		CipherSuite:             ciphersuite.CipherSuite(cipherSuite),
		GroupID:                 NewGroupID(groupID),
		Epoch:                   NewGroupEpoch(epoch),
		TreeHash:                treeHash,
		ConfirmedTranscriptHash: confirmedTranscriptHash,
		Extensions:              gcExtensions,
	}

	extensionsData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	extensions, err := parseExtensions(extensionsData)
	if err != nil {
		return nil, err
	}

	confirmationTag, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	signer, err := r.ReadUint32()
	if err != nil {
		return nil, err
	}

	signature, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	return &GroupInfo{
		GroupContext:    groupContext,
		Extensions:      extensions,
		ConfirmationTag: confirmationTag,
		Signer:          LeafNodeIndex(signer),
		Signature:       signature,
	}, nil
}

// Marshal serializes the Welcome to TLS format.
func (w *Welcome) Marshal() []byte {
	writer := tls.NewWriter()
	writer.WriteUint16(uint16(w.CipherSuite))

	// Secrets
	secretsBuf := tls.NewWriter()
	for _, secret := range w.Secrets {
		secretsBuf.WriteVLBytes(secret.NewMember)
		secretsBuf.WriteVLBytes(secret.EncryptedGroupSecrets.KEMOutput)
		secretsBuf.WriteVLBytes(secret.EncryptedGroupSecrets.Ciphertext)
	}
	writer.WriteVLBytes(secretsBuf.Bytes())

	// Encrypted group info
	writer.WriteVLBytes(w.EncryptedGroupInfo)
	return writer.Bytes()
}

// UnmarshalWelcome deserializes a Welcome from TLS format.
func UnmarshalWelcome(data []byte) (*Welcome, error) {
	r := tls.NewReader(data)

	cipherSuite, err := r.ReadUint16()
	if err != nil {
		return nil, err
	}

	secretsData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	var secrets []EncryptedGroupSecrets
	secretsReader := tls.NewReader(secretsData)
	for secretsReader.Remaining() > 0 {
		newMember, err := secretsReader.ReadVLBytes()
		if err != nil {
			break
		}

		kemOutput, err := secretsReader.ReadVLBytes()
		if err != nil {
			return nil, err
		}
		ciphertext, err := secretsReader.ReadVLBytes()
		if err != nil {
			return nil, err
		}

		secrets = append(secrets, EncryptedGroupSecrets{
			NewMember: newMember,
			EncryptedGroupSecrets: ciphersuite.HpkeCiphertext{
				KEMOutput:  kemOutput,
				Ciphertext: ciphertext,
			},
		})
	}

	encryptedGroupInfo, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	return &Welcome{
		Version:            uint16(keypackages.MLS10),
		CipherSuite:        ciphersuite.CipherSuite(cipherSuite),
		Secrets:            secrets,
		EncryptedGroupInfo: encryptedGroupInfo,
	}, nil
}

// keyPackageRef calculates the reference of a KeyPackage (hash).
func keyPackageRef(kp *keypackages.KeyPackage, cs ciphersuite.CipherSuite) []byte {
	if kp == nil {
		return nil
	}
	if len(kp.Raw) > 0 {
		return ciphersuite.MakeKeyPackageRef(kp.Raw, cs.HashFunction()).AsSlice()
	}
	return ciphersuite.MakeKeyPackageRef(kp.Marshal(), cs.HashFunction()).AsSlice()
}

// CreateWelcome generates a Welcome message for new members.
// RFC 9420 §12.4.3.1
func (g *Group) CreateWelcome(
	newMemberKeyPackages []*keypackages.KeyPackage,
	joinerSecret *ciphersuite.Secret,
	pathSecret []byte,
	signerPrivKey *ciphersuite.SignaturePrivateKey,
) (*Welcome, error) {
	if g.state != StateOperational {
		return nil, fmt.Errorf("group not operational: %w", ErrInvalidGroupState)
	}

	// 1. Compute welcome_secret (RFC §8, §12.4.3.1):
	//    member_secret  = HKDF-Extract(joiner_secret, psk_secret=0^Nh)
	//    welcome_secret = DeriveSecret(member_secret, "welcome")
	// We use a copy to not destroy joiner_secret (needed for GroupSecrets).
	joinerCopyForWelcome := ciphersuite.NewSecret(joinerSecret.AsSlice())
	memberSecretForWelcome, err := joinerCopyForWelcome.HKDFExtract(
		ciphersuite.ZeroSecret(g.CipherSuite.HashLength()),
	)
	if err != nil {
		return nil, fmt.Errorf("computing member_secret for welcome: %w", err)
	}
	welcomeSecret, err := memberSecretForWelcome.DeriveSecret(g.CipherSuite, "welcome")
	if err != nil {
		return nil, fmt.Errorf("deriving welcome_secret: %w", err)
	}

	groupInfo, err := g.buildSignedGroupInfo(signerPrivKey)
	if err != nil {
		return nil, err
	}

	// 3. Encriptar GroupInfo completo (con firma) con welcome_secret (RFC §11.2.2)
	groupInfoBytes := groupInfo.Marshal()
	welcomeKey, err := welcomeSecret.KdfExpandLabel("key", []byte{}, g.CipherSuite.AeadKeyLength())
	if err != nil {
		return nil, err
	}
	welcomeNonce, err := welcomeSecret.KdfExpandLabel("nonce", []byte{}, g.CipherSuite.AeadNonceLength())
	if err != nil {
		return nil, err
	}

	encryptedGroupInfo, err := ciphersuite.EncryptWithCipherSuite(
		welcomeKey.AsSlice(),
		welcomeNonce.AsSlice(),
		groupInfoBytes,
		[]byte{}, // empty AAD
		g.CipherSuite,
	)
	if err != nil {
		return nil, fmt.Errorf("encrypting group info: %w", err)
	}

	// 4. For each new member, encrypt GroupSecrets
	var encryptedSecrets []EncryptedGroupSecrets

	for _, kp := range newMemberKeyPackages {
		// Compute key_package_ref (hash of the key package)
		kpRef := keyPackageRef(kp, g.CipherSuite)

		// Build GroupSecrets
		groupSecrets := &GroupSecrets{
			JoinerSecret: joinerSecret,
			PathSecret:   pathSecret,
			Psks:         nil,
		}

		// Encrypt with HPKE using init_key of the KeyPackage
		secretsBytes := groupSecrets.Marshal()
		encryptedSecretsData, err := ciphersuite.EncryptWithLabel(
			kp.InitKey,
			"Welcome",
			encryptedGroupInfo,
			secretsBytes,
			g.CipherSuite,
		)
		if err != nil {
			return nil, fmt.Errorf("encrypting group secrets: %w", err)
		}

		encryptedSecrets = append(encryptedSecrets, EncryptedGroupSecrets{
			NewMember:             kpRef,
			EncryptedGroupSecrets: *encryptedSecretsData,
		})
	}

	return &Welcome{
		Version:            1, // MLS 1.0
		CipherSuite:        g.CipherSuite,
		Secrets:            encryptedSecrets,
		EncryptedGroupInfo: encryptedGroupInfo,
		GroupInfo:          groupInfo,
	}, nil
}

// JoinFromWelcome allows a new member to join using a Welcome.
func JoinFromWelcome(
	welcome *Welcome,
	myKeyPackage *keypackages.KeyPackage,
	myPrivateKeys *keypackages.KeyPackagePrivateKeys,
	externalPsks map[string][]byte,
) (*Group, error) {
	// 1. Compute my key_package_ref
	myRef := keyPackageRef(myKeyPackage, welcome.CipherSuite)

	// 2. Find my encrypted GroupSecrets
	var myEncryptedSecrets *EncryptedGroupSecrets
	for i := range welcome.Secrets {
		if bytes.Equal(welcome.Secrets[i].NewMember, myRef) {
			myEncryptedSecrets = &welcome.Secrets[i]
			break
		}
	}

	if myEncryptedSecrets == nil {
		return nil, fmt.Errorf("no encrypted secrets found for this key package")
	}

	// 3. Decrypt GroupSecrets with my HPKE private key
	privKeyBytes := myPrivateKeys.InitKey.Bytes()
	secretsData, err := ciphersuite.DecryptWithLabel(
		privKeyBytes,
		"Welcome",
		welcome.EncryptedGroupInfo,
		&myEncryptedSecrets.EncryptedGroupSecrets,
		welcome.CipherSuite,
	)
	if err != nil {
		return nil, fmt.Errorf("decrypting group secrets: %w", err)
	}

	groupSecrets, err := UnmarshalGroupSecrets(secretsData)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling group secrets: %w", err)
	}

	var psks []schedule.Psk
	for _, pskRef := range groupSecrets.Psks {
		if externalPsks != nil {
			if pskBytes, ok := externalPsks[string(pskRef.ID)]; ok {
				psks = append(psks, schedule.Psk{
					PskType:  schedule.PskType(pskRef.PskType),
					PskID:    pskRef.ID,
					PskNonce: pskRef.Nonce,
					Psk:      pskBytes,
				})
			}
		}
	}

	// 4. Derive welcome_secret (RFC §8, §12.4.3.1):
	//    psk_secret     = ComputePskSecret(psks)           (0^Nh if no PSKs)
	//    member_secret  = HKDF-Extract(joiner_secret, psk_secret)
	//    welcome_secret = DeriveSecret(member_secret, "welcome")
	//
	// We use a COPY of joiner_secret so that HKDFExtract (which zeroes its inputs)
	// does not destroy the original, which the key schedule needs later.
	rawPskSecret := ciphersuite.ZeroSecret(welcome.CipherSuite.HashLength())
	if len(psks) > 0 {
		pskInput, pskErr := schedule.ComputePskInput(psks, welcome.CipherSuite)
		if pskErr != nil {
			return nil, fmt.Errorf("computing psk input: %w", pskErr)
		}
		rawPskSecret = ciphersuite.NewSecret(pskInput)
	}

	joinerCopy := ciphersuite.NewSecret(groupSecrets.JoinerSecret.AsSlice())
	memberSecret, err := joinerCopy.HKDFExtract(rawPskSecret)
	if err != nil {
		return nil, fmt.Errorf("computing member_secret for welcome: %w", err)
	}
	welcomeSecret, err := memberSecret.DeriveSecret(welcome.CipherSuite, "welcome")
	if err != nil {
		return nil, fmt.Errorf("deriving welcome_secret: %w", err)
	}

	welcomeKey, err := welcomeSecret.KdfExpandLabel("key", []byte{}, welcome.CipherSuite.AeadKeyLength())
	if err != nil {
		return nil, fmt.Errorf("deriving welcome_key: %w", err)
	}
	welcomeNonce, err := welcomeSecret.KdfExpandLabel("nonce", []byte{}, welcome.CipherSuite.AeadNonceLength())
	if err != nil {
		return nil, fmt.Errorf("deriving welcome_nonce: %w", err)
	}
	groupInfoData, err := ciphersuite.DecryptWithCipherSuite(
		welcomeKey.AsSlice(),
		welcomeNonce.AsSlice(),
		welcome.EncryptedGroupInfo,
		[]byte{},
		welcome.CipherSuite,
	)
	if err != nil {
		return nil, fmt.Errorf("decrypting group info: %w", err)
	}

	groupInfo, err := UnmarshalGroupInfo(groupInfoData)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling group info: %w", err)
	}
	welcome.GroupInfo = groupInfo

	// 6. Reconstruct ratchet tree: first look for ratchet_tree extension,
	// otherwise use the tree in memory (for tests), otherwise create empty tree
	const extTypeRatchetTree = 0x0002
	ratchetTree := groupInfo.RatchetTree
	var ratchetTreeParseErr error
	for _, ext := range groupInfo.Extensions {
		if ext.Type == extTypeRatchetTree {
			parsed, parseErr := treesync.UnmarshalTreeFromExtension(ext.Data)
			if parseErr == nil {
				ratchetTree = parsed
				break
			}
			ratchetTreeParseErr = parseErr
		}
	}
	if ratchetTree == nil {
		if ratchetTreeParseErr != nil {
			return nil, fmt.Errorf("parsing ratchet_tree extension: %w", ratchetTreeParseErr)
		}
		ratchetTree = treesync.NewRatchetTree(1)
	}
	groupInfo.RatchetTree = ratchetTree

	// 7. Verify GroupInfo signature when the signer leaf is available in the tree.
	signerLeaf := ratchetTree.GetLeaf(treesync.LeafIndex(groupInfo.Signer))
	if signerLeaf != nil && signerLeaf.LeafData != nil && signerLeaf.LeafData.SignatureKey != nil {
		rawKey := treesync.MarshalSignatureKey(signerLeaf.LeafData.SignatureKey)
		pubKey := ciphersuite.NewOpenMlsSignaturePublicKey(rawKey, ciphersuite.ECDSA_SECP256R1_SHA256)
		sig := ciphersuite.NewSignature(groupInfo.Signature)
		if verifyErr := ciphersuite.VerifyWithLabel(pubKey, "GroupInfoTBS", groupInfo.MarshalTBS(), sig); verifyErr != nil {
			return nil, fmt.Errorf("invalid group info signature: %w", verifyErr)
		}
	}

	// 8. Initialize GroupContext from GroupInfo
	groupContext := groupInfo.GroupContext

	// 9. Advance key schedule from joiner_secret provided by Welcome.
	keySchedule := schedule.NewKeySchedule(
		welcome.CipherSuite,
		ciphersuite.ZeroSecret(welcome.CipherSuite.HashLength()),
	)
	keySchedule.SetJoinerSecret(groupSecrets.JoinerSecret)

	_, err = keySchedule.ComputePskSecret(psks)
	if err != nil {
		return nil, fmt.Errorf("computing psk secret: %w", err)
	}

	groupContextBytes := groupContext.Marshal()
	_, err = keySchedule.ComputeEpochSecret(groupContextBytes)
	if err != nil {
		return nil, fmt.Errorf("computing epoch secret: %w", err)
	}

	epochSecrets, err := keySchedule.DeriveEpochSecrets()
	if err != nil {
		return nil, fmt.Errorf("deriving epoch secrets: %w", err)
	}

	// 9b. Determine OwnLeafIndex by looking for our key in the tree.
	// It searches by LeafNode.EncryptionKey (TreeKEM key of the leaf), which may differ
	// from the InitKey of the KeyPackage (HPKE key for the Welcome).
	var ownLeafIndex LeafNodeIndex
	leafEncKey := myKeyPackage.LeafNode.EncryptionKey
	if len(leafEncKey) == 0 {
		leafEncKey = myKeyPackage.InitKey
	}
	for i := treesync.LeafIndex(0); i < treesync.LeafIndex(ratchetTree.NumLeaves); i++ {
		leaf := ratchetTree.GetLeaf(i)
		if leaf != nil && leaf.LeafData != nil {
			if bytes.Equal(leaf.LeafData.EncryptionKey, leafEncKey) {
				ownLeafIndex = LeafNodeIndex(i)
				break
			}
		}
	}
	// 10. Create Group
	group := &Group{
		GroupID:      groupContext.GroupID,
		Epoch:        groupContext.Epoch,
		CipherSuite:  welcome.CipherSuite,
		GroupContext: groupContext,
		RatchetTree:  ratchetTree,
		OwnLeafIndex: ownLeafIndex,
		EpochSecrets: epochSecrets,
		InterimTranscriptHash: schedule.ComputeInterimTranscriptHash(
			welcome.CipherSuite,
			groupContext.ConfirmedTranscriptHash,
			groupInfo.ConfirmationTag,
		),
		Members:     make(map[LeafNodeIndex]*Member),
		state:       StateOperational,
		KeySchedule: keySchedule,
		Proposals:   NewProposalStore(),
		CachedPsks:  make(map[string][]byte),
	}
	group.ProposalByRef = make(map[string]*Proposal)
	// Store the leaf's private HPKE key to decrypt path secrets in commits.
	if myPrivateKeys.EncryptionKey != nil {
		group.MyLeafEncryptionKey = myPrivateKeys.EncryptionKey.Bytes()
	} else if myPrivateKeys.InitKey != nil {
		group.MyLeafEncryptionKey = myPrivateKeys.InitKey.Bytes()
	}
	for id, pskBytes := range externalPsks {
		group.CachedPsks[id] = append([]byte(nil), pskBytes...)
	}

	// Cache the resumption secret for this initial epoch so that future
	// resumption PSK proposals referencing this epoch can resolve it.
	if epochSecrets.ResumptionSecret != nil {
		rKey := resumptionPskCacheKey(groupContext.GroupID.AsSlice(), groupContext.Epoch.AsUint64())
		group.CachedPsks[rKey] = append([]byte(nil), epochSecrets.ResumptionSecret.AsSlice()...)
	}

	for i := treesync.LeafIndex(0); i < treesync.LeafIndex(ratchetTree.NumLeaves); i++ {
		leaf := ratchetTree.GetLeaf(i)
		if leaf != nil && leaf.LeafData != nil && leaf.State == treesync.NodeStatePresent {
			leafIdx := LeafNodeIndex(i)
			group.Members[leafIdx] = &Member{
				LeafIndex:  leafIdx,
				Credential: leaf.LeafData.Credential,
				Active:     true,
			}
		}
	}

	group.SecretTree, err = secrettree.NewTree(epochSecrets.EncryptionSecret, ratchetTree.NumLeaves, welcome.CipherSuite)
	if err != nil {
		return nil, fmt.Errorf("initializing secret tree: %w", err)
	}

	return group, nil
}

func verifyGroupInfoSignature(groupInfo *GroupInfo, tree *treesync.RatchetTree) error {
	if groupInfo == nil {
		return fmt.Errorf("group info is nil")
	}
	if tree == nil {
		return fmt.Errorf("ratchet tree is nil")
	}
	signerLeaf := tree.GetLeaf(treesync.LeafIndex(groupInfo.Signer))
	if signerLeaf == nil || signerLeaf.LeafData == nil || signerLeaf.LeafData.SignatureKey == nil {
		return fmt.Errorf("missing signer leaf in ratchet tree")
	}
	rawKey := treesync.MarshalSignatureKey(signerLeaf.LeafData.SignatureKey)
	pubKey := ciphersuite.NewOpenMlsSignaturePublicKey(rawKey, ciphersuite.ECDSA_SECP256R1_SHA256)
	sig := ciphersuite.NewSignature(groupInfo.Signature)
	if err := ciphersuite.VerifyWithLabel(pubKey, "GroupInfoTBS", groupInfo.MarshalTBS(), sig); err != nil {
		return fmt.Errorf("invalid group info signature: %w", err)
	}
	return nil
}
