package group

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/internal/tls"
	"github.com/openmls/go/keypackages"
	"github.com/openmls/go/schedule"
	"github.com/openmls/go/secrettree"
	"github.com/openmls/go/treesync"
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
	Psks         []*ciphersuite.HashReference
}

// Marshal serializa GroupSecrets a formato TLS.
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

	// Psks (simplified - empty for now)
	w.WriteVLBytes([]byte{})

	return w.Bytes()
}

// UnmarshalGroupSecrets deserializa GroupSecrets desde formato TLS.
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

	// Skip Psks
	_, err = r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	return &GroupSecrets{
		JoinerSecret: joinerSecret,
		PathSecret:   pathSecret,
		Psks:         nil,
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

// MarshalTBS serializa los campos a firmar de GroupInfo (excluye Signature).
func (gi *GroupInfo) MarshalTBS() []byte {
	w := tls.NewWriter()
	w.WriteVLBytes(gi.GroupContext.Marshal())
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

// Marshal serializa GroupInfo a formato TLS.
func (gi *GroupInfo) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteVLBytes(gi.GroupContext.Marshal())

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

// UnmarshalGroupInfo deserializa GroupInfo desde formato TLS.
func UnmarshalGroupInfo(data []byte) (*GroupInfo, error) {
	r := tls.NewReader(data)

	gcData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	groupContext, err := UnmarshalGroupContext(gcData)
	if err != nil {
		return nil, err
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
	writer.WriteUint16(w.Version)
	writer.WriteUint16(uint16(w.CipherSuite))

	// Secrets
	secretsBuf := tls.NewWriter()
	for _, secret := range w.Secrets {
		secretsBuf.WriteVLBytes(secret.NewMember)
		// Serialize HpkeCiphertext manualmente
		ctBuf := tls.NewWriter()
		ctBuf.WriteVLBytes(secret.EncryptedGroupSecrets.KEMOutput)
		ctBuf.WriteVLBytes(secret.EncryptedGroupSecrets.Ciphertext)
		secretsBuf.WriteVLBytes(ctBuf.Bytes())
	}
	writer.WriteVLBytes(secretsBuf.Bytes())

	// Encrypted group info
	writer.WriteVLBytes(w.EncryptedGroupInfo)
	return writer.Bytes()
}

// UnmarshalWelcome deserializa un Welcome desde formato TLS.
func UnmarshalWelcome(data []byte) (*Welcome, error) {
	r := tls.NewReader(data)

	version, err := r.ReadUint16()
	if err != nil {
		return nil, err
	}

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

		ctData, err := secretsReader.ReadVLBytes()
		if err != nil {
			return nil, err
		}

		ctReader := tls.NewReader(ctData)
		kemOutput, err := ctReader.ReadVLBytes()
		if err != nil {
			return nil, err
		}
		ciphertext, err := ctReader.ReadVLBytes()
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
		Version:            version,
		CipherSuite:        ciphersuite.CipherSuite(cipherSuite),
		Secrets:            secrets,
		EncryptedGroupInfo: encryptedGroupInfo,
	}, nil
}

// keyPackageRef calcula la referencia de un KeyPackage (hash).
func keyPackageRef(kp *keypackages.KeyPackage) []byte {
	hash := sha256.Sum256(kp.Marshal())
	return hash[:]
}

// CreateWelcome genera un Welcome message para nuevos miembros.
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

	// 1. Calcular welcome_secret desde joiner_secret
	// welcome_secret = DeriveSecret(joiner_secret, "welcome")
	welcomeSecret, err := joinerSecret.DeriveSecret(g.CipherSuite, "welcome")
	if err != nil {
		return nil, fmt.Errorf("deriving welcome secret: %w", err)
	}

	// 2. Construir GroupInfo
	groupInfo := &GroupInfo{
		GroupContext:    g.GroupContext,
		Extensions:      g.GroupContext.Extensions,
		ConfirmationTag: g.ConfirmationTag,
		Signer:          g.OwnLeafIndex,
		RatchetTree:     g.RatchetTree,
	}

	// Serializar ratchet tree como extensión (RFC §12.4.3.3)
	const extTypeRatchetTree = 0x0002
	treeData := g.RatchetTree.MarshalTree()
	groupInfo.Extensions = append(groupInfo.Extensions, Extension{
		Type: extTypeRatchetTree,
		Data: treeData,
	})

	const extTypeExternalPub = uint16(0x0001)
	externalPriv, err := ciphersuite.DeriveKeyPair(g.CipherSuite, g.EpochSecrets.ExternalSecret.AsSlice())
	if err != nil {
		return nil, fmt.Errorf("deriving external key pair: %w", err)
	}
	groupInfo.Extensions = append(groupInfo.Extensions, Extension{
		Type: extTypeExternalPub,
		Data: externalPriv.PublicKey().Bytes(),
	})

	// Firmar GroupInfo sobre los campos TBS (excluye Signature)
	groupInfoTBS := groupInfo.MarshalTBS()
	signature, err := ciphersuite.SignWithLabel(signerPrivKey, "GroupInfoTBS", groupInfoTBS)
	if err != nil {
		return nil, fmt.Errorf("signing group info: %w", err)
	}
	groupInfo.Signature = signature.AsSlice()

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

	encryptedGroupInfo, err := ciphersuite.AESEncrypt(
		welcomeKey.AsSlice(),
		welcomeNonce.AsSlice(),
		groupInfoBytes,
		[]byte{}, // empty AAD
	)
	if err != nil {
		return nil, fmt.Errorf("encrypting group info: %w", err)
	}

	// 4. Para cada nuevo miembro, encriptar GroupSecrets
	var encryptedSecrets []EncryptedGroupSecrets

	for _, kp := range newMemberKeyPackages {
		// Calcular key_package_ref (hash del key package)
		kpRef := keyPackageRef(kp)

		// Construir GroupSecrets
		groupSecrets := &GroupSecrets{
			JoinerSecret: joinerSecret,
			PathSecret:   pathSecret,
			Psks:         nil,
		}

		// Encriptar con HPKE usando init_key del KeyPackage
		secretsBytes := groupSecrets.Marshal()
		encryptedSecretsData, err := ciphersuite.EncryptWithLabel(
			kp.InitKey,
			"GroupSecrets",
			[]byte{},
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

// JoinFromWelcome permite a un nuevo miembro unirse usando un Welcome.
func JoinFromWelcome(
	welcome *Welcome,
	myKeyPackage *keypackages.KeyPackage,
	myPrivateKeys *keypackages.KeyPackagePrivateKeys,
) (*Group, error) {
	// 1. Calcular mi key_package_ref
	myRef := keyPackageRef(myKeyPackage)

	// 2. Buscar mis GroupSecrets encriptados
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

	// 3. Desencriptar GroupSecrets con mi HPKE private key
	privKeyBytes := myPrivateKeys.InitKey.Bytes()
	secretsData, err := ciphersuite.DecryptWithLabel(
		privKeyBytes,
		"GroupSecrets",
		[]byte{},
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

	// 4. Derivar welcome_secret desde joiner_secret
	welcomeSecret, err := groupSecrets.JoinerSecret.DeriveSecret(welcome.CipherSuite, "welcome")
	if err != nil {
		return nil, err
	}

	// 5. Desencriptar GroupInfo
	welcomeKey, err := welcomeSecret.KdfExpandLabel("key", []byte{}, welcome.CipherSuite.AeadKeyLength())
	if err != nil {
		return nil, err
	}
	welcomeNonce, err := welcomeSecret.KdfExpandLabel("nonce", []byte{}, welcome.CipherSuite.AeadNonceLength())
	if err != nil {
		return nil, err
	}

	groupInfoData, err := ciphersuite.AESDecrypt(
		welcomeKey.AsSlice(),
		welcomeNonce.AsSlice(),
		welcome.EncryptedGroupInfo,
		[]byte{},
	)
	if err != nil {
		return nil, fmt.Errorf("decrypting group info: %w", err)
	}

	groupInfo, err := UnmarshalGroupInfo(groupInfoData)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling group info: %w", err)
	}

	// 6. Reconstituir ratchet tree: primero buscar extensión ratchet_tree,
	// sino usar el árbol en memoria (para tests), sino crear árbol vacío
	const extTypeRatchetTree = 0x0002
	ratchetTree := groupInfo.RatchetTree
	for _, ext := range groupInfo.Extensions {
		if ext.Type == extTypeRatchetTree {
			parsed, parseErr := treesync.UnmarshalTree(ext.Data)
			if parseErr == nil {
				ratchetTree = parsed
			}
			break
		}
	}
	if ratchetTree == nil {
		ratchetTree = treesync.NewRatchetTree(1)
	}
	groupInfo.RatchetTree = ratchetTree

	// 7. Verificar firma de GroupInfo (RFC §12.4.3.1)
	signerLeaf := ratchetTree.GetLeaf(treesync.LeafIndex(groupInfo.Signer))
	if signerLeaf == nil || signerLeaf.LeafData == nil || signerLeaf.LeafData.SignatureKey == nil {
		return nil, fmt.Errorf("missing signer leaf in ratchet tree")
	}
	rawKey := treesync.MarshalSignatureKey(signerLeaf.LeafData.SignatureKey)
	pubKey := ciphersuite.NewOpenMlsSignaturePublicKey(rawKey, ciphersuite.ECDSA_SECP256R1_SHA256)
	sig := ciphersuite.NewSignature(groupInfo.Signature)
	if verifyErr := ciphersuite.VerifyWithLabel(pubKey, "GroupInfoTBS", groupInfo.MarshalTBS(), sig); verifyErr != nil {
		return nil, fmt.Errorf("invalid group info signature: %w", verifyErr)
	}

	// 8. Inicializar GroupContext desde GroupInfo
	groupContext := groupInfo.GroupContext

	// 9. Avanzar key schedule desde joiner_secret
	keySchedule := schedule.NewKeySchedule(welcome.CipherSuite, groupSecrets.JoinerSecret)

	if groupSecrets.PathSecret != nil {
		// Derivar commit_secret desde path_secret
		pathSecret := ciphersuite.NewSecret(groupSecrets.PathSecret)
		keySchedule.SetCommitSecret(pathSecret)
	} else {
		// Sin UpdatePath, usar zero secret
		keySchedule.SetCommitSecret(ciphersuite.ZeroSecret(welcome.CipherSuite.HashLength()))
	}

	// Continuar con derivaciones del key schedule
	_, err = keySchedule.ComputeJoinerSecret()
	if err != nil {
		return nil, fmt.Errorf("computing joiner secret: %w", err)
	}

	_, err = keySchedule.ComputePskSecret(nil)
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

	// 9b. Determinar OwnLeafIndex buscando nuestra InitKey en el árbol
	var ownLeafIndex LeafNodeIndex
	for i := treesync.LeafIndex(0); i < treesync.LeafIndex(ratchetTree.NumLeaves); i++ {
		leaf := ratchetTree.GetLeaf(i)
		if leaf != nil && leaf.LeafData != nil {
			if bytes.Equal(leaf.LeafData.EncryptionKey, myKeyPackage.InitKey) {
				ownLeafIndex = LeafNodeIndex(i)
				break
			}
		}
	}

	// 10. Crear Group
	group := &Group{
		GroupID:      groupContext.GroupID,
		Epoch:        groupContext.Epoch,
		CipherSuite:  welcome.CipherSuite,
		GroupContext: groupContext,
		RatchetTree:  ratchetTree,
		OwnLeafIndex: ownLeafIndex,
		EpochSecrets: epochSecrets,
		InterimTranscriptHash: schedule.ComputeInterimTranscriptHash(
			groupContext.ConfirmedTranscriptHash,
			groupInfo.ConfirmationTag,
		),
		Members:     make(map[LeafNodeIndex]*Member),
		state:       StateOperational,
		KeySchedule: keySchedule,
		Proposals:   NewProposalStore(),
	}
	group.ProposalByRef = make(map[string]*Proposal)

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

	group.SecretTree, err = secrettree.NewTree(epochSecrets.EncryptionSecret, ratchetTree.NumLeaves)
	if err != nil {
		return nil, fmt.Errorf("initializing secret tree: %w", err)
	}

	return group, nil
}
