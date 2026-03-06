//nolint:unused
package group

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/internal/tls"
	keypackages "github.com/openmls/go/key_packages"
	"github.com/openmls/go/schedule"
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
	signerPrivKey []byte,
) (*Welcome, error) {
	if g.state != StateOperational {
		return nil, fmt.Errorf("group not operational: %w", ErrInvalidGroupState)
	}

	// 1. Calcular welcome_secret desde joiner_secret
	// welcome_secret = ExpandWithLabel(joiner_secret, "welcome", "", KDF.Nh)
	welcomeSecret := deriveWelcomeSecret(joinerSecret, g.CipherSuite)

	// 2. Construir GroupInfo
	groupInfo := &GroupInfo{
		GroupContext:    g.GroupContext,
		Extensions:      g.GroupContext.Extensions,
		ConfirmationTag: g.ConfirmationTag,
		Signer:          g.OwnLeafIndex,
	}

	// Firmar GroupInfo
	groupInfoBytes := groupInfo.Marshal()
	signature, err := signWithPrivateKey(groupInfoBytes, signerPrivKey)
	if err != nil {
		return nil, fmt.Errorf("signing group info: %w", err)
	}
	groupInfo.Signature = signature

	// 3. Encriptar GroupInfo con welcome_secret
	// Usar AES-GCM con la welcome_secret como key
	encryptedGroupInfo, err := encryptWithAEAD(groupInfoBytes, welcomeSecret, []byte("welcome"))
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
			PathSecret:   pathSecret, // nil si no hay UpdatePath
			Psks:         nil,        // o PSKs si aplica
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
	// Convertir la clave privada ECDH a bytes
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
	welcomeSecret := deriveWelcomeSecret(groupSecrets.JoinerSecret, welcome.CipherSuite)

	// 5. Desencriptar GroupInfo
	groupInfoData, err := decryptWithAEAD(welcome.EncryptedGroupInfo, welcomeSecret, []byte("welcome"))
	if err != nil {
		return nil, fmt.Errorf("decrypting group info: %w", err)
	}

	groupInfo, err := UnmarshalGroupInfo(groupInfoData)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling group info: %w", err)
	}

	// 6. Verificar firma de GroupInfo (simplificado)
	// En implementación real, verificar contra la public key del signer

	// 7. Reconstituir ratchet tree desde GroupInfo.RatchetTree o construir vacío
	ratchetTree := groupInfo.RatchetTree
	if ratchetTree == nil {
		// Crear árbol vacío
		ratchetTree = treesync.NewRatchetTree(1)
	}

	// 8. Inicializar GroupContext desde GroupInfo
	groupContext := groupInfo.GroupContext

	// 9. Avanzar key schedule desde joiner_secret
	// Inicializar key schedule con init_secret = joiner_secret
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

	// 10. Crear Group
	group := &Group{
		GroupID:               groupContext.GroupID,
		Epoch:                 groupContext.Epoch,
		CipherSuite:           welcome.CipherSuite,
		GroupContext:          groupContext,
		RatchetTree:           ratchetTree,
		EpochSecrets:          epochSecrets,
		InterimTranscriptHash: []byte{}, // Inicial
		Members:               make(map[LeafNodeIndex]*Member),
		state:                 StateOperational,
		KeySchedule:           keySchedule,
		Proposals:             NewProposalStore(),
	}

	// Agregarnos como miembro (nuestro índice debe determinarse del commit)
	// Por ahora, usamos el índice del signer como referencia
	// En implementación real, esto viene del UpdatePath

	return group, nil
}

// Funciones auxiliares

// deriveWelcomeSecret deriva el welcome_secret desde joiner_secret.
func deriveWelcomeSecret(joinerSecret *ciphersuite.Secret, cs ciphersuite.CipherSuite) []byte {
	// welcome_secret = ExpandWithLabel(joiner_secret, "welcome", "", KDF.Nh)
	// Simplificado: usar HKDF directamente
	secret, err := joinerSecret.DeriveSecret(cs, "welcome")
	if err != nil {
		return nil
	}
	return secret.AsSlice()
}

// encryptWithAEAD encripta datos usando AES-GCM.
func encryptWithAEAD(plaintext, key, aad []byte) ([]byte, error) {
	// Simplificado: en implementación real usar AEAD del ciphersuite
	// Por ahora, retornar plaintext "encriptado" (mock)
	return plaintext, nil
}

// decryptWithAEAD desencripta datos usando AES-GCM.
func decryptWithAEAD(ciphertext, key, aad []byte) ([]byte, error) {
	// Simplificado: en implementación real usar AEAD del ciphersuite
	// Por ahora, retornar ciphertext "desencriptado" (mock)
	return ciphertext, nil
}

// signWithPrivateKey firma datos con una clave privada.
func signWithPrivateKey(data, privKey []byte) ([]byte, error) {
	// Simplificado: en implementación real usar ECDSA
	// Por ahora, retornar hash como "firma" (mock)
	hash := sha256.Sum256(data)
	return hash[:], nil
}
