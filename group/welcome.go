package group

import (
	"bytes"
	"context"
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	mlsext "github.com/thomas-vilte/mls-go/extensions"
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
		extBuf.WriteUint16(uint16(ext.Type))
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
		extBuf.WriteUint16(uint16(ext.Type))
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

// CreateWelcome generates a Welcome message for new members per RFC 9420 §12.4.3.1.
//
// The Welcome message allows new members to join an existing group by providing
// them with the necessary cryptographic state to participate in the group.
//
// # Welcome Message Structure (RFC 9420 §11.2.2)
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                    Welcome Message                               │
//	├─────────────────────────────────────────────────────────────────┤
//	│  ProtocolVersion version = mls10                                │
//	│  CipherSuite cipher_suite                                       │
//	│  EncryptedGroupSecrets secrets<V>                               │
//	│    ├─ opaque key_package_ref<V>     - Hash of member's KeyPkg   │
//	│    └─ HPKECiphertext encrypted_group_secrets                    │
//	│  opaque encrypted_group_info<V>     - Encrypted GroupInfo       │
//	└─────────────────────────────────────────────────────────────────┘
//
// # Key Schedule for Welcome (RFC 9420 §8, §12.4.3.1)
//
//	joiner_secret (from UpdatePath)
//	    │
//	    │  HKDF-Extract(joiner_secret, psk_secret=0^Nh)
//	    ▼
//	member_secret
//	    │
//	    │  DeriveSecret("welcome")
//	    ▼
//	welcome_secret
//	    │
//	    ├─► KdfExpandLabel("key")   ──► welcome_key (AES-128-GCM key)
//	    └─► KdfExpandLabel("nonce")  ──► welcome_nonce (12 bytes)
//
// # Encryption Flow
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│              Welcome Encryption Process                         │
//	├─────────────────────────────────────────────────────────────────┤
//	│                                                                 │
//	│  1. Derive welcome_secret from joiner_secret                    │
//	│                                                                 │
//	│  2. Encrypt GroupInfo:                                          │
//	│     encrypted_group_info = AES-GCM-Seal(                        │
//	│       welcome_key, welcome_nonce, GroupInfo, aad=[]            │
//	│     )                                                           │
//	│                                                                 │
//	│  3. For each new member:                                        │
//	│     a. Build GroupSecrets {joiner_secret, path_secret, psks}   │
//	│     b. Encrypt with HPKE using member's InitKey:               │
//	│        HPKE.Encrypt(init_key, "Welcome", encrypted_group_info)  │
//	│     c. Add to secrets vector with key_package_ref              │
//	│                                                                 │
//	└─────────────────────────────────────────────────────────────────┘
//
// Parameters:
//   - newMemberKeyPackages: KeyPackages of members being added
//   - joinerSecret: joiner_secret from the commit's UpdatePath
//   - pathSecret: Optional path_secret for the joining members
//   - signerPrivKey: Private key to sign the GroupInfo
//   - pskIDs: PreSharedKeyID entries for all PSK proposals in this commit
//   - pskSecret: The psk_secret used in the key schedule (0^Nh if no PSKs)
//
// Returns:
//   - Welcome message ready to send to new members
//   - Error if key derivation or encryption fails
//
// RFC 9420 References:
//   - §11.2.2: Welcome Message Structure
//   - §12.4.3.1: Creating a Welcome
//   - §8: Key Schedule for Welcome
type CreateWelcomeOptions struct {
	JoinerSecret  *ciphersuite.Secret
	PathSecret    []byte
	SignerPrivKey *ciphersuite.SignaturePrivateKey
	PskIDs        []PskID
	PskSecret     *ciphersuite.Secret
	StagedCommit  *StagedCommit
}

// CreateWelcomeWithOptions creates a Welcome message using an options struct.
func (g *Group) CreateWelcomeWithOptions(
	newMemberKeyPackages []*keypackages.KeyPackage,
	opts CreateWelcomeOptions,
) (*Welcome, error) {
	return g.createWelcome(
		newMemberKeyPackages,
		opts.JoinerSecret,
		opts.PathSecret,
		opts.SignerPrivKey,
		opts.PskIDs,
		opts.PskSecret,
		opts.StagedCommit,
	)
}

// CreateWelcome creates a Welcome message.
//
// Deprecated: prefer CreateWelcomeWithOptions for new code.
func (g *Group) CreateWelcome(
	newMemberKeyPackages []*keypackages.KeyPackage,
	joinerSecret *ciphersuite.Secret,
	pathSecret []byte, // deprecated: ignored if staged != nil (per-joiner path secrets computed from staged)
	signerPrivKey *ciphersuite.SignaturePrivateKey,
	pskIDs []PskID,
	pskSecret *ciphersuite.Secret,
	staged ...*StagedCommit, // optional: if provided, per-joiner path_secret is derived from it
) (*Welcome, error) {
	var stagedCommit *StagedCommit
	if len(staged) > 0 {
		stagedCommit = staged[0]
	}

	return g.createWelcome(
		newMemberKeyPackages,
		joinerSecret,
		pathSecret,
		signerPrivKey,
		pskIDs,
		pskSecret,
		stagedCommit,
	)
}

func (g *Group) createWelcome(
	newMemberKeyPackages []*keypackages.KeyPackage,
	joinerSecret *ciphersuite.Secret,
	pathSecret []byte,
	signerPrivKey *ciphersuite.SignaturePrivateKey,
	pskIDs []PskID,
	pskSecret *ciphersuite.Secret,
	staged *StagedCommit,
) (*Welcome, error) {
	if g.state != StateOperational {
		return nil, fmt.Errorf("group not operational: %w", ErrInvalidGroupState)
	}

	// Compute welcome_secret per RFC 9420 §8, §12.4.3.1:
	//    member_secret  = HKDF-Extract(joiner_secret, psk_secret)
	//    welcome_secret = DeriveSecret(member_secret, "welcome")
	// We use a copy to preserve joiner_secret (needed for GroupSecrets).
	// The psk_secret must match what was used in the epoch key schedule.
	if pskSecret == nil {
		pskSecret = ciphersuite.ZeroSecret(g.cipherSuite.HashLength())
	}
	joinerCopyForWelcome := ciphersuite.NewSecret(joinerSecret.AsSlice())
	memberSecretForWelcome, err := joinerCopyForWelcome.HKDFExtract(pskSecret)
	if err != nil {
		return nil, fmt.Errorf("computing member_secret for welcome: %w", err)
	}
	welcomeSecret, err := memberSecretForWelcome.DeriveSecret(g.cipherSuite, "welcome")
	if err != nil {
		return nil, fmt.Errorf("deriving welcome_secret: %w", err)
	}

	groupInfo, err := g.buildSignedGroupInfo(signerPrivKey)
	if err != nil {
		return nil, err
	}

	// Encrypt GroupInfo (including signature) with welcome_secret per RFC 9420 §11.2.2
	groupInfoBytes := groupInfo.Marshal()
	welcomeKey, err := welcomeSecret.KdfExpandLabel("key", []byte{}, g.cipherSuite.AeadKeyLength())
	if err != nil {
		return nil, err
	}
	welcomeNonce, err := welcomeSecret.KdfExpandLabel("nonce", []byte{}, g.cipherSuite.AeadNonceLength())
	if err != nil {
		return nil, err
	}

	encryptedGroupInfo, err := ciphersuite.EncryptWithCipherSuite(
		welcomeKey.AsSlice(),
		welcomeNonce.AsSlice(),
		groupInfoBytes,
		[]byte{}, // empty AAD
		g.cipherSuite,
	)
	if err != nil {
		return nil, fmt.Errorf("encrypting group info: %w", err)
	}

	// For each new member, encrypt GroupSecrets
	var encryptedSecrets []EncryptedGroupSecrets

	for _, kp := range newMemberKeyPackages {
		// Compute key_package_ref (hash of the key package)
		kpRef := keyPackageRef(kp, g.cipherSuite)

		// Compute per-joiner path_secret from the staged commit if available.
		// RFC 9420 §12.4.3.1: the path_secret for a joiner is the one at the
		// lowest filtered direct path node that is an ancestor of the joiner's leaf.
		// This correctly handles newly added joiners whose LCA with the committer
		// is below the filtered path (because their copath node was excluded).
		joinerPathSecret := pathSecret
		if staged != nil && staged.pathSecrets != nil {
			sc := staged
			N := len(sc.committerDirectPath) - 1
			F := len(sc.committerFilteredLevels)

			if sc.treeAfterProposals != nil {
				encKey := kp.LeafNode.EncryptionKey
				// Find the lowest filtered level whose subtree contains the joiner.
				for m, level := range sc.committerFilteredLevels {
					nodeIdx := sc.committerDirectPath[level+1]
					if sc.treeAfterProposals.SubtreeContainsLeafByKey(nodeIdx, encKey) {
						ps := sc.pathSecrets[N-F+m+1]
						joinerPathSecret = ps.AsSlice()
						break
					}
				}
			}
		}

		// Build GroupSecrets
		groupSecrets := &GroupSecrets{
			JoinerSecret: joinerSecret,
			PathSecret:   joinerPathSecret,
			Psks:         pskIDs,
		}

		// Encrypt with HPKE using init_key of the KeyPackage
		secretsBytes := groupSecrets.Marshal()
		encryptedSecretsData, err := ciphersuite.EncryptWithLabel(
			kp.InitKey,
			"Welcome",
			encryptedGroupInfo,
			secretsBytes,
			g.cipherSuite,
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
		CipherSuite:        g.cipherSuite,
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
	return JoinFromWelcomeWithContext(context.Background(), welcome, myKeyPackage, myPrivateKeys, externalPsks)
}

// JoinFromWelcomeWithContext allows a new member to join using a Welcome, supporting context cancellation.
func JoinFromWelcomeWithContext(
	ctx context.Context,
	welcome *Welcome,
	myKeyPackage *keypackages.KeyPackage,
	myPrivateKeys *keypackages.KeyPackagePrivateKeys,
	externalPsks map[string][]byte,
) (*Group, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Compute my key_package_ref
	myRef := keyPackageRef(myKeyPackage, welcome.CipherSuite)

	// Find my encrypted GroupSecrets
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

	// Decrypt GroupSecrets with my HPKE private key
	privKeyBytes := myPrivateKeys.InitKey.Bytes()
	secretsData, err := ciphersuite.DecryptWithLabel(
		privKeyBytes,
		"Welcome",
		welcome.EncryptedGroupInfo,
		&myEncryptedSecrets.EncryptedGroupSecrets,
		welcome.CipherSuite,
	)
	if err != nil {
		return nil, &ErrDecryptionFailed{Reason: "group secrets", Err: err}
	}

	groupSecrets, err := UnmarshalGroupSecrets(secretsData)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling group secrets: %w", err)
	}

	var psks []schedule.Psk
	for _, pskRef := range groupSecrets.Psks {
		if externalPsks == nil {
			continue
		}

		var pskBytes []byte
		var ok bool

		switch pskRef.PskType {
		case 2: // Resumption PSK: lookup by compound key (group_id, epoch)
			resumptionKey := ResumptionPskCacheKey(pskRef.PskGroupID, pskRef.PskEpoch)
			pskBytes, ok = externalPsks[resumptionKey]
			if ok {
				psks = append(psks, schedule.Psk{
					PskType:    schedule.PskType(pskRef.PskType),
					PskNonce:   pskRef.Nonce,
					Psk:        pskBytes,
					Usage:      pskRef.Usage,
					PskGroupID: pskRef.PskGroupID,
					PskEpoch:   pskRef.PskEpoch,
				})
			}
		default: // External (1) or Branch (3) PSK: lookup by ID
			pskBytes, ok = externalPsks[string(pskRef.ID)]
			if ok {
				psks = append(psks, schedule.Psk{
					PskType:  schedule.PskType(pskRef.PskType),
					PskID:    pskRef.ID,
					PskNonce: pskRef.Nonce,
					Psk:      pskBytes,
				})
			}
		}
	}

	// Derive welcome_secret (RFC §8, §12.4.3.1):
	// psk_secret     = ComputePskSecret(psks)           (0^Nh if no PSKs)
	// member_secret  = HKDF-Extract(joiner_secret, psk_secret)
	// welcome_secret = DeriveSecret(member_secret, "welcome")
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
		return nil, &ErrDecryptionFailed{Reason: "group info", Err: err}
	}

	groupInfo, err := UnmarshalGroupInfo(groupInfoData)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling group info: %w", err)
	}
	welcome.GroupInfo = groupInfo

	// Reconstruct ratchet tree: first look for ratchet_tree extension,
	// otherwise use the tree in memory (for tests), otherwise create empty tree
	ratchetTree := groupInfo.RatchetTree
	var ratchetTreeParseErr error
	for _, ext := range groupInfo.Extensions {
		if ext.Type == mlsext.ExtensionTypeRatchetTree {
			parsed, parseErr := treesync.UnmarshalTreeFromExtension(ext.Data, groupInfo.GroupContext.CipherSuite)
			if parseErr == nil {
				// RFC §7.4.1: wire format is minimal (no trailing blanks), but the
				// internal tree logic assumes power-of-2 leaf count for parent/copath
				// indexing. Expand unconditionally; TreeHashMinimal stays unchanged.
				parsed = parsed.ExpandToPowerOf2()
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
		ratchetTree = treesync.NewRatchetTree(1, groupInfo.GroupContext.CipherSuite)
	}
	groupInfo.RatchetTree = ratchetTree

	// Verify GroupInfo signature when the signer leaf is available in the tree.
	// Use SigKeyBytes() to support both ECDSA (stored in SignatureKey) and Ed25519 (stored in SignatureKeyRaw).
	// Use the cipher suite's SignatureScheme() to select the correct algorithm.
	signerLeaf := ratchetTree.GetLeaf(treesync.LeafIndex(groupInfo.Signer))
	if signerLeaf != nil && signerLeaf.LeafData != nil {
		rawKey := signerLeaf.LeafData.SigKeyBytes()
		if len(rawKey) > 0 {
			cs := groupInfo.GroupContext.CipherSuite
			pubKey := ciphersuite.NewMLSSignaturePublicKey(rawKey, cs.SignatureScheme())
			sig := ciphersuite.NewSignature(groupInfo.Signature)
			if verifyErr := ciphersuite.VerifyWithLabel(pubKey, "GroupInfoTBS", groupInfo.MarshalTBS(), sig); verifyErr != nil {
				return nil, fmt.Errorf("invalid group info signature: %w", verifyErr)
			}
		}
	}

	// Initialize GroupContext from GroupInfo
	groupContext := groupInfo.GroupContext

	// Advance key schedule from joiner_secret provided by Welcome.
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

	// Determine OwnLeafIndex by looking for our key in the tree.
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
	// Create Group
	group := &Group{
		groupID:         groupContext.GroupID,
		epoch:           groupContext.Epoch,
		cipherSuite:     welcome.CipherSuite,
		groupContext:    groupContext,
		ratchetTree:     ratchetTree,
		ownLeafIndex:    ownLeafIndex,
		epochSecrets:    epochSecrets,
		confirmationTag: groupInfo.ConfirmationTag,
		interimTranscriptHash: schedule.ComputeInterimTranscriptHash(
			welcome.CipherSuite,
			groupContext.ConfirmedTranscriptHash,
			groupInfo.ConfirmationTag,
		),
		members:     make(map[LeafNodeIndex]*Member),
		state:       StateOperational,
		keySchedule: keySchedule,
		proposals:   NewProposalStore(),
		cachedPsks:  make(map[string][]byte),
	}
	group.proposalByRef = make(map[string]*Proposal)
	// Store the leaf's private HPKE key to decrypt path secrets in commits.
	if myPrivateKeys.EncryptionKey != nil {
		group.myLeafEncryptionKey = myPrivateKeys.EncryptionKey.Bytes()
	} else if myPrivateKeys.InitKey != nil {
		group.myLeafEncryptionKey = myPrivateKeys.InitKey.Bytes()
	}
	for id, pskBytes := range externalPsks {
		group.cachedPsks[id] = append([]byte(nil), pskBytes...)
	}

	// Derive PathNodePrivKeys from path_secret (RFC 9420 §12.4.3.1).
	// The path_secret lets the joiner derive private keys for the committer's
	// filtered direct path nodes, from the common ancestor up to the root.
	// This is needed so the joiner can decrypt future commits where one of
	// these intermediate nodes appears in a copath resolution.
	if len(groupSecrets.PathSecret) > 0 {
		committerLeafIdx := treesync.LeafIndex(groupInfo.Signer)
		committerDP := ratchetTree.DirectPath(committerLeafIdx)

		// Walk the committer's directPath (skipping the leaf at index 0).
		// Only PRESENT nodes were filtered levels when the UpdatePath was built;
		// BLANK nodes were non-filtered (their copath had empty resolution with
		// the exclusion set, so no path_secret entry was produced for them).
		// The path_secret advances one step per PRESENT node.
		// We start storing keys from the first PRESENT node that is an ancestor
		// of the joiner's leaf (SubtreeContainsLeaf check).
		ps := ciphersuite.NewSecret(groupSecrets.PathSecret)
		ownLeaf := treesync.LeafIndex(ownLeafIndex)
		started := false
		for _, nodeIdx := range committerDP[1:] { // skip the sender leaf (index 0)
			if int(nodeIdx) >= len(ratchetTree.Nodes) {
				break
			}
			if ratchetTree.Nodes[nodeIdx].State != treesync.NodeStatePresent {
				continue // blank node = non-filtered, skip (no path_secret for it)
			}
			if !started {
				if !ratchetTree.SubtreeContainsLeaf(nodeIdx, ownLeaf) {
					continue // joiner is not in this node's subtree
				}
				started = true
				if group.pathNodePrivKeys == nil {
					group.pathNodePrivKeys = make(map[treesync.NodeIndex][]byte)
				}
			}
			nodeSecret, nsErr := ps.DeriveSecret(welcome.CipherSuite, "node")
			if nsErr == nil {
				privKey, pkErr := ciphersuite.DeriveKeyPair(welcome.CipherSuite, nodeSecret.AsSlice())
				if pkErr == nil {
					group.pathNodePrivKeys[nodeIdx] = privKey.Bytes()
				}
			}
			ps, _ = ps.DeriveSecret(welcome.CipherSuite, "path")
		}
	}

	// Cache the resumption secret for this initial epoch so that future
	// resumption PSK proposals referencing this epoch can resolve it.
	if epochSecrets.ResumptionSecret != nil {
		rKey := ResumptionPskCacheKey(groupContext.GroupID.AsSlice(), groupContext.Epoch.AsUint64())
		group.cachedPsks[rKey] = append([]byte(nil), epochSecrets.ResumptionSecret.AsSlice()...)
	}

	for i := treesync.LeafIndex(0); i < treesync.LeafIndex(ratchetTree.NumLeaves); i++ {
		leaf := ratchetTree.GetLeaf(i)
		if leaf != nil && leaf.LeafData != nil && leaf.State == treesync.NodeStatePresent {
			leafIdx := LeafNodeIndex(i)
			group.members[leafIdx] = &Member{
				LeafIndex:  leafIdx,
				Credential: leaf.LeafData.Credential,
				Active:     true,
			}
		}
	}

	group.secretTree, err = secrettree.NewTree(epochSecrets.EncryptionSecret, ratchetTree.NumLeaves, welcome.CipherSuite)
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
	if signerLeaf == nil || signerLeaf.LeafData == nil {
		return fmt.Errorf("missing signer leaf in ratchet tree")
	}
	rawKey := signerLeaf.LeafData.SigKeyBytes()
	if len(rawKey) == 0 {
		return fmt.Errorf("missing signature key for signer leaf")
	}
	cs := groupInfo.GroupContext.CipherSuite
	pubKey := ciphersuite.NewMLSSignaturePublicKey(rawKey, cs.SignatureScheme())
	sig := ciphersuite.NewSignature(groupInfo.Signature)
	if err := ciphersuite.VerifyWithLabel(pubKey, "GroupInfoTBS", groupInfo.MarshalTBS(), sig); err != nil {
		return fmt.Errorf("invalid group info signature: %w", err)
	}
	return nil
}
