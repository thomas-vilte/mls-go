//nolint:unused
package group

import (
	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/internal/tls"
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
	RatchetTree     *RatchetTree
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
		// Write encrypted secrets (simplified)
	}
	writer.WriteVLBytes(secretsBuf.Bytes())
	// Encrypted group info
	writer.WriteVLBytes(w.EncryptedGroupInfo)
	return writer.Bytes()
}

// decryptGroupSecrets decrypts group secrets using the private key.
func decryptGroupSecrets(encrypted *EncryptedGroupSecrets, privateKey []byte) (*GroupSecrets, error) {
	// TODO: Implement proper HPKE decryption
	return &GroupSecrets{
		JoinerSecret: ciphersuite.NewSecret([]byte("mock")),
	}, nil
}

// decryptGroupInfo decrypts and verifies the GroupInfo.
func decryptGroupInfo(encrypted []byte, joinerSecret *ciphersuite.Secret) (*GroupInfo, error) {
	// TODO: Implement proper decryption and verification
	return &GroupInfo{}, nil
}
