package messages

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	mlsext "github.com/thomas-vilte/mls-go/extensions"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/internal/tls"
)

// Welcome represents an MLS Welcome message as defined in RFC 9420 §11.2.2.
//
// Welcome messages are sent to new members to allow them to join a group.
// They contain encrypted group secrets for each new member, encrypted using
// HPKE (RFC 9180) with the recipient's KeyPackage public key.
//
// RFC 9420 §11.2.2:
//
//	struct {
//	    CipherSuite cipher_suite;
//	    EncryptedGroupSecrets secrets<V>;
//	    opaque encrypted_group_info<V>;
//	} Welcome;
type Welcome struct {
	CipherSuite        uint16
	Secrets            []EncryptedGroupSecrets
	EncryptedGroupInfo []byte
}

// EncryptedGroupSecrets contains encrypted secrets for a new group member
// as defined in RFC 9420 §11.2.2.
//
// Each new member receives their own encrypted secrets in the Welcome message.
// The key_package_hash identifies which KeyPackage this secret is for.
//
//	struct {
//	    opaque key_package_hash<V>;
//	    opaque kem_output<V>;
//	    opaque ciphertext<V>;
//	} EncryptedGroupSecrets;
type EncryptedGroupSecrets struct {
	KeyPackageHash []byte // Hash reference of the member's KeyPackage (RFC 9420 §10.5)
	EncryptedKey   []byte // HPKE encapsulated key (kem_output from RFC 9180)
	Ciphertext     []byte // Encrypted group secrets (AES-GCM ciphertext)
}

// NewWelcome creates a new Welcome message with the specified parameters.
//
// The cipherSuite specifies which cryptographic algorithms to use for the group.
// Each secret in secrets is encrypted for a different new group member.
func NewWelcome(cipherSuite uint16, secrets []EncryptedGroupSecrets, encryptedGroupInfo []byte) *Welcome {
	return &Welcome{
		CipherSuite:        cipherSuite,
		Secrets:            secrets,
		EncryptedGroupInfo: encryptedGroupInfo,
	}
}

// Marshal serializes the Welcome message to TLS presentation language format
// as specified in RFC 9420 §2.1 (Presentation Language).
//
// The encoded format is:
//   - cipher_suite: uint16 (2 bytes)
//   - secrets: variable-length vector of EncryptedGroupSecrets
//   - encrypted_group_info: variable-length vector of bytes
func (w *Welcome) Marshal() ([]byte, error) {
	buf := tls.NewWriter()

	// cipher_suite (uint16)
	buf.WriteUint16(w.CipherSuite)

	// secrets<V>
	secretsBuf := tls.NewWriter()
	for _, secret := range w.Secrets {
		secretsBuf.WriteVLBytes(secret.KeyPackageHash)
		secretsBuf.WriteVLBytes(secret.EncryptedKey)
		secretsBuf.WriteVLBytes(secret.Ciphertext)
	}
	buf.WriteVLBytes(secretsBuf.Bytes())

	// encrypted_group_info<V>
	buf.WriteVLBytes(w.EncryptedGroupInfo)

	return buf.Bytes(), nil
}

// UnmarshalWelcome parses a Welcome message from TLS presentation language format.
//
// This function decodes the binary data according to RFC 9420 §11.2.2:
//   - cipher_suite: uint16
//   - secrets: vector of EncryptedGroupSecrets
//   - encrypted_group_info: opaque bytes
//
// Returns an error if the data is malformed or incomplete.
func UnmarshalWelcome(data []byte) (*Welcome, error) {
	buf := tls.NewReader(data)

	cipherSuite, err := buf.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("reading cipher_suite: %w", err)
	}

	secretsBytes, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading secrets: %w", err)
	}

	secrets, err := unmarshalEncryptedGroupSecrets(secretsBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing secrets: %w", err)
	}

	encryptedGroupInfo, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading encrypted_group_info: %w", err)
	}

	return &Welcome{
		CipherSuite:        cipherSuite,
		Secrets:            secrets,
		EncryptedGroupInfo: encryptedGroupInfo,
	}, nil
}

// unmarshalEncryptedGroupSecrets parses a vector of EncryptedGroupSecrets
// from TLS presentation language format.
//
// Each entry contains:
//   - key_package_hash: identifier for the recipient's KeyPackage
//   - kem_output: HPKE encapsulated key (RFC 9180)
//   - ciphertext: AES-GCM encrypted group secrets
func unmarshalEncryptedGroupSecrets(data []byte) ([]EncryptedGroupSecrets, error) {
	buf := tls.NewReader(data)
	var secrets []EncryptedGroupSecrets

	for buf.Remaining() > 0 {
		keyPackageHash, err := buf.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading key_package_hash: %w", err)
		}

		encryptedKey, err := buf.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading kem_output: %w", err)
		}

		ciphertext, err := buf.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading ciphertext: %w", err)
		}

		secrets = append(secrets, EncryptedGroupSecrets{
			KeyPackageHash: keyPackageHash,
			EncryptedKey:   encryptedKey,
			Ciphertext:     ciphertext,
		})
	}

	return secrets, nil
}

// FindSecret finds the encrypted secrets for a specific KeyPackage hash.
//
// This method searches the Welcome message for secrets intended for a
// particular KeyPackage, identified by its hash (RFC 9420 §10.5).
// Returns nil if no matching secrets are found.
func (w *Welcome) FindSecret(keyPackageHash []byte) *EncryptedGroupSecrets {
	for i := range w.Secrets {
		if bytes.Equal(w.Secrets[i].KeyPackageHash, keyPackageHash) {
			return &w.Secrets[i]
		}
	}
	return nil
}

// GroupInfo represents the MLS GroupInfo structure as defined in RFC 9420 §11.2.1.
//
// GroupInfo contains public information about a group's state, signed by a
// current member. It is encrypted for transmission in Welcome messages to
// protect group secrets from unauthorized disclosure.
//
// RFC 9420 §11.2.1:
//
//	struct {
//	    GroupContext group_context;
//	    Extension extensions<V>;
//	    opaque confirmation_tag<V>;
//	    uint32 signer;
//	    opaque signature<V>;
//	} GroupInfo;
type GroupInfo struct {
	GroupContext    *GroupContext
	Extensions      []Extension
	ConfirmationTag []byte
	Signer          uint32
	Signature       []byte
}

// GroupContext re-exports the canonical MLS group context type.
type GroupContext = group.GroupContext

// Extension re-exports the canonical MLS extension type.
type Extension = mlsext.Extension

// Marshal serializes the GroupInfo to TLS presentation language format.
//
// The GroupInfo is serialized as:
//   - group_context: serialized GroupContext
//   - extensions: vector of extensions
//   - confirmation_tag: MAC for epoch confirmation
//   - signer: leaf index of the signer
//   - signature: signature over the TBS (To-Be-Signed) content
func (gi *GroupInfo) Marshal() []byte {
	tbsBytes := gi.marshalTBS()

	buf := tls.NewWriter()
	buf.WriteRaw(tbsBytes)
	buf.WriteVLBytes(gi.Signature)

	return buf.Bytes()
}

// marshalTBS serializes the To-Be-Signed (TBS) payload of GroupInfo.
//
// The TBS payload includes all fields except the signature itself:
//   - group_context
//   - extensions
//   - confirmation_tag
//   - signer
//
// The signature is computed over this TBS payload using the signer's
// signature key (RFC 9420 §5.3).
func (gi *GroupInfo) marshalTBS() []byte {
	buf := tls.NewWriter()

	buf.WriteRaw(gi.GroupContext.Marshal())

	extBuf := tls.NewWriter()
	for _, ext := range gi.Extensions {
		extBuf.WriteUint16(uint16(ext.Type))
		extBuf.WriteVLBytes(ext.Data)
	}
	buf.WriteVLBytes(extBuf.Bytes())

	buf.WriteVLBytes(gi.ConfirmationTag)
	buf.WriteUint32(gi.Signer)

	return buf.Bytes()
}

// UnmarshalGroupInfo parses a GroupInfo from TLS presentation language format.
//
// This function decodes the binary data according to RFC 9420 §11.2.1:
//   - group_context: GroupContext structure
//   - extensions: vector of extensions
//   - confirmation_tag: MAC for epoch confirmation
//   - signer: leaf index of signer
//   - signature: signature over TBS content
//
// Returns an error if the data is malformed or incomplete.
func UnmarshalGroupInfo(data []byte) (*GroupInfo, error) {
	buf := tls.NewReader(data)

	groupContext, err := UnmarshalGroupContext(buf.BytesAfterPosition())
	if err != nil {
		return nil, fmt.Errorf("parsing GroupContext: %w", err)
	}
	buf.Skip(len(groupContext.Marshal()))

	extBytes, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading extensions: %w", err)
	}
	extensions, err := unmarshalExtensions(extBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing extensions: %w", err)
	}

	confirmationTag, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading confirmation_tag: %w", err)
	}

	signer, err := buf.ReadUint32()
	if err != nil {
		return nil, fmt.Errorf("reading signer: %w", err)
	}

	signature, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading signature: %w", err)
	}

	return &GroupInfo{
		GroupContext:    groupContext,
		Extensions:      extensions,
		ConfirmationTag: confirmationTag,
		Signer:          signer,
		Signature:       signature,
	}, nil
}

// UnmarshalGroupContext parses a GroupContext from TLS presentation language format.
//
// This function decodes the binary data according to RFC 9420 §5.2:
//   - protocol_version: uint16
//   - cipher_suite: uint16
//   - group_id: variable-length identifier
//   - epoch: uint64
//   - tree_hash: hash of ratchet tree
//   - confirmed_transcript_hash: transcript hash
//   - extensions: vector of extensions
//
// Returns an error if the data is malformed or incomplete.
func UnmarshalGroupContext(data []byte) (*GroupContext, error) {
	return group.UnmarshalGroupContext(data)
}

// unmarshalExtensions parses a vector of extensions from TLS presentation
// language format.
//
// Each extension is encoded as:
//   - extension_type: uint16
//   - extension_data: variable-length bytes
//
// Unknown extension types are preserved (RFC 9420 §13.4 requires ignoring
// unknown extensions rather than rejecting them).
func unmarshalExtensions(data []byte) ([]Extension, error) {
	buf := tls.NewReader(data)
	var extensions []Extension

	for buf.Remaining() > 0 {
		extType, err := buf.ReadUint16()
		if err != nil {
			return nil, err
		}

		extData, err := buf.ReadVLBytes()
		if err != nil {
			return nil, err
		}

		extensions = append(extensions, Extension{
			Type: mlsext.ExtensionType(extType),
			Data: extData,
		})
	}

	return extensions, nil
}

// EncryptGroupInfo encrypts a GroupInfo for inclusion in a Welcome message
// as specified in RFC 9420 §11.2.2.
//
// The AEAD algorithm is selected based on cs (AES-128-GCM for CS1/CS2,
// ChaCha20-Poly1305 for CS3). welcome_key and welcome_nonce must be derived
// from welcome_secret using HKDF-Expand-Label:
//   - welcome_key = HKDF-Expand-Label(welcome_secret, "key", "", AEAD.Nk)
//   - welcome_nonce = HKDF-Expand-Label(welcome_secret, "nonce", "", AEAD.Nn)
//
// The GroupInfo is serialized and encrypted with no associated data (AAD).
func EncryptGroupInfo(groupInfo *GroupInfo, welcomeKey, welcomeNonce []byte, cs ciphersuite.CipherSuite) ([]byte, error) {
	groupInfoBytes := groupInfo.Marshal()
	return ciphersuite.EncryptWithCipherSuite(welcomeKey, welcomeNonce, groupInfoBytes, []byte{}, cs)
}

// DecryptGroupInfo decrypts a GroupInfo from a Welcome message.
//
// This function reverses the encryption performed by EncryptGroupInfo,
// using the same welcome_key and welcome_nonce derived from welcome_secret.
// The AEAD algorithm is selected based on cs.
//
// Returns an error if decryption fails (e.g., wrong key, tampered ciphertext)
// or if the decrypted data cannot be parsed as a valid GroupInfo.
func DecryptGroupInfo(encryptedGroupInfo, welcomeKey, welcomeNonce []byte, cs ciphersuite.CipherSuite) (*GroupInfo, error) {
	if len(encryptedGroupInfo) < 16 {
		return nil, errors.New("encrypted group info too short")
	}

	plaintext, err := ciphersuite.DecryptWithCipherSuite(welcomeKey, welcomeNonce, encryptedGroupInfo, []byte{}, cs)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return UnmarshalGroupInfo(plaintext)
}

// ComputeConfirmationTag computes the MLS confirmation tag as specified in
// RFC 9420 §8.2 (Transcript Hashes).
//
// The confirmation tag is a MAC over the confirmed_transcript_hash using the
// confirmation_key:
//
//	confirmation_tag = MAC(confirmation_key, confirmed_transcript_hash)
//
// The confirmation_key is derived from the epoch_secret using HKDF-Expand-Label
// with the label "confirm". The hash function h is determined by the cipher suite.
//
// This tag allows new members to verify that the GroupInfo they received is
// consistent with the group's transcript history.
func ComputeConfirmationTag(h func() hash.Hash, confirmationKey, confirmedTranscriptHash []byte) []byte {
	mac := hmac.New(h, confirmationKey)
	mac.Write(confirmedTranscriptHash)
	return mac.Sum(nil)
}

// VerifyConfirmationTag verifies a confirmation tag using constant-time comparison.
//
// This function computes the expected confirmation tag and compares it with
// the provided tag using hmac.Equal to prevent timing attacks.
//
// Returns true if the tag is valid, false otherwise.
func VerifyConfirmationTag(h func() hash.Hash, confirmationKey, confirmedTranscriptHash, expectedTag []byte) bool {
	computedTag := ComputeConfirmationTag(h, confirmationKey, confirmedTranscriptHash)
	return hmac.Equal(computedTag, expectedTag)
}

// HashKeyPackage computes the hash reference of a KeyPackage as specified in
// RFC 9420 §10.5 (KeyPackage Hash Reference).
//
// The hash is computed using SHA-256 over the serialized KeyPackage:
//
//	key_package_hash = Hash(KeyPackage.Marshal())
//
// This hash is used in Welcome messages to identify which KeyPackage each
// EncryptedGroupSecrets entry is intended for (RFC 9420 §11.2.2).
func HashKeyPackage(keyPackageBytes []byte) []byte {
	hashSum := sha256.Sum256(keyPackageBytes)
	return hashSum[:]
}
