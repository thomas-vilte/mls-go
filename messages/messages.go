// Package messages implements MLS message types according to RFC 9420.
//
// This package provides types for Welcome, Commit, Proposal, and GroupInfo messages.
//
// # Welcome Messages
//
// Welcome messages are used to add new members to a group:
//
//	welcome, err := group.CreateWelcome(newMemberKPHash)
//	if err != nil {
//	    return err
//	}
//
//	data := welcome.Marshal()
//
// # Parsing Messages
//
// To parse a Welcome from bytes:
//
//	welcome, err := messages.ParseWelcome(data)
//	if err != nil {
//	    return err
//	}
package messages

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"

	"github.com/mls-go/internal/tls"
)

// Welcome represents an MLS Welcome message (RFC 9420 §11.2.2).
//
// Welcome messages are sent to new members to allow them to join a group.
// They contain encrypted group secrets for each new member.
type Welcome struct {
	CipherSuite        uint16
	Secrets            []EncryptedGroupSecrets
	EncryptedGroupInfo []byte
}

// EncryptedGroupSecrets contains encrypted secrets for a new group member.
//
// Each new member receives their own encrypted secrets in the Welcome message.
type EncryptedGroupSecrets struct {
	KeyPackageHash []byte // Hash reference of the member's KeyPackage
	EncryptedKey   []byte // HPKE encapsulated key (kem_output)
	Ciphertext     []byte // Encrypted group secrets
}

// NewWelcome creates a new Welcome message.
func NewWelcome(cipherSuite uint16, secrets []EncryptedGroupSecrets, encryptedGroupInfo []byte) *Welcome {
	return &Welcome{
		CipherSuite:        cipherSuite,
		Secrets:            secrets,
		EncryptedGroupInfo: encryptedGroupInfo,
	}
}

// Marshal serializes the Welcome to TLS presentation language format.
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

// UnmarshalWelcome parses a Welcome message from TLS format.
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

// unmarshalEncryptedGroupSecrets parses a vector of EncryptedGroupSecrets.
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
func (w *Welcome) FindSecret(keyPackageHash []byte) *EncryptedGroupSecrets {
	for i := range w.Secrets {
		if bytes.Equal(w.Secrets[i].KeyPackageHash, keyPackageHash) {
			return &w.Secrets[i]
		}
	}
	return nil
}

// GroupInfo represents MLS GroupInfo (RFC 9420 §11.2.1).
//
// GroupInfo contains public information about a group's state,
// encrypted for transmission in Welcome messages.
type GroupInfo struct {
	GroupContext    *GroupContext
	Extensions      []Extension
	ConfirmationTag []byte
	Signer          uint32
	Signature       []byte
}

// GroupContext represents the MLS GroupContext (RFC 9420 §5.2).
type GroupContext struct {
	ProtocolVersion         uint16
	CipherSuite             uint16
	GroupID                 []byte
	Epoch                   uint64
	TreeHash                []byte
	ConfirmedTranscriptHash []byte
	Extensions              []Extension
}

// Extension represents a generic MLS extension.
type Extension struct {
	Type uint16
	Data []byte
}

// Marshal serializes the GroupInfo to TLS format.
func (gi *GroupInfo) Marshal() []byte {
	tbsBytes := gi.marshalTBS()

	buf := tls.NewWriter()
	buf.WriteRaw(tbsBytes)
	buf.WriteVLBytes(gi.Signature)

	return buf.Bytes()
}

// marshalTBS serializes the To-Be-Signed payload of GroupInfo.
func (gi *GroupInfo) marshalTBS() []byte {
	buf := tls.NewWriter()

	buf.WriteRaw(gi.GroupContext.Marshal())

	extBuf := tls.NewWriter()
	for _, ext := range gi.Extensions {
		extBuf.WriteUint16(ext.Type)
		extBuf.WriteVLBytes(ext.Data)
	}
	buf.WriteVLBytes(extBuf.Bytes())

	buf.WriteVLBytes(gi.ConfirmationTag)
	buf.WriteUint32(gi.Signer)

	return buf.Bytes()
}

// Marshal serializes the GroupContext to TLS format.
func (gc *GroupContext) Marshal() []byte {
	buf := tls.NewWriter()

	buf.WriteUint16(gc.ProtocolVersion)
	buf.WriteUint16(gc.CipherSuite)
	buf.WriteVLBytes(gc.GroupID)
	buf.WriteUint64(gc.Epoch)
	buf.WriteVLBytes(gc.TreeHash)
	buf.WriteVLBytes(gc.ConfirmedTranscriptHash)

	extBuf := tls.NewWriter()
	for _, ext := range gc.Extensions {
		extBuf.WriteUint16(ext.Type)
		extBuf.WriteVLBytes(ext.Data)
	}
	buf.WriteVLBytes(extBuf.Bytes())

	return buf.Bytes()
}

// UnmarshalGroupInfo parses a GroupInfo from TLS format.
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

// UnmarshalGroupContext parses a GroupContext from TLS format.
func UnmarshalGroupContext(data []byte) (*GroupContext, error) {
	buf := tls.NewReader(data)

	protocolVersion, err := buf.ReadUint16()
	if err != nil {
		return nil, err
	}

	cipherSuite, err := buf.ReadUint16()
	if err != nil {
		return nil, err
	}

	groupID, err := buf.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	epoch, err := buf.ReadUint64()
	if err != nil {
		return nil, err
	}

	treeHash, err := buf.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	confirmedTranscriptHash, err := buf.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	extBytes, err := buf.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	extensions, err := unmarshalExtensions(extBytes)
	if err != nil {
		return nil, err
	}

	return &GroupContext{
		ProtocolVersion:         protocolVersion,
		CipherSuite:             cipherSuite,
		GroupID:                 groupID,
		Epoch:                   epoch,
		TreeHash:                treeHash,
		ConfirmedTranscriptHash: confirmedTranscriptHash,
		Extensions:              extensions,
	}, nil
}

// unmarshalExtensions parses a vector of extensions.
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
			Type: extType,
			Data: extData,
		})
	}

	return extensions, nil
}

// EncryptGroupInfo encrypts a GroupInfo for inclusion in a Welcome.
//
// Uses AES-128-GCM with the provided welcome key and nonce.
func EncryptGroupInfo(groupInfo *GroupInfo, welcomeKey, welcomeNonce []byte) ([]byte, error) {
	groupInfoBytes := groupInfo.Marshal()

	block, err := aes.NewCipher(welcomeKey)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	ciphertext := gcm.Seal(nil, welcomeNonce, groupInfoBytes, []byte{})
	return ciphertext, nil
}

// DecryptGroupInfo decrypts a GroupInfo from a Welcome.
func DecryptGroupInfo(encryptedGroupInfo, welcomeKey, welcomeNonce []byte) (*GroupInfo, error) {
	if len(encryptedGroupInfo) < 16 {
		return nil, errors.New("encrypted group info too short")
	}

	block, err := aes.NewCipher(welcomeKey)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, welcomeNonce, encryptedGroupInfo, []byte{})
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return UnmarshalGroupInfo(plaintext)
}

// ComputeConfirmationTag computes the MLS confirmation tag.
//
// confirmation_tag = MAC(confirmation_key, confirmed_transcript_hash)
func ComputeConfirmationTag(h func() hash.Hash, confirmationKey, confirmedTranscriptHash []byte) []byte {
	mac := hmac.New(h, confirmationKey)
	mac.Write(confirmedTranscriptHash)
	return mac.Sum(nil)
}

// VerifyConfirmationTag verifies a confirmation tag.
func VerifyConfirmationTag(h func() hash.Hash, confirmationKey, confirmedTranscriptHash, expectedTag []byte) bool {
	computedTag := ComputeConfirmationTag(h, confirmationKey, confirmedTranscriptHash)
	return hmac.Equal(computedTag, expectedTag)
}

// HashKeyPackage computes the hash reference of a KeyPackage.
//
// This is used to identify KeyPackages in Welcome messages.
func HashKeyPackage(keyPackageBytes []byte) []byte {
	hash := sha256.Sum256(keyPackageBytes)
	return hash[:]
}
