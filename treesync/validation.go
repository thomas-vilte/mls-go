package treesync

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// ValidateLeafNodeSignature validates the signature on a LeafNode.
func ValidateLeafNodeSignature(
	leafData *LeafNodeData,
	signature []byte,
) error {
	if leafData.SignatureKey == nil {
		return errors.New("signature_key is nil")
	}

	if len(signature) == 0 {
		return errors.New("signature is empty")
	}

	tbsBytes := leafData.MarshalTBS()
	hash := sha256.Sum256(tbsBytes)

	if len(signature) < 64 {
		return errors.New("signature too short")
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	if !ecdsa.Verify(leafData.SignatureKey, hash[:], r, s) {
		return errors.New("signature verification failed")
	}

	return nil
}

// ValidateLeafNodeLifetime validates the lifetime of a LeafNode.
func ValidateLeafNodeLifetime(lifetime *LeafNodeLifetime) error {
	if lifetime == nil {
		return nil
	}

	now := uint64(time.Now().Unix())

	if now < lifetime.NotBefore {
		return fmt.Errorf("leaf node not yet valid (not_before: %d, now: %d)",
			lifetime.NotBefore, now)
	}

	if now > lifetime.NotAfter {
		return fmt.Errorf("leaf node expired (not_after: %d, now: %d)",
			lifetime.NotAfter, now)
	}

	return nil
}

// ValidateLeafNodeCapabilities validates that capabilities are well-formed.
func ValidateLeafNodeCapabilities(caps *LeafNodeCapabilities) error {
	if caps == nil {
		return errors.New("capabilities is nil")
	}

	if len(caps.ProtocolVersions) == 0 {
		return errors.New("protocol_versions is empty")
	}

	if len(caps.CipherSuites) == 0 {
		return errors.New("cipher_suites is empty")
	}

	for _, v := range caps.ProtocolVersions {
		if v == 0 {
			return errors.New("invalid protocol version 0")
		}
	}

	for _, cs := range caps.CipherSuites {
		if cs == 0 {
			return errors.New("invalid cipher suite 0")
		}
	}

	return nil
}

// ValidateLeafNode performs comprehensive validation of a LeafNode.
func ValidateLeafNode(leafData *LeafNodeData) error {
	if leafData == nil {
		return errors.New("leaf node is nil")
	}

	if len(leafData.EncryptionKey) == 0 {
		return errors.New("encryption_key is empty")
	}

	if leafData.SignatureKey == nil {
		return errors.New("signature_key is nil")
	}

	if leafData.Credential == nil {
		return errors.New("credential is nil")
	}

	if err := leafData.Credential.Validate(); err != nil {
		return fmt.Errorf("credential validation failed: %w", err)
	}

	if err := ValidateLeafNodeCapabilities(leafData.Capabilities); err != nil {
		return fmt.Errorf("capabilities validation failed: %w", err)
	}

	if err := ValidateLeafNodeLifetime(leafData.Lifetime); err != nil {
		return fmt.Errorf("lifetime validation failed: %w", err)
	}

	if err := ValidateLeafNodeSignature(leafData, leafData.Signature); err != nil {
		return fmt.Errorf("signature validation failed: %w", err)
	}

	return nil
}
