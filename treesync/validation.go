package treesync

import (
	"errors"
	"fmt"
	"time"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// ValidateLeafNodeSignature validates the signature on a LeafNode.
// Uses the RFC 9420 §7.2 "LeafNodeTBS" label and the cipher suite's
// signature scheme, supporting both ECDSA and Ed25519.
func ValidateLeafNodeSignature(
	leafData *LeafNodeData,
	signature []byte,
	cs ciphersuite.CipherSuite,
) error {
	if leafData.SignatureKey == nil && len(leafData.SignatureKeyRaw) == 0 {
		return errors.New("signature_key is nil")
	}

	if len(signature) == 0 {
		return errors.New("signature is empty")
	}

	tbs := leafData.MarshalTBSWithContext(nil, 0)
	pubKeyBytes := leafData.SigKeyBytes()
	pk := ciphersuite.NewMLSSignaturePublicKey(pubKeyBytes, cs.SignatureScheme())
	return ciphersuite.VerifyWithLabel(pk, "LeafNodeTBS", tbs, ciphersuite.NewSignature(signature))
}

// ValidateLeafNodeLifetime validates the lifetime of a LeafNode.
func ValidateLeafNodeLifetime(lifetime *LeafNodeLifetime) error {
	return ValidateLeafNodeLifetimeAt(lifetime, time.Now())
}

// ValidateLeafNodeLifetimeAt validates the lifetime of a LeafNode against a supplied time.
func ValidateLeafNodeLifetimeAt(lifetime *LeafNodeLifetime, now time.Time) error {
	if lifetime == nil {
		return nil
	}

	nowUnix := uint64(now.Unix())

	if nowUnix < lifetime.NotBefore {
		return fmt.Errorf("leaf node not yet valid (not_before: %d, now: %d)",
			lifetime.NotBefore, nowUnix)
	}

	if nowUnix > lifetime.NotAfter {
		return fmt.Errorf("leaf node expired (not_after: %d, now: %d)",
			lifetime.NotAfter, nowUnix)
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
func ValidateLeafNode(leafData *LeafNodeData, cs ciphersuite.CipherSuite) error {
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

	if err := ValidateLeafNodeSignature(leafData, leafData.Signature, cs); err != nil {
		return fmt.Errorf("signature validation failed: %w", err)
	}

	return nil
}
