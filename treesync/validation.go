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

// ValidateLeafNodeStructureWithContext validates the structural properties of a
// LeafNode (key presence, credential, capabilities, signature) with group context,
// but does NOT check the leaf lifetime. Use this when validating existing group
// members' leaves (e.g. during Welcome processing), where expired lifetimes cannot
// be rejected since the joiner cannot choose group membership.
func ValidateLeafNodeStructureWithContext(leafData *LeafNodeData, cs ciphersuite.CipherSuite, groupID []byte, leafIndex uint32) error {
	if leafData == nil {
		return errors.New("leaf node is nil")
	}
	if len(leafData.EncryptionKey) == 0 {
		return errors.New("encryption_key is empty")
	}
	if len(leafData.SigKeyBytes()) == 0 {
		return errors.New("signature_key is empty")
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
	if err := leafData.VerifyWithContext(cs, groupID, leafIndex); err != nil {
		return fmt.Errorf("signature validation failed: %w", err)
	}
	return nil
}

// ValidateLeafNodeWithContext performs comprehensive validation of a LeafNode
// including a context-aware signature check. Use this for leaves with
// leaf_node_source == update (2) or commit (3), which include group_id and
// leaf_index in the signed TBS per RFC 9420 §7.2.
// For key_package leaves (source == 1), pass (nil, 0) or use ValidateLeafNode.
func ValidateLeafNodeWithContext(leafData *LeafNodeData, cs ciphersuite.CipherSuite, groupID []byte, leafIndex uint32) error {
	if leafData == nil {
		return errors.New("leaf node is nil")
	}
	if len(leafData.EncryptionKey) == 0 {
		return errors.New("encryption_key is empty")
	}
	if len(leafData.SigKeyBytes()) == 0 {
		return errors.New("signature_key is empty")
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
	if err := leafData.VerifyWithContext(cs, groupID, leafIndex); err != nil {
		return fmt.Errorf("signature validation failed: %w", err)
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

	// RFC §7.3: signature_key must be present. Use SigKeyBytes() to support both
	// ECDSA (SignatureKey parsed) and Ed25519 (SignatureKeyRaw only).
	if len(leafData.SigKeyBytes()) == 0 {
		return errors.New("signature_key is empty")
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

	// RFC §7.3: every extension type in LeafNode.extensions MUST appear in capabilities.extensions.
	if leafData.Capabilities != nil {
		capExts := leafData.Capabilities.Extensions
		for _, extBytes := range leafData.Extensions {
			if len(extBytes) < 2 {
				return fmt.Errorf("extension entry too short (%d bytes)", len(extBytes))
			}
			extType := uint16(extBytes[0])<<8 | uint16(extBytes[1])
			found := false
			for _, capExt := range capExts {
				if capExt == extType {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("extension type 0x%04x not declared in capabilities.extensions (RFC §7.3)", extType)
			}
		}
	}

	return nil
}
