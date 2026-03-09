// Package schedule implements the MLS Key Schedule according to RFC 9420 §8.
//
// The key schedule describes the chain of key derivations used to progress
// from epoch to epoch, as well as the derivation of various secrets.
//
// This implementation is generic and can be used for any MLS-based protocol,
// not just DAVE.
package schedule

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/internal/tls"
)

// EpochSecrets contains all secrets derived for an epoch (RFC 9420 §8).
//
// From epoch_secret, we derive:
//   - encryption_secret → secret tree
//   - exporter_secret → external exporters
//   - authentication_secret → authentication keys
//   - confirmation_key → confirmation_tag
//   - membership_key → membership_tag
//   - external_secret → external senders
//   - resumption_secret → reinitialization
//   - init_secret → next epoch
type EpochSecrets struct {
	SenderDataSecret     *ciphersuite.Secret
	EncryptionSecret     *ciphersuite.Secret
	ExporterSecret       *ciphersuite.Secret
	AuthenticationSecret *ciphersuite.Secret
	ConfirmationKey      *ciphersuite.Secret
	MembershipKey        *ciphersuite.Secret
	ExternalSecret       *ciphersuite.Secret
	ResumptionSecret     *ciphersuite.Secret
	InitSecret           *ciphersuite.Secret
}

// KeySchedule implements the MLS key schedule state machine.
type KeySchedule struct {
	ciphersuite   ciphersuite.CipherSuite
	initSecret    *ciphersuite.Secret
	commitSecret  *ciphersuite.Secret
	joinerSecret  *ciphersuite.Secret
	rawPskSecret  *ciphersuite.Secret // raw psk_secret (before Extract with joiner_secret)
	pskSecret     *ciphersuite.Secret // stores member_secret = Extract(joiner_secret, rawPskSecret)
	welcomeSecret *ciphersuite.Secret
	epochSecret   *ciphersuite.Secret
	groupContext  []byte
}

// NewKeySchedule creates a new key schedule.
//
// For the first epoch: initSecret = all zeros
// For subsequent epochs: initSecret from previous epoch
func NewKeySchedule(cs ciphersuite.CipherSuite, initSecret *ciphersuite.Secret) *KeySchedule {
	return &KeySchedule{
		ciphersuite: cs,
		initSecret:  initSecret,
	}
}

// InitSecret returns the init_secret.
func (ks *KeySchedule) InitSecret() *ciphersuite.Secret {
	return ks.initSecret
}

// SetCommitSecret sets the commit_secret.
func (ks *KeySchedule) SetCommitSecret(commitSecret *ciphersuite.Secret) {
	ks.commitSecret = commitSecret
}

// SetJoinerSecret sets joiner_secret directly.
// This is used by Welcome recipients that already possess joiner_secret.
func (ks *KeySchedule) SetJoinerSecret(joinerSecret *ciphersuite.Secret) {
	ks.joinerSecret = joinerSecret
}

// ComputeJoinerSecret computes joiner_secret per RFC 9420 §8:
//
//  1. intermediate = HKDF-Extract(init_secret, commit_secret)
//  2. joiner_secret = ExpandWithLabel(intermediate, "joiner", GroupContext, Nh)
func (ks *KeySchedule) ComputeJoinerSecret(groupContext []byte) (*ciphersuite.Secret, error) {
	if ks.initSecret == nil {
		return nil, fmt.Errorf("init_secret is nil")
	}

	commitSecret := ks.commitSecret
	if commitSecret == nil {
		commitSecret = ciphersuite.ZeroSecret(ks.ciphersuite.HashLength())
	}

	intermediate, err := ks.initSecret.HKDFExtract(commitSecret)
	if err != nil {
		return nil, fmt.Errorf("HKDF extract intermediate: %w", err)
	}

	joinerSecret, err := intermediate.KdfExpandLabel("joiner", groupContext, ks.ciphersuite.HashLength())
	if err != nil {
		return nil, fmt.Errorf("ExpandWithLabel joiner_secret: %w", err)
	}

	ks.joinerSecret = joinerSecret
	return joinerSecret, nil
}

// ComputePskSecret computes member_secret from PSKs.
func (ks *KeySchedule) ComputePskSecret(psks []Psk) (*ciphersuite.Secret, error) {
	if ks.joinerSecret == nil {
		return nil, fmt.Errorf("joiner_secret not computed")
	}
	var pskSecret *ciphersuite.Secret
	if len(psks) == 0 {
		pskSecret = ciphersuite.ZeroSecret(ks.ciphersuite.HashLength())
	} else {
		pskInput, err := ComputePskInput(psks, ks.ciphersuite)
		if err != nil {
			return nil, fmt.Errorf("computing psk input: %w", err)
		}
		pskSecret = ciphersuite.NewSecret(pskInput)
	}
	ks.rawPskSecret = pskSecret
	memberSecret, err := ks.joinerSecret.HKDFExtract(pskSecret)
	if err != nil {
		return nil, fmt.Errorf("HKDF extract member_secret: %w", err)
	}
	ks.pskSecret = memberSecret
	return memberSecret, nil
}

// SetPskSecretDirect injects a raw psk_secret directly (used for Welcome recipients
// and interop testing where psk_secret is provided externally).
func (ks *KeySchedule) SetPskSecretDirect(pskSecret *ciphersuite.Secret) error {
	if ks.joinerSecret == nil {
		return fmt.Errorf("joiner_secret not computed")
	}
	ks.rawPskSecret = pskSecret
	memberSecret, err := ks.joinerSecret.HKDFExtract(pskSecret)
	if err != nil {
		return fmt.Errorf("HKDF extract member_secret: %w", err)
	}
	ks.pskSecret = memberSecret
	return nil
}

// ComputeEpochSecret computes epoch_secret = ExpandWithLabel(member_secret, "epoch", GroupContext, Nh).
func (ks *KeySchedule) ComputeEpochSecret(groupContext []byte) (*ciphersuite.Secret, error) {
	if ks.pskSecret == nil {
		return nil, fmt.Errorf("member_secret not computed (call ComputePskSecret first)")
	}
	epochSecret, err := ks.pskSecret.KdfExpandLabel("epoch", groupContext, ks.ciphersuite.HashLength())
	if err != nil {
		return nil, fmt.Errorf("deriving epoch_secret: %w", err)
	}
	ks.epochSecret = epochSecret
	ks.groupContext = groupContext
	return epochSecret, nil
}

// DeriveEpochSecrets derives all epoch secrets from epoch_secret.
func (ks *KeySchedule) DeriveEpochSecrets() (*EpochSecrets, error) {
	if ks.epochSecret == nil {
		return nil, fmt.Errorf("epoch_secret not computed")
	}

	secrets := &EpochSecrets{}
	var err error

	// All epoch secrets use DeriveSecret = KdfExpandLabel(label, [], Nh) per RFC 9420 §8.
	// sender_data_secret
	secrets.SenderDataSecret, err = ks.epochSecret.DeriveSecret(ks.ciphersuite, "sender data")
	if err != nil {
		return nil, fmt.Errorf("deriving sender_data_secret: %w", err)
	}

	// encryption_secret
	secrets.EncryptionSecret, err = ks.epochSecret.DeriveSecret(ks.ciphersuite, "encryption")
	if err != nil {
		return nil, fmt.Errorf("deriving encryption_secret: %w", err)
	}

	// exporter_secret
	secrets.ExporterSecret, err = ks.epochSecret.DeriveSecret(ks.ciphersuite, "exporter")
	if err != nil {
		return nil, fmt.Errorf("deriving exporter_secret: %w", err)
	}

	// authentication_secret (= epoch_authenticator in RFC 9420)
	secrets.AuthenticationSecret, err = ks.epochSecret.DeriveSecret(ks.ciphersuite, "authentication")
	if err != nil {
		return nil, fmt.Errorf("deriving authentication_secret: %w", err)
	}

	// confirmation_key
	secrets.ConfirmationKey, err = ks.epochSecret.DeriveSecret(ks.ciphersuite, "confirm")
	if err != nil {
		return nil, fmt.Errorf("deriving confirmation_key: %w", err)
	}

	// membership_key
	secrets.MembershipKey, err = ks.epochSecret.DeriveSecret(ks.ciphersuite, "membership")
	if err != nil {
		return nil, fmt.Errorf("deriving membership_key: %w", err)
	}

	// external_secret
	secrets.ExternalSecret, err = ks.epochSecret.DeriveSecret(ks.ciphersuite, "external")
	if err != nil {
		return nil, fmt.Errorf("deriving external_secret: %w", err)
	}

	// resumption_psk
	secrets.ResumptionSecret, err = ks.epochSecret.DeriveSecret(ks.ciphersuite, "resumption")
	if err != nil {
		return nil, fmt.Errorf("deriving resumption_psk: %w", err)
	}

	// init_secret (for next epoch)
	secrets.InitSecret, err = ks.epochSecret.DeriveSecret(ks.ciphersuite, "init")
	if err != nil {
		return nil, fmt.Errorf("deriving init_secret: %w", err)
	}

	return secrets, nil
}

// ComputeWelcomeSecret computes welcome_secret per RFC 9420 §8:
//
//	welcome_secret = DeriveSecret(member_secret, "welcome")
//	             = ExpandWithLabel(member_secret, "welcome", [], Nh)
func (ks *KeySchedule) ComputeWelcomeSecret() (*ciphersuite.Secret, error) {
	if ks.pskSecret == nil {
		return nil, fmt.Errorf("member_secret not computed (call ComputePskSecret first)")
	}

	welcomeSecret, err := ks.pskSecret.DeriveSecret(ks.ciphersuite, "welcome")
	if err != nil {
		return nil, fmt.Errorf("deriving welcome_secret: %w", err)
	}

	ks.welcomeSecret = welcomeSecret
	return welcomeSecret, nil
}

// WelcomeKeyNonce derives welcome_key and welcome_nonce from welcome_secret.
func (ks *KeySchedule) WelcomeKeyNonce() ([]byte, []byte, error) {
	if ks.welcomeSecret == nil {
		return nil, nil, fmt.Errorf("welcome_secret not computed")
	}

	// RFC 9420 §8: welcome_key/nonce use ExpandWithLabel (KdfExpandLabel)
	// RFC 9420 §8: welcome_key/nonce use ExpandWithLabel (KdfExpandLabel)
	welcomeKey, err := ks.welcomeSecret.KdfExpandLabel("key", []byte{}, ks.ciphersuite.AeadKeyLength())
	if err != nil {
		return nil, nil, fmt.Errorf("deriving welcome_key: %w", err)
	}

	welcomeNonce, err := ks.welcomeSecret.KdfExpandLabel("nonce", []byte{}, ks.ciphersuite.AeadNonceLength())
	if err != nil {
		return nil, nil, fmt.Errorf("deriving welcome_nonce: %w", err)
	}

	return welcomeKey.AsSlice(), welcomeNonce.AsSlice(), nil
}

// ComputeConfirmationTag computes confirmation_tag.
func ComputeConfirmationTag(confirmationKey, confirmedTranscriptHash []byte) []byte {
	h := hmac.New(sha256.New, confirmationKey)
	h.Write(confirmedTranscriptHash)
	return h.Sum(nil)
}

// ComputeMembershipTag computes membership_tag.
func ComputeMembershipTag(membershipKey, authenticatedContent []byte) []byte {
	h := hmac.New(sha256.New, membershipKey)
	h.Write(authenticatedContent)
	return h.Sum(nil)
}

// VerifyMembershipTag verifies a membership_tag.
func VerifyMembershipTag(membershipKey, authenticatedContent, membershipTag []byte) bool {
	expected := ComputeMembershipTag(membershipKey, authenticatedContent)
	return subtle.ConstantTimeCompare(expected, membershipTag) == 1
}

// ComputeTranscriptHash computes the transcript hash.
func ComputeTranscriptHash(interimTranscriptHash, framedContent, signature []byte) []byte {
	buf := tls.NewWriter()
	buf.WriteRaw(interimTranscriptHash)
	buf.WriteRaw(framedContent)
	buf.WriteVLBytes(signature)

	hash := sha256.Sum256(buf.Bytes())
	return hash[:]
}

// ComputeInterimTranscriptHash computes interim_transcript_hash.
func ComputeInterimTranscriptHash(confirmedTranscriptHash, confirmationTag []byte) []byte {
	buf := tls.NewWriter()
	buf.WriteRaw(confirmedTranscriptHash)
	buf.WriteVLBytes(confirmationTag)

	hash := sha256.Sum256(buf.Bytes())
	return hash[:]
}
