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
	ciphersuite        ciphersuite.CipherSuite
	initSecret         *ciphersuite.Secret
	commitSecret       *ciphersuite.Secret
	joinerSecret       *ciphersuite.Secret
	pskSecret          *ciphersuite.Secret
	intermediateSecret *ciphersuite.Secret
	welcomeSecret      *ciphersuite.Secret
	epochSecret        *ciphersuite.Secret
	groupContext       []byte
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

// ComputeJoinerSecret computes joiner_secret = HKDF.Extract(init_secret, commit_secret).
func (ks *KeySchedule) ComputeJoinerSecret() (*ciphersuite.Secret, error) {
	if ks.initSecret == nil {
		return nil, fmt.Errorf("init_secret is nil")
	}

	commitSecret := ks.commitSecret
	if commitSecret == nil {
		commitSecret = ciphersuite.ZeroSecret(ks.ciphersuite.HashLength())
	}

	joinerSecret, err := ks.initSecret.HKDFExtract(commitSecret)
	if err != nil {
		return nil, fmt.Errorf("HKDF extract failed: %w", err)
	}

	ks.joinerSecret = joinerSecret
	return joinerSecret, nil
}

// ComputePskSecret computes psk_secret from PSKs.
func (ks *KeySchedule) ComputePskSecret(psks []Psk) (*ciphersuite.Secret, error) {
	if ks.joinerSecret == nil {
		return nil, fmt.Errorf("joiner_secret not computed")
	}

	if len(psks) == 0 {
		ks.pskSecret = ks.joinerSecret
		return ks.pskSecret, nil
	}

	pskInput, err := ComputePskInput(psks, ks.ciphersuite)
	if err != nil {
		return nil, fmt.Errorf("computing PSK input: %w", err)
	}

	pskSecret := ciphersuite.NewSecret(pskInput)
	pskSecret, err = ks.joinerSecret.HKDFExtract(pskSecret)
	if err != nil {
		return nil, fmt.Errorf("HKDF extract failed: %w", err)
	}

	ks.pskSecret = pskSecret
	return pskSecret, nil
}

// ComputeIntermediateSecret computes intermediate_secret = HKDF.Extract(psk_secret, group_context).
func (ks *KeySchedule) ComputeIntermediateSecret(groupContext []byte) (*ciphersuite.Secret, error) {
	if ks.pskSecret == nil {
		return nil, fmt.Errorf("psk_secret not computed")
	}

	groupContextSecret := ciphersuite.NewSecret(groupContext)
	intermediateSecret, err := ks.pskSecret.HKDFExtract(groupContextSecret)
	if err != nil {
		return nil, fmt.Errorf("HKDF extract failed: %w", err)
	}

	ks.intermediateSecret = intermediateSecret
	ks.groupContext = groupContext
	return intermediateSecret, nil
}

// ComputeEpochSecret computes epoch_secret = HKDF.Expand(intermediate_secret, "epoch").
func (ks *KeySchedule) ComputeEpochSecret() (*ciphersuite.Secret, error) {
	if ks.intermediateSecret == nil {
		return nil, fmt.Errorf("intermediate_secret not computed")
	}

	epochSecret, err := ks.intermediateSecret.HKDFExpand([]byte("epoch"), ks.ciphersuite.HashLength())
	if err != nil {
		return nil, fmt.Errorf("HKDF expand failed: %w", err)
	}

	ks.epochSecret = epochSecret
	return epochSecret, nil
}

// DeriveEpochSecrets derives all epoch secrets from epoch_secret.
func (ks *KeySchedule) DeriveEpochSecrets() (*EpochSecrets, error) {
	if ks.epochSecret == nil {
		return nil, fmt.Errorf("epoch_secret not computed")
	}

	secrets := &EpochSecrets{}
	var err error

	// encryption_secret
	secrets.EncryptionSecret, err = ks.epochSecret.HKDFExpand([]byte("encryption"), ks.ciphersuite.HashLength())
	if err != nil {
		return nil, fmt.Errorf("deriving encryption_secret: %w", err)
	}

	// exporter_secret
	secrets.ExporterSecret, err = ks.epochSecret.HKDFExpand([]byte("exporter"), ks.ciphersuite.HashLength())
	if err != nil {
		return nil, fmt.Errorf("deriving exporter_secret: %w", err)
	}

	// authentication_secret
	secrets.AuthenticationSecret, err = ks.epochSecret.HKDFExpand([]byte("authentication"), ks.ciphersuite.HashLength())
	if err != nil {
		return nil, fmt.Errorf("deriving authentication_secret: %w", err)
	}

	// confirmation_key (32 bytes)
	secrets.ConfirmationKey, err = ks.epochSecret.HKDFExpand([]byte("confirm"), 32)
	if err != nil {
		return nil, fmt.Errorf("deriving confirmation_key: %w", err)
	}

	// membership_key (32 bytes)
	secrets.MembershipKey, err = ks.epochSecret.HKDFExpand([]byte("membership"), 32)
	if err != nil {
		return nil, fmt.Errorf("deriving membership_key: %w", err)
	}

	// external_secret
	secrets.ExternalSecret, err = ks.epochSecret.HKDFExpand([]byte("external"), ks.ciphersuite.HashLength())
	if err != nil {
		return nil, fmt.Errorf("deriving external_secret: %w", err)
	}

	// resumption_secret
	secrets.ResumptionSecret, err = ks.epochSecret.HKDFExpand([]byte("resumption"), ks.ciphersuite.HashLength())
	if err != nil {
		return nil, fmt.Errorf("deriving resumption_secret: %w", err)
	}

	// init_secret (for next epoch)
	secrets.InitSecret, err = ks.epochSecret.HKDFExpand([]byte("init"), ks.ciphersuite.HashLength())
	if err != nil {
		return nil, fmt.Errorf("deriving init_secret: %w", err)
	}

	return secrets, nil
}

// ComputeWelcomeSecret computes welcome_secret for joining via Welcome.
func (ks *KeySchedule) ComputeWelcomeSecret() (*ciphersuite.Secret, error) {
	if ks.joinerSecret == nil {
		return nil, fmt.Errorf("joiner_secret not computed")
	}

	welcomeSecret, err := ks.joinerSecret.HKDFExpand([]byte("welcome"), sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("HKDF expand failed: %w", err)
	}

	ks.welcomeSecret = welcomeSecret
	return welcomeSecret, nil
}

// WelcomeKeyNonce derives welcome_key and welcome_nonce from welcome_secret.
func (ks *KeySchedule) WelcomeKeyNonce() ([]byte, []byte, error) {
	if ks.welcomeSecret == nil {
		return nil, nil, fmt.Errorf("welcome_secret not computed")
	}

	welcomeKey, err := ks.welcomeSecret.HKDFExpand([]byte("key"), 16)
	if err != nil {
		return nil, nil, fmt.Errorf("deriving welcome_key: %w", err)
	}

	welcomeNonce, err := ks.welcomeSecret.HKDFExpand([]byte("nonce"), 12)
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
