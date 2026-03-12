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
	"crypto/subtle"
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/internal/tls"
)

// EpochSecrets contains all secrets derived for an epoch as defined in RFC 9420 §8.
//
// From epoch_secret, we derive multiple secrets for different purposes:
//   - sender_data_secret: Encrypts sender metadata in PrivateMessages
//   - encryption_secret: Derives message encryption keys via secret tree
//   - exporter_secret: Exports secrets to other protocols (RFC §8.5)
//   - authentication_secret: Epoch authenticator for group state verification
//   - confirmation_key: Computes confirmation_tag (RFC §8.2)
//   - membership_key: Computes membership_tag for PublicMessages (RFC §6)
//   - external_secret: Derives HPKE key pair for external commits (RFC §8.3)
//   - resumption_secret: Proves membership via PSK injection (RFC §8.6)
//   - init_secret: Input for the next epoch's key schedule
//
// RFC 9420 §8, Table 4:
//
//	epoch_secret
//	    │
//	    ├─► sender_data_secret
//	    ├─► encryption_secret ──► SecretTree
//	    ├─► exporter_secret ──► Exporters
//	    ├─► authentication_secret
//	    ├─► confirmation_key ──► confirmation_tag
//	    ├─► membership_key ──► membership_tag
//	    ├─► external_secret ──► External senders
//	    ├─► resumption_psk ──► Reinit/Branch
//	    └─► init_secret ──► Next epoch
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

// KeySchedule implements the MLS key schedule state machine as defined in RFC 9420 §8.
//
// The KeySchedule manages the stateful derivation of secrets across epochs:
//   - initSecret: Carried forward from the previous epoch
//   - commitSecret: Fresh entropy from the current commit (UpdatePath)
//   - joinerSecret: Intermediate secret after mixing commit entropy
//   - pskSecret: Optional pre-shared key input (RFC §8.4)
//   - epochSecret: The root secret for all epoch-specific secrets
//
// The state machine must be used in order (see package doc for details).
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

// NewKeySchedule creates a new key schedule for an epoch.
//
// Parameters:
//   - cs: Cipher suite for HKDF operations
//   - initSecret: The init_secret from the previous epoch
//
// For the first epoch (epoch 0), initSecret MUST be all zeros:
//
//	initSecret = 0^Nh  (where Nh is the hash output length)
//
// For subsequent epochs, initSecret comes from the previous epoch's secrets:
//
//	initSecret[n] = DeriveSecret(epoch_secret[n-1], "init")
//
// RFC 9420 §8:
//
//	init_secret_[0] = 0^Nh
//	init_secret_[n] = DeriveSecret(epoch_secret_[n-1], "init") for n > 0
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

// SetCommitSecret sets the commit_secret for the current epoch.
//
// The commit_secret contains fresh entropy from the UpdatePath in a Commit message.
// It is mixed with init_secret to provide post-compromise security.
//
// RFC 9420 §8:
//
//	intermediate_secret = HKDF-Extract(init_secret, commit_secret)
//
// If no commit secret is available (e.g., external commit), this should be
// set to zeros before calling ComputeJoinerSecret.
func (ks *KeySchedule) SetCommitSecret(commitSecret *ciphersuite.Secret) {
	ks.commitSecret = commitSecret
}

// SetJoinerSecret sets joiner_secret directly.
//
// This is used by Welcome recipients that already possess joiner_secret
// (e.g., from a KeyPackage's HPKE decryption).
//
// RFC 9420 §8:
//
//	joiner_secret = ExpandWithLabel(
//	    HKDF-Extract(init_secret, commit_secret),
//	    "joiner",
//	    GroupContext,
//	    Nh
//	)
func (ks *KeySchedule) SetJoinerSecret(joinerSecret *ciphersuite.Secret) {
	ks.joinerSecret = joinerSecret
}

// ComputeJoinerSecret computes joiner_secret per RFC 9420 §8.
//
// The joiner_secret is derived in two steps:
//  1. intermediate_secret = HKDF-Extract(init_secret, commit_secret)
//  2. joiner_secret = ExpandWithLabel(intermediate, "joiner", GroupContext, Nh)
//
// Parameters:
//   - groupContext: The serialized GroupContext for the current epoch
//
// Returns the computed joiner_secret, or an error if init_secret is not set.
//
// RFC 9420 §8:
//
//	intermediate_secret = HKDF-Extract(init_secret, commit_secret)
//	joiner_secret = ExpandWithLabel(intermediate_secret, "joiner", GroupContext, Nh)
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

// ComputePskSecret computes member_secret from PSKs per RFC 9420 §8.4.
//
// Pre-Shared Keys are mixed into the key schedule to provide additional entropy:
//   - External PSKs: Application-defined pre-shared keys
//   - Resumption PSKs: Prove membership in a previous epoch
//   - Branch PSKs: Link a new group to an existing one
//
// The PSK combination uses iterated HKDF-Extract:
//
//	psk_secret_0 = 0^Nh
//	psk_secret_i = HKDF-Extract(psk_input[i], psk_secret_{i-1})
//	psk_secret   = psk_secret_n
//	member_secret = HKDF-Extract(joiner_secret, psk_secret)
//
// Parameters:
//   - psks: List of PSKs to mix in (may be empty for no PSKs)
//
// Returns member_secret, or an error if joiner_secret is not set.
//
// RFC 9420 §8.4:
//
//	member_secret = HKDF-Extract(joiner_secret, psk_secret)
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

// SetPskSecretFromInput sets the psk_secret from a test vector input.
// This is used for interop testing where psk_secret is provided as an input.
func (ks *KeySchedule) SetPskSecretFromInput(pskSecretInput *ciphersuite.Secret) error {
	if ks.joinerSecret == nil {
		return fmt.Errorf("joiner_secret not computed")
	}
	ks.rawPskSecret = pskSecretInput
	memberSecret, err := ks.joinerSecret.HKDFExtract(pskSecretInput)
	if err != nil {
		return fmt.Errorf("HKDF extract member_secret: %w", err)
	}
	ks.pskSecret = memberSecret
	return nil
}

// ComputeEpochSecret computes epoch_secret per RFC 9420 §8.
//
// The epoch_secret is the root secret from which all epoch-specific secrets
// are derived. It is computed as:
//
//	epoch_secret = ExpandWithLabel(member_secret, "epoch", GroupContext, Nh)
//
// Parameters:
//   - groupContext: The serialized GroupContext for the current epoch
//
// Returns the computed epoch_secret, or an error if member_secret is not set.
//
// RFC 9420 §8:
//
//	epoch_secret = ExpandWithLabel(member_secret, "epoch", GroupContext, Nh)
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

// DeriveEpochSecrets derives all epoch secrets from epoch_secret per RFC 9420 §8.
//
// From epoch_secret, the following secrets are derived using DeriveSecret:
//
//	DeriveSecret(epoch_secret, label) = ExpandWithLabel(epoch_secret, label, [], Nh)
//
// The derived secrets are:
//   - sender_data_secret: For encrypting sender metadata
//   - encryption_secret: For the secret tree (message encryption)
//   - exporter_secret: For external protocol exporters
//   - authentication_secret: Epoch authenticator for group state
//   - confirmation_key: For computing confirmation_tag
//   - membership_key: For computing membership_tag
//   - external_secret: For external sender HPKE keys
//   - resumption_psk: For proving group membership
//   - init_secret: For the next epoch's key schedule
//
// Returns EpochSecrets containing all derived secrets, or an error if
// epoch_secret is not set.
//
// RFC 9420 §8, Table 4:
//
//	epoch_secret ──┬──► sender_data_secret
//	               ├──► encryption_secret
//	               ├──► exporter_secret
//	               ├──► authentication_secret
//	               ├──► confirmation_key
//	               ├──► membership_key
//	               ├──► external_secret
//	               ├──► resumption_psk
//	               └──► init_secret
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

// ComputeWelcomeSecret computes welcome_secret per RFC 9420 §8.
//
// The welcome_secret is used to encrypt GroupInfo for transmission in Welcome
// messages. It is derived as:
//
//	welcome_secret = DeriveSecret(member_secret, "welcome")
//	             = ExpandWithLabel(member_secret, "welcome", [], Nh)
//
// Returns the computed welcome_secret, or an error if member_secret is not set.
//
// RFC 9420 §8:
//
//	welcome_secret = DeriveSecret(member_secret, "welcome")
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
//
// These values are used to encrypt GroupInfo in Welcome messages:
//
//	welcome_key = ExpandWithLabel(welcome_secret, "key", [], AEAD.Nk)
//	welcome_nonce = ExpandWithLabel(welcome_secret, "nonce", [], AEAD.Nn)
//
// Returns the 16-byte welcome_key and 12-byte welcome_nonce (for AES-128-GCM),
// or an error if welcome_secret is not set.
//
// RFC 9420 §8:
//
//	welcome_key = ExpandWithLabel(welcome_secret, "key", [], AEAD.Nk)
//	welcome_nonce = ExpandWithLabel(welcome_secret, "nonce", [], AEAD.Nn)
func (ks *KeySchedule) WelcomeKeyNonce() (welcomeKey, welcomeNonce []byte, err error) {
	if ks.welcomeSecret == nil {
		return nil, nil, fmt.Errorf("welcome_secret not computed")
	}

	// RFC 9420 §8: welcome_key/nonce use ExpandWithLabel (KdfExpandLabel)
	key, err := ks.welcomeSecret.KdfExpandLabel("key", []byte{}, ks.ciphersuite.AeadKeyLength())
	if err != nil {
		return nil, nil, fmt.Errorf("deriving welcome_key: %w", err)
	}

	nonce, err := ks.welcomeSecret.KdfExpandLabel("nonce", []byte{}, ks.ciphersuite.AeadNonceLength())
	if err != nil {
		return nil, nil, fmt.Errorf("deriving welcome_nonce: %w", err)
	}

	return key.AsSlice(), nonce.AsSlice(), nil
}

// ComputeConfirmationTag computes confirmation_tag using the ciphersuite hash.
//
// The confirmation_tag is a MAC over the confirmed_transcript_hash that allows
// new members to verify all group members have the same view of the group state.
//
//	confirmation_tag = HMAC(confirmation_key, confirmed_transcript_hash)
//
// Parameters:
//   - cs: Cipher suite for HMAC
//   - confirmationKey: The confirmation_key from epoch secrets
//   - confirmedTranscriptHash: Hash of all confirmed handshake messages
//
// Returns the 32-byte confirmation_tag (for SHA-256).
//
// RFC 9420 §8.2:
//
//	confirmation_tag = HMAC(confirmation_key, confirmed_transcript_hash)
func ComputeConfirmationTag(cs ciphersuite.CipherSuite, confirmationKey, confirmedTranscriptHash []byte) []byte {
	h := hmac.New(cs.HashFunction(), confirmationKey)
	h.Write(confirmedTranscriptHash)
	return h.Sum(nil)
}

// ComputeMembershipTag computes membership_tag using the ciphersuite hash.
//
// The membership_tag is a MAC that proves the sender is a member of the group
// (possesses the membership_key for the current epoch).
//
//	membership_tag = HMAC(membership_key, authenticated_content)
//
// Parameters:
//   - cs: Cipher suite for HMAC
//   - membershipKey: The membership_key from epoch secrets
//   - authenticatedContent: The FramedContentAuthData to authenticate
//
// Returns the membership_tag MAC.
//
// RFC 9420 §6.1:
//
//	membership_tag = HMAC(membership_key, authenticated_content)
func ComputeMembershipTag(cs ciphersuite.CipherSuite, membershipKey, authenticatedContent []byte) []byte {
	h := hmac.New(cs.HashFunction(), membershipKey)
	h.Write(authenticatedContent)
	return h.Sum(nil)
}

// VerifyMembershipTag verifies a membership_tag using constant-time comparison.
//
// This function computes the expected membership_tag and compares it with the
// provided tag to verify the sender possesses the membership_key.
//
// Parameters:
//   - cs: Cipher suite for HMAC
//   - membershipKey: The membership_key from epoch secrets
//   - authenticatedContent: The FramedContentAuthData that was authenticated
//   - membershipTag: The tag to verify
//
// Returns true if the tag is valid, false otherwise.
//
// RFC 9420 §6.1:
//
//	membership_tag = HMAC(membership_key, authenticated_content)
func VerifyMembershipTag(cs ciphersuite.CipherSuite, membershipKey, authenticatedContent, membershipTag []byte) bool {
	expected := ComputeMembershipTag(cs, membershipKey, authenticatedContent)
	return subtle.ConstantTimeCompare(expected, membershipTag) == 1
}

// ComputeTranscriptHash computes the transcript hash for a message per RFC 9420 §8.2.
//
// The transcript hash accumulates all handshake messages to ensure group state
// consistency. For each message:
//
//	transcript_hash = Hash(interim_transcript_hash || framed_content || signature)
//
// Parameters:
//   - cs: Cipher suite for hashing
//   - interimTranscriptHash: Hash of all prior handshake messages
//   - framedContent: The serialized FramedContent
//   - signature: The signature over the content
//
// Returns the new transcript hash.
//
// RFC 9420 §8.2:
//
//	transcript_hash_[N] = Hash(transcript_hash_[N-1] || framed_content || signature)
func ComputeTranscriptHash(cs ciphersuite.CipherSuite, interimTranscriptHash, framedContent, signature []byte) []byte {
	buf := tls.NewWriter()
	buf.WriteRaw(interimTranscriptHash)
	buf.WriteRaw(framedContent)
	buf.WriteVLBytes(signature)
	h := cs.HashFunction()()
	_, _ = h.Write(buf.Bytes())
	return h.Sum(nil)
}

// ComputeInterimTranscriptHash computes the interim transcript hash per RFC 9420 §8.2.
//
// The interim transcript hash is computed after processing a Commit and before
// the next handshake message:
//
//	interim_transcript_hash = Hash(confirmed_transcript_hash || confirmation_tag)
//
// Parameters:
//   - cs: Cipher suite for hashing
//   - confirmedTranscriptHash: Hash of confirmed handshake messages
//   - confirmationTag: The confirmation_tag from the Commit
//
// Returns the interim transcript hash.
//
// RFC 9420 §8.2:
//
//	interim_transcript_hash = Hash(confirmed_transcript_hash || confirmation_tag)
func ComputeInterimTranscriptHash(cs ciphersuite.CipherSuite, confirmedTranscriptHash, confirmationTag []byte) []byte {
	buf := tls.NewWriter()
	buf.WriteRaw(confirmedTranscriptHash)
	buf.WriteVLBytes(confirmationTag)
	h := cs.HashFunction()()
	_, _ = h.Write(buf.Bytes())
	return h.Sum(nil)
}
