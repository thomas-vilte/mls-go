package group

import (
	"errors"
	"fmt"
)

// Typed errors for semantic error handling
// These errors contain context about the failure.

// ErrEpochMismatch is returned when a message belongs to the wrong epoch.
type ErrEpochMismatch struct {
	Got  uint64
	Want uint64
}

func (e *ErrEpochMismatch) Error() string {
	return fmt.Sprintf("group: epoch mismatch: message has %d, group is at %d", e.Got, e.Want)
}

// ErrGroupIDMismatch is returned when a message carries an incorrect ID.
type ErrGroupIDMismatch struct {
	Got  []byte
	Want []byte
}

func (e *ErrGroupIDMismatch) Error() string {
	return fmt.Sprintf("group: group ID mismatch: message has %x, group is at %x", e.Got, e.Want)
}

// ErrInvalidSignature is returned when a signature does not verify.
type ErrInvalidSignature struct {
	Context string
	Err     error
}

func (e *ErrInvalidSignature) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("group: %s signature invalid: %v", e.Context, e.Err)
	}
	return fmt.Sprintf("group: %s signature invalid", e.Context)
}

func (e *ErrInvalidSignature) Unwrap() error {
	return e.Err
}

// ErrUnknownMember is returned when the leaf index does not exist in the tree.
type ErrUnknownMember struct {
	LeafIndex uint32
}

func (e *ErrUnknownMember) Error() string {
	return fmt.Sprintf("group: unknown member or out of bounds leaf index: %d", e.LeafIndex)
}

// ErrDecryptionFailed is returned when AEAD decryption fails.
// This may indicate a tampered message, a wrong key, or a replay.
type ErrDecryptionFailed struct {
	Reason string
	Err    error
}

func (e *ErrDecryptionFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("group: decryption failed (%s): %v", e.Reason, e.Err)
	}
	return fmt.Sprintf("group: decryption failed (%s)", e.Reason)
}

func (e *ErrDecryptionFailed) Unwrap() error {
	return e.Err
}

// Sentinel errors for group operations.
//
// These errors represent specific failure conditions in group operations.
// They can be checked using errors.Is() for programmatic handling.
var (
	// ErrNilProposal is returned when a proposal is nil.
	ErrNilProposal = errors.New("group: proposal is nil")
	// ErrInvalidProposal is returned when a proposal is invalid.
	ErrInvalidProposal = errors.New("group: invalid proposal")
	// ErrUnsupportedProposalType is returned when a proposal type is not supported.
	ErrUnsupportedProposalType = errors.New("group: proposal type not supported")
	// ErrUnknownProposalType is returned when a proposal type is unknown.
	ErrUnknownProposalType = errors.New("group: unknown proposal type")
	// ErrNilAddProposal is returned when an add proposal is nil.
	ErrNilAddProposal = errors.New("group: add proposal is nil")
	// ErrNilUpdateProposal is returned when an update proposal is nil.
	ErrNilUpdateProposal = errors.New("group: update proposal is nil")
	// ErrNilRemoveProposal is returned when a remove proposal is nil.
	ErrNilRemoveProposal = errors.New("group: remove proposal is nil")
	// ErrNilPreSharedKeyProposal is returned when a pre-shared key proposal is nil.
	ErrNilPreSharedKeyProposal = errors.New("group: pre-shared key proposal is nil")
	// ErrNilReInitProposal is returned when a reinit proposal is nil.
	ErrNilReInitProposal = errors.New("group: reinit proposal is nil")
	// ErrNilExternalInitProposal is returned when an external init proposal is nil.
	ErrNilExternalInitProposal = errors.New("group: external init proposal is nil")
	// ErrNilGroupContextExtensionsProposal is returned when a group context extensions proposal is nil.
	ErrNilGroupContextExtensionsProposal = errors.New("group: group context extensions proposal is nil")

	// ErrNilKeyPackage is returned when a key package is nil.
	ErrNilKeyPackage = errors.New("group: key package is nil")
	// ErrNilLeafNode is returned when a leaf node is nil.
	ErrNilLeafNode = errors.New("group: leaf node is nil")

	// ErrGroupNotOperational is returned when the group is not operational.
	ErrGroupNotOperational = errors.New("group: not operational")
	// ErrPendingProposals is returned when there are proposals pending.
	ErrPendingProposals = errors.New("group: proposals pending")
	// ErrEmptyGroupID is returned when the group ID is empty.
	ErrEmptyGroupID = errors.New("group: group ID is empty")
	// ErrInvalidGroupState is returned when the group state is invalid.
	ErrInvalidGroupState = errors.New("group: invalid group state")
	// ErrUnknownEpoch is returned when the epoch is unknown.
	ErrUnknownEpoch = errors.New("group: unknown epoch")
	// ErrNilPrivateMessage is returned when a private message is nil.
	ErrNilPrivateMessage = errors.New("group: private message is nil")
	// ErrNilSignaturePrivateKey is returned when a signature private key is nil.
	ErrNilSignaturePrivateKey = errors.New("group: signature private key is nil")
	// ErrSenderDataSecretMissing is returned when the sender_data_secret is not available.
	ErrSenderDataSecretMissing = errors.New("group: sender_data_secret not available")
	// ErrSecretTreeMissing is returned when the secret tree is not available.
	ErrSecretTreeMissing = errors.New("group: secret tree not available")
	// ErrRatchetTreeMissing is returned when the ratchet tree is not available.
	ErrRatchetTreeMissing = errors.New("group: ratchet tree not available")
	// ErrSenderNotActive is returned when the sender is not an active member.
	ErrSenderNotActive = errors.New("group: sender is not an active member")
	// ErrMissingSenderSignature is returned when the sender signature key is missing.
	ErrMissingSenderSignature = errors.New("group: missing sender signature key")
	// ErrNotApplicationData is returned when a message is not application data.
	ErrNotApplicationData = errors.New("group: message is not application data")
	// ErrNoPendingCommit is returned when there is no pending commit to discard.
	ErrNoPendingCommit = errors.New("group: no pending commit to discard")
	// ErrNotACommit is returned when a message is not a commit.
	ErrNotACommit = errors.New("group: not a commit message")
	// ErrMissingAuthenticatedContent is returned when authenticated content is missing.
	ErrMissingAuthenticatedContent = errors.New("group: missing authenticated content")
	// ErrUnknownProposalRef is returned when a proposal reference in a commit is unknown.
	ErrUnknownProposalRef = errors.New("group: unknown proposal reference in commit")
	// ErrOwnLeafNotFound is returned when the own leaf is not found in the ratchet tree.
	ErrOwnLeafNotFound = errors.New("group: own leaf not found in ratchet tree")

	// ErrWelcomeNoEncryptedSecrets is returned when no encrypted secrets are found for a key package.
	ErrWelcomeNoEncryptedSecrets = errors.New("group: no encrypted secrets found for key package")
	// ErrWelcomeMissingPSK is returned when a PSK is required but not provided.
	ErrWelcomeMissingPSK = errors.New("group: PSK required but not provided")
	// ErrWelcomePSKNotFound is returned when a PSK is not found in the store.
	ErrWelcomePSKNotFound = errors.New("group: PSK not found in store")
	// ErrWelcomeInvalidPSK is returned when a PSK is invalid.
	ErrWelcomeInvalidPSK = errors.New("group: PSK is invalid")
	// ErrWelcomeInvalidGroupSecrets is returned when group secrets are invalid.
	ErrWelcomeInvalidGroupSecrets = errors.New("group: invalid group secrets")
	// ErrWelcomeJoinerSecretMissing is returned when the joiner secret is nil.
	ErrWelcomeJoinerSecretMissing = errors.New("group: joiner secret is nil")
	// ErrGroupInfoUnmarshal is returned when group info cannot be unmarshaled.
	ErrGroupInfoUnmarshal = errors.New("group: cannot unmarshal group info")
	// ErrRatchetTreeUnmarshal is returned when the ratchet tree cannot be unmarshaled.
	ErrRatchetTreeUnmarshal = errors.New("group: cannot unmarshal ratchet tree")
	// ErrLeafNodeInvalid is returned when a leaf node is invalid.
	ErrLeafNodeInvalid = errors.New("group: leaf node is invalid")
	// ErrUnmergedLeavesInvalid is returned when an unmerged_leaves entry is invalid.
	ErrUnmergedLeavesInvalid = errors.New("group: unmerged_leaves entry is invalid")
	// ErrRequiredExtensionMissing is returned when a required extension is not supported.
	ErrRequiredExtensionMissing = errors.New("group: required extension not supported")
	// ErrJoinerLeafNotFound is returned when the joiner leaf is not found in the ratchet tree.
	ErrJoinerLeafNotFound = errors.New("group: joiner leaf not found in ratchet tree")

	// ErrTreeHashMismatch is returned when the tree hash does not match.
	ErrTreeHashMismatch = errors.New("group: tree hash mismatch")
	// ErrConfirmationTagMismatch is returned when the confirmation tag does not match.
	ErrConfirmationTagMismatch = errors.New("group: confirmation tag mismatch")
	// ErrGroupInfoNil is returned when group info is nil.
	ErrGroupInfoNil = errors.New("group: group info is nil")
	// ErrRatchetTreeNil is returned when the ratchet tree is nil.
	ErrRatchetTreeNil = errors.New("group: ratchet tree is nil")
	// ErrSignerLeafMissing is returned when the signer leaf is missing in the ratchet tree.
	ErrSignerLeafMissing = errors.New("group: signer leaf missing in ratchet tree")
	// ErrSignerKeyMissing is returned when the signer signature key is missing.
	ErrSignerKeyMissing = errors.New("group: signer signature key missing")
)
