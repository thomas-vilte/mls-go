package group

import (
	"errors"
	"fmt"
)

// Typed errors for semantic error handling
// These errors contain context about the failure.

// ErrEpochMismatch se retorna cuando un mensaje es de una epoch incorrecta.
type ErrEpochMismatch struct {
	Got  uint64
	Want uint64
}

func (e *ErrEpochMismatch) Error() string {
	return fmt.Sprintf("group: epoch mismatch: message has %d, group is at %d", e.Got, e.Want)
}

// ErrGroupIDMismatch se retorna cuando un mensaje tiene un GroupID incorrecto.
type ErrGroupIDMismatch struct {
	Got  []byte
	Want []byte
}

func (e *ErrGroupIDMismatch) Error() string {
	return fmt.Sprintf("group: group ID mismatch: message has %x, group is at %x", e.Got, e.Want)
}

// ErrInvalidSignature se retorna cuando una firma no verifica.
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

// ErrUnknownMember se retorna cuando el leaf index no existe en el árbol.
type ErrUnknownMember struct {
	LeafIndex uint32
}

func (e *ErrUnknownMember) Error() string {
	return fmt.Sprintf("group: unknown member or out of bounds leaf index: %d", e.LeafIndex)
}

// ErrDecryptionFailed se retorna cuando el descifrado AEAD falla.
// Puede indicar un mensaje adulterado, una clave incorrecta o un replay.
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
	// Proposal errors
	ErrNilProposal                       = errors.New("group: proposal is nil")
	ErrInvalidProposal                   = errors.New("group: invalid proposal")
	ErrUnsupportedProposalType           = errors.New("group: proposal type not supported")
	ErrUnknownProposalType               = errors.New("group: unknown proposal type")
	ErrNilAddProposal                    = errors.New("group: add proposal is nil")
	ErrNilUpdateProposal                 = errors.New("group: update proposal is nil")
	ErrNilRemoveProposal                 = errors.New("group: remove proposal is nil")
	ErrNilPreSharedKeyProposal           = errors.New("group: pre-shared key proposal is nil")
	ErrNilReInitProposal                 = errors.New("group: reinit proposal is nil")
	ErrNilExternalInitProposal           = errors.New("group: external init proposal is nil")
	ErrNilGroupContextExtensionsProposal = errors.New("group: group context extensions proposal is nil")

	// KeyPackage and leaf errors
	ErrNilKeyPackage = errors.New("group: key package is nil")
	ErrNilLeafNode   = errors.New("group: leaf node is nil")

	// Group state errors
	ErrGroupNotOperational         = errors.New("group: not operational")
	ErrPendingProposals            = errors.New("group: proposals pending")
	ErrEmptyGroupID                = errors.New("group: group ID is empty")
	ErrInvalidGroupState           = errors.New("group: invalid group state")
	ErrUnknownEpoch                = errors.New("group: unknown epoch")
	ErrNilPrivateMessage           = errors.New("group: private message is nil")
	ErrNilSignaturePrivateKey      = errors.New("group: signature private key is nil")
	ErrSenderDataSecretMissing     = errors.New("group: sender_data_secret not available")
	ErrSecretTreeMissing           = errors.New("group: secret tree not available")
	ErrRatchetTreeMissing          = errors.New("group: ratchet tree not available")
	ErrSenderNotActive             = errors.New("group: sender is not an active member")
	ErrMissingSenderSignature      = errors.New("group: missing sender signature key")
	ErrNotApplicationData          = errors.New("group: message is not application data")
	ErrNoPendingCommit             = errors.New("group: no pending commit to discard")
	ErrNotACommit                  = errors.New("group: not a commit message")
	ErrMissingAuthenticatedContent = errors.New("group: missing authenticated content")
	ErrUnknownProposalRef          = errors.New("group: unknown proposal reference in commit")
	ErrOwnLeafNotFound             = errors.New("group: own leaf not found in ratchet tree")

	// Welcome/Join errors
	ErrWelcomeNoEncryptedSecrets  = errors.New("group: no encrypted secrets found for key package")
	ErrWelcomeMissingPSK          = errors.New("group: PSK required but not provided")
	ErrWelcomePSKNotFound         = errors.New("group: PSK not found in store")
	ErrWelcomeInvalidPSK          = errors.New("group: PSK is invalid")
	ErrWelcomeInvalidGroupSecrets = errors.New("group: invalid group secrets")
	ErrWelcomeJoinerSecretMissing = errors.New("group: joiner secret is nil")
	ErrGroupInfoUnmarshal         = errors.New("group: cannot unmarshal group info")
	ErrRatchetTreeUnmarshal       = errors.New("group: cannot unmarshal ratchet tree")
	ErrLeafNodeInvalid            = errors.New("group: leaf node is invalid")
	ErrUnmergedLeavesInvalid      = errors.New("group: unmerged_leaves entry is invalid")
	ErrRequiredExtensionMissing   = errors.New("group: required extension not supported")
	ErrJoinerLeafNotFound         = errors.New("group: joiner leaf not found in ratchet tree")

	// State validation errors
	ErrTreeHashMismatch        = errors.New("group: tree hash mismatch")
	ErrConfirmationTagMismatch = errors.New("group: confirmation tag mismatch")
	ErrGroupInfoNil            = errors.New("group: group info is nil")
	ErrRatchetTreeNil          = errors.New("group: ratchet tree is nil")
	ErrSignerLeafMissing       = errors.New("group: signer leaf missing in ratchet tree")
	ErrSignerKeyMissing        = errors.New("group: signer signature key missing")
)
