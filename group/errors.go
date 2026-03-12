package group

import "errors"

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
	ErrEmptyGroupID             = errors.New("group: group ID is empty")
	ErrInvalidGroupState        = errors.New("group: invalid group state")
	ErrCommitVerificationFailed = errors.New("group: commit verification failed")
	ErrConfirmationTagMismatch  = errors.New("group: confirmation tag mismatch")
	ErrWelcomeDecryptionFailed  = errors.New("group: welcome decryption failed")
	ErrTreeHashMismatch         = errors.New("group: tree hash mismatch")
	ErrInvalidEpoch             = errors.New("group: invalid epoch")
)
