package group

import "errors"

// Error definitions for proposal validation
var (
	ErrNilProposal                       = errors.New("proposal is nil")
	ErrInvalidProposal                   = errors.New("invalid proposal")
	ErrUnsupportedProposalType           = errors.New("proposal type not supported")
	ErrUnknownProposalType               = errors.New("unknown proposal type")
	ErrNilAddProposal                    = errors.New("add proposal is nil")
	ErrNilUpdateProposal                 = errors.New("update proposal is nil")
	ErrNilRemoveProposal                 = errors.New("remove proposal is nil")
	ErrNilPreSharedKeyProposal           = errors.New("pre-shared key proposal is nil")
	ErrNilReInitProposal                 = errors.New("reinit proposal is nil")
	ErrNilExternalInitProposal           = errors.New("external init proposal is nil")
	ErrNilGroupContextExtensionsProposal = errors.New("group context extensions proposal is nil")
	ErrNilKeyPackage                     = errors.New("key package is nil")
	ErrNilLeafNode                       = errors.New("leaf node is nil")
	ErrEmptyGroupID                      = errors.New("group ID is empty")
	ErrInvalidGroupState                 = errors.New("invalid group state")
	ErrCommitVerificationFailed          = errors.New("commit verification failed")
	ErrConfirmationTagMismatch           = errors.New("confirmation tag mismatch")
	ErrWelcomeDecryptionFailed           = errors.New("welcome decryption failed")
	ErrTreeHashMismatch                  = errors.New("tree hash mismatch")
	ErrInvalidEpoch                      = errors.New("invalid epoch")
)
