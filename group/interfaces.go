package group

import (
	"context"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
)

// CredentialValidator validates credentials before they are admitted to a group.
//
// Applications can use this hook to enforce custom trust policies such as
// identity allowlists, external PKI validation, or credential type checks.
type CredentialValidator interface {
	ValidateCredential(ctx context.Context, credential *credentials.Credential) error
}

// GroupStorage persists serialized group state outside of process memory.
//
// The library's MarshalState and UnmarshalGroupState helpers make this easy to
// back with files, databases, or secret storage systems.
type GroupStorage interface {
	SaveGroupState(ctx context.Context, groupID *GroupID, state []byte) error
	LoadGroupState(ctx context.Context, groupID *GroupID) ([]byte, error)
	DeleteGroupState(ctx context.Context, groupID *GroupID) error
}

// KeyStore provides application-managed private key material for MLS state.
//
// This interface is intentionally minimal so callers can back it with HSMs,
// KMS systems, encrypted files, or in-memory test doubles.
type KeyStore interface {
	StoreSignatureKey(ctx context.Context, groupID *GroupID, key *ciphersuite.SignaturePrivateKey) error
	LoadSignatureKey(ctx context.Context, groupID *GroupID) (*ciphersuite.SignaturePrivateKey, error)
	StoreLeafEncryptionKey(ctx context.Context, groupID *GroupID, leafIndex LeafNodeIndex, key []byte) error
	LoadLeafEncryptionKey(ctx context.Context, groupID *GroupID, leafIndex LeafNodeIndex) ([]byte, error)
}
