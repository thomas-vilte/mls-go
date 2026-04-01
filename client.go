package mls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/keypackages"
	filestore "github.com/thomas-vilte/mls-go/storage/file"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
	"github.com/thomas-vilte/mls-go/treesync"
)

type clientStore interface {
	group.GroupStorage
	group.KeyStore
}

type combinedStore struct {
	group.GroupStorage
	group.KeyStore
}

func (s combinedStore) Close() error {
	var firstErr error
	if closer, ok := s.GroupStorage.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			firstErr = err
		}
	}
	if closer, ok := s.KeyStore.(io.Closer); ok {
		// Avoid double-closing when both interfaces are backed by the same object.
		if any(s.GroupStorage) != any(s.KeyStore) {
			if err := closer.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

type clientConfig struct {
	storage             clientStore
	credentialValidator group.CredentialValidator
	eventHandler        EventHandler
	paddingSize         int
	cacheStrategy       CacheStrategy
	credentialWithKey   *credentials.CredentialWithKey
	sigKey              *ciphersuite.SignaturePrivateKey
}

// ClientOption configures optional Client behavior.
type ClientOption func(*clientConfig)

// WithStorage overrides the default in-memory group/key storage.
func WithStorage(gs group.GroupStorage, ks group.KeyStore) ClientOption {
	return func(cfg *clientConfig) {
		if cfg == nil || gs == nil || ks == nil {
			return
		}
		cfg.storage = combinedStore{GroupStorage: gs, KeyStore: ks}
	}
}

// WithCredentialValidator validates credentials admitted through Client helpers.
func WithCredentialValidator(v group.CredentialValidator) ClientOption {
	return func(cfg *clientConfig) {
		if cfg == nil {
			return
		}
		cfg.credentialValidator = v
	}
}

// WithPaddingSize sets the padding size used for application messages.
func WithPaddingSize(n int) ClientOption {
	return func(cfg *clientConfig) {
		if cfg == nil {
			return
		}
		if n < 0 {
			n = 0
		}
		cfg.paddingSize = n
	}
}

// WithX509Credential configures the client to use an X.509 credential instead of a basic credential.
//
// This currently supports cipher suites that use ECDSA P-256 signatures.
func WithX509Credential(certDER []byte, privKey *ecdsa.PrivateKey) ClientOption {
	return func(cfg *clientConfig) {
		if cfg == nil || len(certDER) == 0 || privKey == nil {
			return
		}
		credWithKey, err := credentials.GenerateX509CredentialWithKey(certDER, privKey)
		if err != nil {
			return
		}
		cfg.credentialWithKey = credWithKey
		cfg.sigKey = ciphersuite.NewSignaturePrivateKey(privKey)
	}
}

// CacheStrategy controls how the Client caches loaded group state in memory.
type CacheStrategy int

const (
	// CacheNone reloads group state from storage on every operation.
	CacheNone CacheStrategy = iota
	// CacheAlways keeps loaded group state in memory after the first load.
	CacheAlways
)

// WithCacheStrategy sets the in-memory caching strategy for group state.
func WithCacheStrategy(s CacheStrategy) ClientOption {
	return func(cfg *clientConfig) {
		if cfg == nil {
			return
		}
		cfg.cacheStrategy = s
	}
}

// EventType identifies which lifecycle event a GroupEvent describes.
type EventType int

const (
	// EventMemberJoined is emitted when a new member joins the group via Welcome or ExternalJoin.
	EventMemberJoined EventType = iota
	// EventMemberRemoved is emitted when a member is removed from the group.
	EventMemberRemoved
	// EventEpochAdvanced is emitted after every commit that advances the group epoch.
	EventEpochAdvanced
	// EventMessageReceived is emitted when an application message is successfully decrypted.
	EventMessageReceived
	// EventSelfUpdated is emitted after a successful SelfUpdate commit.
	EventSelfUpdated
)

// GroupEvent carries information about a group lifecycle event.
type GroupEvent struct {
	Type           EventType
	GroupID        []byte
	Epoch          uint64
	MemberIdentity []byte
}

// EventHandler is called asynchronously in its own goroutine for each group event.
// The handler must not block and must not call any Client methods, as it runs
// concurrently with the Client's internal lock. Use a buffered channel send or
// a non-blocking update for any state that needs to be updated.
type EventHandler func(event GroupEvent)

// WithEventHandler registers a callback for group lifecycle events.
func WithEventHandler(h EventHandler) ClientOption {
	return func(cfg *clientConfig) {
		if cfg == nil {
			return
		}
		cfg.eventHandler = h
	}
}

var (
	// ErrEmptyIdentity is returned when NewClient receives an empty identity slice.
	ErrEmptyIdentity = errors.New("mls: identity is empty")
	// ErrEmptyGroupID is returned when a group operation receives an empty group ID.
	ErrEmptyGroupID = errors.New("mls: group ID is empty")
	// ErrEmptyKeyPackage is returned when InviteMember receives empty key package bytes.
	ErrEmptyKeyPackage = errors.New("mls: key package is empty")
	// ErrEmptyWelcome is returned when JoinGroup receives empty welcome bytes.
	ErrEmptyWelcome = errors.New("mls: welcome is empty")
	// ErrEmptyGroupInfo is returned when ExternalJoin receives empty GroupInfo bytes.
	ErrEmptyGroupInfo = errors.New("mls: group info is empty")
	// ErrEmptyCommit is returned when ProcessCommit receives empty commit bytes.
	ErrEmptyCommit = errors.New("mls: commit is empty")
	// ErrEmptyCiphertext is returned when ReceiveMessage receives empty ciphertext bytes.
	ErrEmptyCiphertext = errors.New("mls: ciphertext is empty")
	// ErrGroupNotFound is returned when an operation references a group that has not been joined or created.
	ErrGroupNotFound = errors.New("mls: group not found")
	// ErrNoPendingKeyPackage is returned when JoinGroup is called before FreshKeyPackageBytes.
	ErrNoPendingKeyPackage = errors.New("mls: no pending key package available")
	// ErrUnexpectedMessageType is returned when a parsed MLSMessage does not match the expected wire format.
	ErrUnexpectedMessageType = errors.New("mls: unexpected MLS message type")
	// ErrMemberNotFound is returned when a member identity cannot be resolved in the target group.
	ErrMemberNotFound = errors.New("mls: member not found")
	// ErrClientClosed is returned when a closed Client is used.
	ErrClientClosed = errors.New("mls: client is closed")
)

// ErrEpochMismatch is a type alias for group.ErrEpochMismatch, surfaced at the Client level.
type ErrEpochMismatch = group.ErrEpochMismatch

// ErrGroupIDMismatch is a type alias for group.ErrGroupIDMismatch, surfaced at the Client level.
type ErrGroupIDMismatch = group.ErrGroupIDMismatch

// ErrInvalidSignature is a type alias for group.ErrInvalidSignature, surfaced at the Client level.
type ErrInvalidSignature = group.ErrInvalidSignature

// ErrUnknownMember is a type alias for group.ErrUnknownMember, surfaced at the Client level.
type ErrUnknownMember = group.ErrUnknownMember

// ErrDecryptionFailed is a type alias for group.ErrDecryptionFailed, surfaced at the Client level.
type ErrDecryptionFailed = group.ErrDecryptionFailed

// IsEpochMismatch reports whether err contains an ErrEpochMismatch.
func IsEpochMismatch(err error) bool {
	var target *group.ErrEpochMismatch
	return errors.As(err, &target)
}

// IsGroupIDMismatch reports whether err contains an ErrGroupIDMismatch.
func IsGroupIDMismatch(err error) bool {
	var target *group.ErrGroupIDMismatch
	return errors.As(err, &target)
}

// IsInvalidSignature reports whether err contains an ErrInvalidSignature.
func IsInvalidSignature(err error) bool {
	var target *group.ErrInvalidSignature
	return errors.As(err, &target)
}

// IsUnknownMember reports whether err contains an ErrUnknownMember.
func IsUnknownMember(err error) bool {
	var target *group.ErrUnknownMember
	return errors.As(err, &target)
}

// IsDecryptionFailed reports whether err contains an ErrDecryptionFailed.
func IsDecryptionFailed(err error) bool {
	var target *group.ErrDecryptionFailed
	return errors.As(err, &target)
}

// ReceivedMessage is the result of a successful ReceiveMessage or ReceiveMessageWithAAD call.
type ReceivedMessage struct {
	Plaintext         []byte
	AuthenticatedData []byte
	SenderIdentity    []byte
	SenderLeafIdx     uint32
}

// MemberInfo describes a single active member in an MLS group.
type MemberInfo struct {
	LeafIndex  uint32
	Identity   []byte
	SigningKey []byte
}

// groupEntry holds a per-group mutex and optional cached group state.
// The mutex serializes all operations on a single group, allowing concurrent
// operations on different groups to proceed independently.
type groupEntry struct {
	mu    sync.Mutex
	group *group.Group // non-nil only when cacheStrategy == CacheAlways
}

// Client is a high-level, thread-safe facade over the low-level MLS group API.
//
// The Client uses lock striping: a global mutex (mu) protects the map of group
// entries and the pending key packages, while each group entry carries its own
// mutex that serializes operations on that particular group. This allows N groups
// to perform cryptographic operations concurrently.
type Client struct {
	// mu protects closed, pendingKPs, and groupEntries.
	// It is held only for map reads/writes, never during cryptographic operations.
	mu sync.Mutex

	identity []byte
	cs       ciphersuite.CipherSuite

	// These fields are immutable after NewClient returns. Close() does not nil
	// them because in-flight per-group operations may still reference them after
	// the brief global lock section completes.
	credWithKey   *credentials.CredentialWithKey
	sigKey        *ciphersuite.SignaturePrivateKey
	store         clientStore
	validator     group.CredentialValidator
	paddingSize   int
	cacheStrategy CacheStrategy

	events EventHandler
	closed bool

	pendingKPs   map[string]*pendingEntry
	groupEntries map[string]*groupEntry
}

type pendingEntry struct {
	kp      *keypackages.KeyPackage
	kpPriv  *keypackages.KeyPackagePrivateKeys
	kpBytes []byte
}

// NewClient creates a new high-level MLS client for a single identity.
func NewClient(identity []byte, cs ciphersuite.CipherSuite, opts ...ClientOption) (*Client, error) {
	cfg := clientConfig{storage: memorystore.NewStore()}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.storage == nil {
		cfg.storage = memorystore.NewStore()
	}
	var (
		credWithKey *credentials.CredentialWithKey
		sigKey      *ciphersuite.SignaturePrivateKey
		err         error
	)
	if cfg.credentialWithKey != nil {
		if cs.SignatureScheme() != ciphersuite.ECDSA_SECP256R1_SHA256 {
			return nil, fmt.Errorf("X.509 credentials require an ECDSA P-256 cipher suite")
		}
		credWithKey = cfg.credentialWithKey
		sigKey = cfg.sigKey
	} else {
		if len(identity) == 0 {
			return nil, ErrEmptyIdentity
		}
		credWithKey, sigKey, err = credentials.GenerateCredentialWithKeyForCS(identity, cs)
		if err != nil {
			return nil, fmt.Errorf("generating client identity: %w", err)
		}
	}
	clientIdentity := append([]byte(nil), identity...)
	if len(clientIdentity) == 0 {
		clientIdentity = credentialIdentityBytes(credWithKey.Credential)
	}

	return &Client{
		identity:      clientIdentity,
		cs:            cs,
		credWithKey:   credWithKey,
		sigKey:        sigKey,
		store:         cfg.storage,
		validator:     cfg.credentialValidator,
		events:        cfg.eventHandler,
		paddingSize:   cfg.paddingSize,
		cacheStrategy: cfg.cacheStrategy,
		pendingKPs:    make(map[string]*pendingEntry),
		groupEntries:  make(map[string]*groupEntry),
	}, nil
}

// FreshKeyPackageBytes generates a fresh single-use KeyPackage for invitations.
func (c *Client) FreshKeyPackageBytes(ctx context.Context) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	kp, kpPriv, err := keypackages.Generate(c.credWithKey, c.cs)
	if err != nil {
		return nil, fmt.Errorf("generating key package: %w", err)
	}

	kpBytes := kp.Marshal()
	c.pendingKPs[keyPackageFingerprint(kpBytes)] = &pendingEntry{
		kp:      kp,
		kpPriv:  kpPriv,
		kpBytes: cloneBytes(kpBytes),
	}

	return kpBytes, nil
}

// CreateGroup creates a fresh one-member MLS group and returns its group ID.
func (c *Client) CreateGroup(ctx context.Context) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	groupID, err := group.NewGroupIDRandom()
	if err != nil {
		return nil, fmt.Errorf("generating group ID: %w", err)
	}
	kp, kpPriv, err := keypackages.Generate(c.credWithKey, c.cs)
	if err != nil {
		return nil, fmt.Errorf("generating creator key package: %w", err)
	}
	g, err := group.NewGroup(groupID, c.cs, kp, kpPriv)
	if err != nil {
		return nil, fmt.Errorf("creating group: %w", err)
	}
	g.SetPaddingSize(c.paddingSize)
	entry := &groupEntry{}
	if err := c.persistGroup(ctx, g, entry); err != nil {
		return nil, err
	}
	c.groupEntries[groupCacheKey(groupID)] = entry
	return cloneBytes(groupID.AsSlice()), nil
}

// InviteMember adds a member and returns the commit bytes to broadcast plus the welcome bytes for the joiner.
func (c *Client) InviteMember(ctx context.Context, groupID, memberKeyPackageBytes []byte) (commit, welcome []byte, err error) {
	if len(memberKeyPackageBytes) == 0 {
		return nil, nil, ErrEmptyKeyPackage
	}

	c.mu.Lock()
	if err := c.checkOpen(); err != nil {
		c.mu.Unlock()
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return nil, nil, err
	}
	entry := c.getOrCreateEntryLocked(groupCacheKeyBytes(groupID))
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	g, err := c.loadGroupEntry(ctx, groupID, entry)
	if err != nil {
		return nil, nil, err
	}

	memberKP, err := keypackages.UnmarshalKeyPackage(memberKeyPackageBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshaling member key package: %w", err)
	}
	if err := c.validateCredential(ctx, memberKP.LeafNode.Credential); err != nil {
		return nil, nil, err
	}

	if _, err := g.AddMember(memberKP); err != nil {
		return nil, nil, fmt.Errorf("adding member: %w", err)
	}
	return c.commitPendingProposals(ctx, g, entry)
}

// JoinGroup joins a group using the most recently generated pending KeyPackage.
func (c *Client) JoinGroup(ctx context.Context, welcomeBytes []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(welcomeBytes) == 0 {
		return nil, ErrEmptyWelcome
	}
	if len(c.pendingKPs) == 0 {
		return nil, ErrNoPendingKeyPackage
	}
	welcome, err := parseWelcomeBytes(welcomeBytes)
	if err != nil {
		return nil, err
	}

	var joinedGroup *group.Group
	var matchKey string
	var joinMatchErr error
	for key, pe := range c.pendingKPs {
		g, joinErr := group.JoinFromWelcomeWithContext(ctx, welcome, pe.kp, pe.kpPriv, nil)
		if joinErr != nil {
			continue
		}
		if err := c.validateGroupMembers(ctx, g); err != nil {
			joinMatchErr = err
			continue
		}
		g.SetPaddingSize(c.paddingSize)
		joinedGroup = g
		matchKey = key
		break
	}
	if joinedGroup == nil {
		if joinMatchErr != nil {
			return nil, joinMatchErr
		}
		return nil, ErrNoPendingKeyPackage
	}
	entry := &groupEntry{}
	if err := c.persistGroup(ctx, joinedGroup, entry); err != nil {
		return nil, err
	}
	c.groupEntries[groupCacheKey(joinedGroup.GroupID())] = entry
	delete(c.pendingKPs, matchKey)
	return cloneBytes(joinedGroup.GroupID().AsSlice()), nil
}

// ProposeAddMember stores an Add proposal locally and returns a signed PublicMessage.
func (c *Client) ProposeAddMember(ctx context.Context, groupID, memberKPBytes []byte) ([]byte, error) {
	if len(memberKPBytes) == 0 {
		return nil, ErrEmptyKeyPackage
	}

	c.mu.Lock()
	if err := c.checkOpen(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	entry := c.getOrCreateEntryLocked(groupCacheKeyBytes(groupID))
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	g, err := c.loadGroupEntry(ctx, groupID, entry)
	if err != nil {
		return nil, err
	}
	memberKP, err := keypackages.UnmarshalKeyPackage(memberKPBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling member key package: %w", err)
	}
	if err := c.validateCredential(ctx, memberKP.LeafNode.Credential); err != nil {
		return nil, err
	}
	proposal, err := g.AddMember(memberKP)
	if err != nil {
		return nil, fmt.Errorf("adding member proposal: %w", err)
	}
	msg, err := g.SignProposalAsPublicMessage(proposal, c.sigKey)
	if err != nil {
		return nil, fmt.Errorf("signing add proposal: %w", err)
	}
	if err := c.persistGroup(ctx, g, entry); err != nil {
		return nil, err
	}
	return msg, nil
}

// ProposeRemoveMember stores a Remove proposal locally and returns a signed PublicMessage.
func (c *Client) ProposeRemoveMember(ctx context.Context, groupID, memberIdentity []byte) ([]byte, error) {
	c.mu.Lock()
	if err := c.checkOpen(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	entry := c.getOrCreateEntryLocked(groupCacheKeyBytes(groupID))
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	g, err := c.loadGroupEntry(ctx, groupID, entry)
	if err != nil {
		return nil, err
	}
	leafIndex, err := findMemberLeafIndexByIdentity(g, memberIdentity)
	if err != nil {
		return nil, err
	}
	proposal, err := g.RemoveMember(leafIndex)
	if err != nil {
		return nil, fmt.Errorf("creating remove proposal: %w", err)
	}
	msg, err := g.SignProposalAsPublicMessage(proposal, c.sigKey)
	if err != nil {
		return nil, fmt.Errorf("signing remove proposal: %w", err)
	}
	if err := c.persistGroup(ctx, g, entry); err != nil {
		return nil, err
	}
	return msg, nil
}

// CommitPendingProposals commits all currently stored proposals in one operation.
func (c *Client) CommitPendingProposals(ctx context.Context, groupID []byte) (commit, welcome []byte, err error) {
	c.mu.Lock()
	if err := c.checkOpen(); err != nil {
		c.mu.Unlock()
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return nil, nil, err
	}
	entry := c.getOrCreateEntryLocked(groupCacheKeyBytes(groupID))
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	g, err := c.loadGroupEntry(ctx, groupID, entry)
	if err != nil {
		return nil, nil, err
	}
	return c.commitPendingProposals(ctx, g, entry)
}

// ProcessCommit applies a commit from another existing group member.
func (c *Client) ProcessCommit(ctx context.Context, groupID, commitBytes []byte) error {
	if len(commitBytes) == 0 {
		return ErrEmptyCommit
	}

	c.mu.Lock()
	if err := c.checkOpen(); err != nil {
		c.mu.Unlock()
		return err
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return err
	}
	entry := c.getOrCreateEntryLocked(groupCacheKeyBytes(groupID))
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	g, err := c.loadGroupEntry(ctx, groupID, entry)
	if err != nil {
		return err
	}
	msg, err := framing.UnmarshalMLSMessage(commitBytes)
	if err != nil {
		return fmt.Errorf("parsing commit message: %w", err)
	}
	var ac *framing.AuthenticatedContent
	var senderLeafIdx treesync.LeafIndex
	if pubMsg, ok := msg.AsPublic(); ok {
		if g.EpochSecrets() != nil && g.EpochSecrets().MembershipKey != nil {
			if err := pubMsg.VerifyMembershipTagWithContext(
				g.CipherSuite(),
				g.EpochSecrets().MembershipKey,
				g.GroupContext().Marshal(),
			); err != nil {
				return fmt.Errorf("verifying membership tag: %w", err)
			}
		}
		ac = &framing.AuthenticatedContent{
			WireFormat:   framing.WireFormatPublicMessage,
			Content:      pubMsg.Content,
			Auth:         pubMsg.Auth,
			GroupContext: g.GroupContext().Marshal(),
		}
		senderLeafIdx = treesync.LeafIndex(pubMsg.Content.Sender.LeafIndex)
	} else if privMsg, ok := msg.AsPrivate(); ok {
		if g.EpochSecrets() == nil || g.EpochSecrets().SenderDataSecret == nil {
			return fmt.Errorf("sender_data_secret not available for private commit")
		}
		if g.SecretTree() == nil {
			return fmt.Errorf("secret tree not available for private commit")
		}
		decrypted, err := framing.Decrypt(privMsg, framing.DecryptParams{
			CipherSuite:      g.CipherSuite(),
			SenderDataSecret: g.EpochSecrets().SenderDataSecret,
			SecretTree:       g.SecretTree(),
			GroupContext:     g.GroupContext().Marshal(),
		})
		if err != nil {
			return fmt.Errorf("decrypting private commit: %w", err)
		}
		ac = decrypted
		ac.WireFormat = framing.WireFormatPrivateMessage
		senderLeafIdx = treesync.LeafIndex(ac.Content.Sender.LeafIndex)
	} else {
		return ErrUnexpectedMessageType
	}
	if err := g.ProcessReceivedCommit(ac, senderLeafIdx, g.MyLeafEncryptionKey()); err != nil {
		return fmt.Errorf("processing received commit: %w", err)
	}
	return c.persistGroup(ctx, g, entry)
}

// SendMessage encrypts an application message for the given group.
func (c *Client) SendMessage(ctx context.Context, groupID, plaintext []byte) ([]byte, error) {
	c.mu.Lock()
	if err := c.checkOpen(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	entry := c.getOrCreateEntryLocked(groupCacheKeyBytes(groupID))
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	g, err := c.loadGroupEntry(ctx, groupID, entry)
	if err != nil {
		return nil, err
	}
	pm, err := g.SendMessage(plaintext, c.sigKey)
	if err != nil {
		return nil, fmt.Errorf("sending message: %w", err)
	}
	if err := c.persistGroup(ctx, g, entry); err != nil {
		return nil, err
	}
	return framing.NewMLSMessagePrivate(pm).Marshal(), nil
}

// SendMessageWithAAD encrypts an application message with authenticated associated data.
func (c *Client) SendMessageWithAAD(ctx context.Context, groupID, plaintext, authenticatedData []byte) ([]byte, error) {
	c.mu.Lock()
	if err := c.checkOpen(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	entry := c.getOrCreateEntryLocked(groupCacheKeyBytes(groupID))
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	g, err := c.loadGroupEntry(ctx, groupID, entry)
	if err != nil {
		return nil, err
	}
	pm, err := g.SendApplicationMessage(plaintext, authenticatedData, c.sigKey)
	if err != nil {
		return nil, fmt.Errorf("sending message with AAD: %w", err)
	}
	if err := c.persistGroup(ctx, g, entry); err != nil {
		return nil, err
	}
	return framing.NewMLSMessagePrivate(pm).Marshal(), nil
}

// ReceiveMessage decrypts an application message for the given group.
func (c *Client) ReceiveMessage(ctx context.Context, groupID, ciphertextBytes []byte) (*ReceivedMessage, error) {
	if len(ciphertextBytes) == 0 {
		return nil, ErrEmptyCiphertext
	}

	c.mu.Lock()
	if err := c.checkOpen(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	entry := c.getOrCreateEntryLocked(groupCacheKeyBytes(groupID))
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	g, err := c.loadGroupEntry(ctx, groupID, entry)
	if err != nil {
		return nil, err
	}
	msg, err := framing.UnmarshalMLSMessage(ciphertextBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing ciphertext: %w", err)
	}
	pm, ok := msg.AsPrivate()
	if !ok {
		return nil, ErrUnexpectedMessageType
	}
	plaintext, authenticatedData, senderLeafIdx, err := g.ReceiveApplicationMessage(pm)
	if err != nil {
		return nil, fmt.Errorf("receiving message: %w", err)
	}
	member, ok := g.GetMember(group.LeafNodeIndex(senderLeafIdx))
	if !ok || member == nil {
		return nil, fmt.Errorf("sender %d not found in group", senderLeafIdx)
	}
	if err := c.persistGroup(ctx, g, entry); err != nil {
		return nil, err
	}
	received := &ReceivedMessage{
		Plaintext:         cloneBytes(plaintext),
		AuthenticatedData: cloneBytes(authenticatedData),
		SenderIdentity:    credentialIdentityBytes(member.Credential),
		SenderLeafIdx:     uint32(senderLeafIdx),
	}
	c.emitEvent(GroupEvent{
		Type:           EventMessageReceived,
		GroupID:        g.GroupID().AsSlice(),
		Epoch:          g.Epoch().AsUint64(),
		MemberIdentity: received.SenderIdentity,
	})
	return received, nil
}

// RemoveMember removes a member by credential identity and returns the commit bytes to broadcast.
func (c *Client) RemoveMember(ctx context.Context, groupID, memberIdentity []byte) ([]byte, error) {
	c.mu.Lock()
	if err := c.checkOpen(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	entry := c.getOrCreateEntryLocked(groupCacheKeyBytes(groupID))
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	g, err := c.loadGroupEntry(ctx, groupID, entry)
	if err != nil {
		return nil, err
	}
	leafIndex, err := findMemberLeafIndexByIdentity(g, memberIdentity)
	if err != nil {
		return nil, err
	}
	if _, err := g.RemoveMember(leafIndex); err != nil {
		return nil, fmt.Errorf("creating remove proposal: %w", err)
	}
	commit, err := c.commitCurrentState(ctx, g, entry, "creating remove commit")
	if err != nil {
		return nil, err
	}
	c.emitEvent(GroupEvent{Type: EventMemberRemoved, GroupID: g.GroupID().AsSlice(), Epoch: g.Epoch().AsUint64(), MemberIdentity: memberIdentity})
	c.emitEvent(GroupEvent{Type: EventEpochAdvanced, GroupID: g.GroupID().AsSlice(), Epoch: g.Epoch().AsUint64()})
	return commit, nil
}

// SelfUpdate rotates the local member's leaf encryption key and returns the commit bytes to broadcast.
func (c *Client) SelfUpdate(ctx context.Context, groupID []byte) ([]byte, error) {
	c.mu.Lock()
	if err := c.checkOpen(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	entry := c.getOrCreateEntryLocked(groupCacheKeyBytes(groupID))
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	g, err := c.loadGroupEntry(ctx, groupID, entry)
	if err != nil {
		return nil, err
	}
	if _, err := g.SelfUpdate(c.sigKey); err != nil {
		return nil, fmt.Errorf("creating self-update proposal: %w", err)
	}
	commit, err := c.commitCurrentState(ctx, g, entry, "creating self-update commit")
	if err != nil {
		return nil, err
	}
	c.emitEvent(GroupEvent{Type: EventSelfUpdated, GroupID: g.GroupID().AsSlice(), Epoch: g.Epoch().AsUint64(), MemberIdentity: cloneBytes(c.identity)})
	c.emitEvent(GroupEvent{Type: EventEpochAdvanced, GroupID: g.GroupID().AsSlice(), Epoch: g.Epoch().AsUint64()})
	return commit, nil
}

// LeaveGroup deletes the local persisted state for the group.
//
// The low-level group package currently rejects self-remove proposals from the
// committer, so this helper performs a local leave only. No commit is produced.
func (c *Client) LeaveGroup(ctx context.Context, groupID []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkOpen(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(groupID) == 0 {
		return ErrEmptyGroupID
	}
	cacheKey := groupCacheKeyBytes(groupID)
	gID := group.NewGroupID(cloneBytes(groupID))
	if err := c.store.DeleteGroupState(ctx, gID); err != nil {
		return fmt.Errorf("deleting group state: %w", err)
	}
	delete(c.groupEntries, cacheKey)
	return nil
}

// Epoch returns the current epoch number of the group.
func (c *Client) Epoch(ctx context.Context, groupID []byte) (uint64, error) {
	c.mu.Lock()
	if err := c.checkOpen(); err != nil {
		c.mu.Unlock()
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return 0, err
	}
	entry := c.getOrCreateEntryLocked(groupCacheKeyBytes(groupID))
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	g, err := c.loadGroupEntry(ctx, groupID, entry)
	if err != nil {
		return 0, err
	}
	return g.Epoch().AsUint64(), nil
}

// OwnLeafIndex returns the caller's leaf index in the ratchet tree for the given group.
func (c *Client) OwnLeafIndex(ctx context.Context, groupID []byte) (uint32, error) {
	c.mu.Lock()
	if err := c.checkOpen(); err != nil {
		c.mu.Unlock()
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return 0, err
	}
	entry := c.getOrCreateEntryLocked(groupCacheKeyBytes(groupID))
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	g, err := c.loadGroupEntry(ctx, groupID, entry)
	if err != nil {
		return 0, err
	}
	return uint32(g.OwnLeafIndex()), nil
}

// CancelPendingProposals discards all locally stored proposals without committing them.
// This is useful when the application decides to abort a batch of membership changes.
func (c *Client) CancelPendingProposals(ctx context.Context, groupID []byte) error {
	c.mu.Lock()
	if err := c.checkOpen(); err != nil {
		c.mu.Unlock()
		return err
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return err
	}
	entry := c.getOrCreateEntryLocked(groupCacheKeyBytes(groupID))
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	g, err := c.loadGroupEntry(ctx, groupID, entry)
	if err != nil {
		return err
	}
	g.ClearProposals()
	return c.persistGroup(ctx, g, entry)
}

// ListMembers returns all active members in the group.
func (c *Client) ListMembers(ctx context.Context, groupID []byte) ([]MemberInfo, error) {
	c.mu.Lock()
	if err := c.checkOpen(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	entry := c.getOrCreateEntryLocked(groupCacheKeyBytes(groupID))
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	g, err := c.loadGroupEntry(ctx, groupID, entry)
	if err != nil {
		return nil, err
	}
	members := g.GetMembers()
	out := make([]MemberInfo, 0, len(members))
	for _, member := range members {
		out = append(out, memberInfoFromGroup(g, member))
	}
	return out, nil
}

// Export derives exporter secret material for the current epoch.
func (c *Client) Export(ctx context.Context, groupID []byte, label string, exportContext []byte, length int) ([]byte, error) {
	c.mu.Lock()
	if err := c.checkOpen(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	entry := c.getOrCreateEntryLocked(groupCacheKeyBytes(groupID))
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	g, err := c.loadGroupEntry(ctx, groupID, entry)
	if err != nil {
		return nil, err
	}
	secret, err := g.Export(label, exportContext, length)
	if err != nil {
		return nil, fmt.Errorf("exporting secret: %w", err)
	}
	return cloneBytes(secret), nil
}

// EpochAuthenticator returns the epoch authenticator for the current epoch.
func (c *Client) EpochAuthenticator(ctx context.Context, groupID []byte) ([]byte, error) {
	c.mu.Lock()
	if err := c.checkOpen(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	entry := c.getOrCreateEntryLocked(groupCacheKeyBytes(groupID))
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	g, err := c.loadGroupEntry(ctx, groupID, entry)
	if err != nil {
		return nil, err
	}
	return cloneBytes(g.EpochAuthenticator()), nil
}

// GroupInfo returns a signed GroupInfo structure encoded as bytes.
func (c *Client) GroupInfo(ctx context.Context, groupID []byte) ([]byte, error) {
	c.mu.Lock()
	if err := c.checkOpen(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	entry := c.getOrCreateEntryLocked(groupCacheKeyBytes(groupID))
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	g, err := c.loadGroupEntry(ctx, groupID, entry)
	if err != nil {
		return nil, err
	}
	gi, err := g.GetGroupInfo(c.sigKey)
	if err != nil {
		return nil, fmt.Errorf("building group info: %w", err)
	}
	return gi.Marshal(), nil
}

// ExternalJoin performs an External Commit to join a group without a Welcome.
func (c *Client) ExternalJoin(ctx context.Context, groupInfoBytes []byte) (groupID, commit []byte, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkOpen(); err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if len(groupInfoBytes) == 0 {
		return nil, nil, ErrEmptyGroupInfo
	}
	groupInfo, err := group.UnmarshalGroupInfo(groupInfoBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshaling group info: %w", err)
	}
	g, staged, err := group.ExternalCommit(
		groupInfo,
		groupInfo.GroupContext.CipherSuite,
		c.sigKey,
		c.sigKey.PublicKey(),
		nil,
		c.credWithKey.Credential,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("creating external commit: %w", err)
	}
	if err := c.validateGroupMembers(ctx, g); err != nil {
		return nil, nil, err
	}
	g.SetPaddingSize(c.paddingSize)
	entry := &groupEntry{}
	if err := c.persistGroup(ctx, g, entry); err != nil {
		return nil, nil, err
	}
	c.groupEntries[groupCacheKey(g.GroupID())] = entry
	c.emitEvent(GroupEvent{Type: EventEpochAdvanced, GroupID: g.GroupID().AsSlice(), Epoch: g.Epoch().AsUint64()})
	pm := &framing.PublicMessage{
		Content: staged.AuthenticatedContent().Content,
		Auth:    staged.AuthenticatedContent().Auth,
	}
	return cloneBytes(g.GroupID().AsSlice()), framing.NewMLSMessagePublic(pm).Marshal(), nil
}

// Close releases all resources held by the Client.
// After Close, the Client must not be used.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.identity = nil
	c.pendingKPs = nil
	c.groupEntries = nil
	c.events = nil
	if closer, ok := any(c.store).(io.Closer); ok {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// getOrCreateEntryLocked returns an existing groupEntry for the given cache key,
// or creates and stores a new one. Must be called with c.mu held (write lock).
func (c *Client) getOrCreateEntryLocked(cacheKey string) *groupEntry {
	if entry, ok := c.groupEntries[cacheKey]; ok {
		return entry
	}
	entry := &groupEntry{}
	c.groupEntries[cacheKey] = entry
	return entry
}

// loadGroupEntry loads group state from storage (or the in-memory cache).
// Must be called with entry.mu held.
func (c *Client) loadGroupEntry(ctx context.Context, groupIDBytes []byte, entry *groupEntry) (*group.Group, error) {
	if len(groupIDBytes) == 0 {
		return nil, ErrEmptyGroupID
	}
	if c.cacheStrategy == CacheAlways && entry.group != nil {
		entry.group.SetPaddingSize(c.paddingSize)
		return entry.group, nil
	}
	groupID := group.NewGroupID(cloneBytes(groupIDBytes))
	state, err := c.store.LoadGroupState(ctx, groupID)
	if err != nil {
		if isGroupStateNotFound(err) {
			return nil, ErrGroupNotFound
		}
		return nil, fmt.Errorf("loading group state: %w", err)
	}
	g, err := group.UnmarshalGroupState(state)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling group state: %w", err)
	}
	g.SetPaddingSize(c.paddingSize)
	if c.cacheStrategy == CacheAlways {
		entry.group = g
	}
	return g, nil
}

// persistGroup marshals and saves group state, and updates the in-memory cache.
// For per-group operations this is called with entry.mu held.
// For global-lock operations (CreateGroup, JoinGroup, ExternalJoin) it is called
// with c.mu held exclusively, which also provides the necessary exclusion.
func (c *Client) persistGroup(ctx context.Context, g *group.Group, entry *groupEntry) error {
	state, err := g.MarshalState()
	if err != nil {
		return fmt.Errorf("marshaling group state: %w", err)
	}
	groupID := g.GroupID()
	if err := c.store.SaveGroupState(ctx, groupID, state); err != nil {
		return fmt.Errorf("saving group state: %w", err)
	}
	if err := c.store.StoreSignatureKey(ctx, groupID, c.sigKey); err != nil {
		return fmt.Errorf("saving signature key: %w", err)
	}
	leafKey := g.MyLeafEncryptionKey()
	if len(leafKey) > 0 {
		if err := c.store.StoreLeafEncryptionKey(ctx, groupID, g.OwnLeafIndex(), leafKey); err != nil {
			return fmt.Errorf("saving leaf encryption key: %w", err)
		}
	}
	if c.cacheStrategy == CacheAlways {
		entry.group = g
	}
	return nil
}

func parseWelcomeBytes(data []byte) (*group.Welcome, error) {
	if len(data) == 0 {
		return nil, ErrEmptyWelcome
	}
	msg, err := framing.UnmarshalMLSMessage(data)
	if err == nil {
		if len(msg.Welcome) == 0 {
			return nil, ErrUnexpectedMessageType
		}
		welcome, err := group.UnmarshalWelcome(msg.Welcome)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling welcome: %w", err)
		}
		return welcome, nil
	}
	welcome, rawErr := group.UnmarshalWelcome(data)
	if rawErr != nil {
		return nil, fmt.Errorf("unmarshaling welcome: %w", rawErr)
	}
	return welcome, nil
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

func keyPackageFingerprint(kpBytes []byte) string {
	sum := sha256.Sum256(kpBytes)
	return hex.EncodeToString(sum[:])
}

func groupCacheKey(groupID *group.GroupID) string {
	if groupID == nil {
		return ""
	}
	return groupCacheKeyBytes(groupID.AsSlice())
}

func groupCacheKeyBytes(groupID []byte) string {
	return hex.EncodeToString(groupID)
}

func (c *Client) emitEvent(event GroupEvent) {
	if c == nil || c.events == nil {
		return
	}
	handler := c.events
	cloned := GroupEvent{
		Type:           event.Type,
		GroupID:        cloneBytes(event.GroupID),
		Epoch:          event.Epoch,
		MemberIdentity: cloneBytes(event.MemberIdentity),
	}
	go handler(cloned)
}

func isGroupStateNotFound(err error) bool {
	return errors.Is(err, memorystore.ErrGroupStateNotFound) || errors.Is(err, filestore.ErrGroupStateNotFound)
}

func credentialIdentityBytes(cred *credentials.Credential) []byte {
	if cred == nil {
		return nil
	}

	switch cred.Type() {
	case credentials.BasicCredential:
		return cloneBytes(cred.Identity)
	case credentials.X509Credential:
		if len(cred.Certificates) == 0 {
			return nil
		}
		return cloneBytes(cred.Certificates[0])
	default:
		return nil
	}
}

func memberInfoFromGroup(g *group.Group, member *group.Member) MemberInfo {
	if member == nil {
		return MemberInfo{}
	}
	signingKey := cloneBytes(g.MemberSigningKey(member.LeafIndex))
	if len(signingKey) == 0 && member.KeyPackage != nil && member.KeyPackage.LeafNode != nil {
		signingKey = cloneBytes(member.KeyPackage.LeafNode.SignatureKeyBytes)
	}

	return MemberInfo{
		LeafIndex:  uint32(member.LeafIndex),
		Identity:   credentialIdentityBytes(member.Credential),
		SigningKey: signingKey,
	}
}

func (c *Client) commitCurrentState(ctx context.Context, g *group.Group, entry *groupEntry, errContext string) ([]byte, error) {
	staged, err := g.Commit(c.sigKey, c.sigKey.PublicKey(), nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errContext, err)
	}
	if err := g.MergeCommit(staged); err != nil {
		return nil, fmt.Errorf("merging own commit: %w", err)
	}
	if err := c.persistGroup(ctx, g, entry); err != nil {
		return nil, err
	}
	commitMsg := framing.NewMLSMessagePublic(&framing.PublicMessage{
		Content:       staged.AuthenticatedContent().Content,
		Auth:          staged.AuthenticatedContent().Auth,
		MembershipTag: staged.MembershipTag(),
	})
	return commitMsg.Marshal(), nil
}

func (c *Client) commitPendingProposals(ctx context.Context, g *group.Group, entry *groupEntry) (commit, welcome []byte, err error) {
	joinIdentities := make([][]byte, 0)
	removeIdentities := make([][]byte, 0)
	for _, stored := range g.StoredProposals() {
		if stored.Proposal == nil {
			continue
		}
		switch stored.Proposal.Type {
		case group.ProposalTypeAdd:
			if stored.Proposal.Add != nil && stored.Proposal.Add.KeyPackage != nil && stored.Proposal.Add.KeyPackage.LeafNode != nil {
				joinIdentities = append(joinIdentities, credentialIdentityBytes(stored.Proposal.Add.KeyPackage.LeafNode.Credential))
			}
		case group.ProposalTypeRemove:
			if stored.Proposal.Remove != nil {
				if member, ok := g.GetMember(stored.Proposal.Remove.Removed); ok && member != nil {
					removeIdentities = append(removeIdentities, credentialIdentityBytes(member.Credential))
				}
			}
		}
	}

	staged, err := g.Commit(c.sigKey, c.sigKey.PublicKey(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("creating commit: %w", err)
	}

	var newMemberKPs []*keypackages.KeyPackage
	for _, prop := range staged.Proposals() {
		if prop.Type == group.ProposalTypeAdd && prop.Add != nil {
			newMemberKPs = append(newMemberKPs, prop.Add.KeyPackage)
		}
	}

	joinerSecret := staged.JoinerSecret()
	if err := g.MergeCommit(staged); err != nil {
		return nil, nil, fmt.Errorf("merging own commit: %w", err)
	}

	commitMsg := framing.NewMLSMessagePublic(&framing.PublicMessage{
		Content:       staged.AuthenticatedContent().Content,
		Auth:          staged.AuthenticatedContent().Auth,
		MembershipTag: staged.MembershipTag(),
	})
	commitBytes := commitMsg.Marshal()

	if len(newMemberKPs) == 0 {
		if err := c.persistGroup(ctx, g, entry); err != nil {
			return nil, nil, err
		}
		for _, identity := range removeIdentities {
			c.emitEvent(GroupEvent{Type: EventMemberRemoved, GroupID: g.GroupID().AsSlice(), Epoch: g.Epoch().AsUint64(), MemberIdentity: identity})
		}
		c.emitEvent(GroupEvent{Type: EventEpochAdvanced, GroupID: g.GroupID().AsSlice(), Epoch: g.Epoch().AsUint64()})
		return commitBytes, nil, nil
	}

	welcomeObj, err := g.CreateWelcomeWithOptions(newMemberKPs, group.CreateWelcomeOptions{
		JoinerSecret:  joinerSecret,
		SignerPrivKey: c.sigKey,
		PskIDs:        staged.PskIDs(),
		PskSecret:     staged.RawPskSecret(),
		StagedCommit:  staged,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("creating welcome: %w", err)
	}
	if err := c.persistGroup(ctx, g, entry); err != nil {
		return nil, nil, err
	}
	for _, identity := range joinIdentities {
		c.emitEvent(GroupEvent{Type: EventMemberJoined, GroupID: g.GroupID().AsSlice(), Epoch: g.Epoch().AsUint64(), MemberIdentity: identity})
	}
	for _, identity := range removeIdentities {
		c.emitEvent(GroupEvent{Type: EventMemberRemoved, GroupID: g.GroupID().AsSlice(), Epoch: g.Epoch().AsUint64(), MemberIdentity: identity})
	}
	c.emitEvent(GroupEvent{Type: EventEpochAdvanced, GroupID: g.GroupID().AsSlice(), Epoch: g.Epoch().AsUint64()})
	welcomeMsg := framing.MLSMessage{Welcome: welcomeObj.Marshal()}
	return commitBytes, welcomeMsg.Marshal(), nil
}

func findMemberLeafIndexByIdentity(g *group.Group, memberIdentity []byte) (group.LeafNodeIndex, error) {
	for _, member := range g.GetMembers() {
		if bytes.Equal(credentialIdentityBytes(member.Credential), memberIdentity) {
			return member.LeafIndex, nil
		}
	}
	return 0, ErrMemberNotFound
}

func (c *Client) validateCredential(ctx context.Context, cred *credentials.Credential) error {
	if c.validator == nil || cred == nil {
		return nil
	}
	if err := c.validator.ValidateCredential(ctx, cred); err != nil {
		return fmt.Errorf("validating credential: %w", err)
	}
	return nil
}

func (c *Client) validateGroupMembers(ctx context.Context, g *group.Group) error {
	if c.validator == nil || g == nil {
		return nil
	}
	for _, member := range g.GetMembers() {
		if err := c.validateCredential(ctx, member.Credential); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) checkOpen() error {
	if c == nil || c.closed {
		return ErrClientClosed
	}
	return nil
}
