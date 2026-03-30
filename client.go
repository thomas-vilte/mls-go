package mls

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/keypackages"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
	"github.com/thomas-vilte/mls-go/treesync"
)

var (
	ErrEmptyIdentity         = errors.New("mls: identity is empty")
	ErrEmptyGroupID          = errors.New("mls: group ID is empty")
	ErrEmptyKeyPackage       = errors.New("mls: key package is empty")
	ErrEmptyWelcome          = errors.New("mls: welcome is empty")
	ErrEmptyCommit           = errors.New("mls: commit is empty")
	ErrEmptyCiphertext       = errors.New("mls: ciphertext is empty")
	ErrGroupNotFound         = errors.New("mls: group not found")
	ErrNoPendingKeyPackage   = errors.New("mls: no pending key package available")
	ErrUnexpectedMessageType = errors.New("mls: unexpected MLS message type")
)

// Client is a high-level, thread-safe facade over the low-level MLS group API.
type Client struct {
	mu sync.RWMutex

	identity []byte
	cs       ciphersuite.CipherSuite

	credWithKey *credentials.CredentialWithKey
	sigKey      *ciphersuite.SignaturePrivateKey
	store       *memorystore.Store

	pendingKeyPackage *keypackages.KeyPackage
	pendingPrivate    *keypackages.KeyPackagePrivateKeys
}

// NewClient creates a new high-level MLS client for a single identity.
func NewClient(identity []byte, cs ciphersuite.CipherSuite) (*Client, error) {
	if len(identity) == 0 {
		return nil, ErrEmptyIdentity
	}

	credWithKey, sigKey, err := credentials.GenerateCredentialWithKeyForCS(identity, cs)
	if err != nil {
		return nil, fmt.Errorf("generating client identity: %w", err)
	}

	return &Client{
		identity:    append([]byte(nil), identity...),
		cs:          cs,
		credWithKey: credWithKey,
		sigKey:      sigKey,
		store:       memorystore.NewStore(),
	}, nil
}

// FreshKeyPackageBytes generates a fresh single-use KeyPackage for invitations.
func (c *Client) FreshKeyPackageBytes() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	kp, kpPriv, err := keypackages.Generate(c.credWithKey, c.cs)
	if err != nil {
		return nil, fmt.Errorf("generating key package: %w", err)
	}

	c.pendingKeyPackage = kp
	c.pendingPrivate = kpPriv

	return kp.Marshal(), nil
}

// CreateGroup creates a fresh one-member MLS group and returns its group ID.
func (c *Client) CreateGroup() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
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
	if err := c.persistGroupLocked(g); err != nil {
		return nil, err
	}
	return cloneBytes(groupID.AsSlice()), nil
}

// InviteMember adds a member and returns the commit bytes to broadcast plus the welcome bytes for the joiner.
func (c *Client) InviteMember(groupID, memberKeyPackageBytes []byte) ([]byte, []byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(memberKeyPackageBytes) == 0 {
		return nil, nil, ErrEmptyKeyPackage
	}

	g, err := c.loadGroupLocked(groupID)
	if err != nil {
		return nil, nil, err
	}

	memberKP, err := keypackages.UnmarshalKeyPackage(memberKeyPackageBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshaling member key package: %w", err)
	}

	if _, err := g.AddMember(memberKP); err != nil {
		return nil, nil, fmt.Errorf("adding member: %w", err)
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

	welcome, err := g.CreateWelcomeWithOptions(newMemberKPs, group.CreateWelcomeOptions{
		JoinerSecret:  joinerSecret,
		SignerPrivKey: c.sigKey,
		PskIDs:        staged.PskIDs(),
		PskSecret:     staged.RawPskSecret(),
		StagedCommit:  staged,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("creating welcome: %w", err)
	}

	if err := c.persistGroupLocked(g); err != nil {
		return nil, nil, err
	}

	commitMsg := framing.NewMLSMessagePublic(&framing.PublicMessage{
		Content:       staged.AuthenticatedContent().Content,
		Auth:          staged.AuthenticatedContent().Auth,
		MembershipTag: staged.MembershipTag(),
	})

	welcomeMsg := framing.MLSMessage{Welcome: welcome.Marshal()}

	return commitMsg.Marshal(), welcomeMsg.Marshal(), nil
}

// JoinGroup joins a group using the most recently generated pending KeyPackage.
func (c *Client) JoinGroup(welcomeBytes []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(welcomeBytes) == 0 {
		return nil, ErrEmptyWelcome
	}
	if c.pendingKeyPackage == nil || c.pendingPrivate == nil {
		return nil, ErrNoPendingKeyPackage
	}
	welcome, err := parseWelcomeBytes(welcomeBytes)
	if err != nil {
		return nil, err
	}
	g, err := group.JoinFromWelcome(welcome, c.pendingKeyPackage, c.pendingPrivate, nil)
	if err != nil {
		return nil, fmt.Errorf("joining from welcome: %w", err)
	}
	if err := c.persistGroupLocked(g); err != nil {
		return nil, err
	}
	c.pendingKeyPackage = nil
	c.pendingPrivate = nil
	return cloneBytes(g.GroupID().AsSlice()), nil
}

// ProcessCommit applies a commit from another existing group member.
func (c *Client) ProcessCommit(groupID, commitBytes []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(commitBytes) == 0 {
		return ErrEmptyCommit
	}
	g, err := c.loadGroupLocked(groupID)
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
	return c.persistGroupLocked(g)
}

// SendMessage encrypts an application message for the given group.
func (c *Client) SendMessage(groupID, plaintext []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	g, err := c.loadGroupLocked(groupID)
	if err != nil {
		return nil, err
	}
	pm, err := g.SendMessage(plaintext, c.sigKey)
	if err != nil {
		return nil, fmt.Errorf("sending message: %w", err)
	}
	if err := c.persistGroupLocked(g); err != nil {
		return nil, err
	}
	return framing.NewMLSMessagePrivate(pm).Marshal(), nil
}

// ReceiveMessage decrypts an application message for the given group.
func (c *Client) ReceiveMessage(groupID, ciphertextBytes []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(ciphertextBytes) == 0 {
		return nil, ErrEmptyCiphertext
	}
	g, err := c.loadGroupLocked(groupID)
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
	plaintext, _, err := g.ReceiveApplicationMessage(pm)
	if err != nil {
		return nil, fmt.Errorf("receiving message: %w", err)
	}
	if err := c.persistGroupLocked(g); err != nil {
		return nil, err
	}
	return cloneBytes(plaintext), nil
}

func (c *Client) loadGroupLocked(groupIDBytes []byte) (*group.Group, error) {
	if len(groupIDBytes) == 0 {
		return nil, ErrEmptyGroupID
	}
	groupID := group.NewGroupID(cloneBytes(groupIDBytes))
	state, err := c.store.LoadGroupState(context.Background(), groupID)
	if err != nil {
		if errors.Is(err, memorystore.ErrGroupStateNotFound) {
			return nil, ErrGroupNotFound
		}
		return nil, fmt.Errorf("loading group state: %w", err)
	}
	g, err := group.UnmarshalGroupState(state)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling group state: %w", err)
	}
	return g, nil
}

func (c *Client) persistGroupLocked(g *group.Group) error {
	state, err := g.MarshalState()
	if err != nil {
		return fmt.Errorf("marshaling group state: %w", err)
	}
	groupID := g.GroupID()
	if err := c.store.SaveGroupState(context.Background(), groupID, state); err != nil {
		return fmt.Errorf("saving group state: %w", err)
	}
	if err := c.store.StoreSignatureKey(context.Background(), groupID, c.sigKey); err != nil {
		return fmt.Errorf("saving signature key: %w", err)
	}
	leafKey := g.MyLeafEncryptionKey()
	if len(leafKey) > 0 {
		if err := c.store.StoreLeafEncryptionKey(context.Background(), groupID, g.OwnLeafIndex(), leafKey); err != nil {
			return fmt.Errorf("saving leaf encryption key: %w", err)
		}
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
