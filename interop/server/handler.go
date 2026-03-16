package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"sync"
	"sync/atomic"

	"github.com/thomas-vilte/mls-go/treesync"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	mlsext "github.com/thomas-vilte/mls-go/extensions"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/interop/server/proto"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// Server implements the MLSClient gRPC service
type Server struct {
	proto.UnimplementedMLSClientServer

	// stateID -> *group.Group
	groups sync.Map

	// transactionID -> *keyPackageTransaction (pending)
	transactions sync.Map

	// stateID -> *ciphersuite.SignaturePrivateKey
	signers sync.Map

	// reinitID -> *reInitState (pending reinit flow)
	reinits sync.Map

	// externalSignerID -> *ciphersuite.SignaturePrivateKey
	externalSigners sync.Map

	// transactionID -> map[string][]byte  (PSKs stored before the transaction joins)
	txPsks sync.Map

	// Monotonic IDs
	nextStateID       uint32
	nextTransactionID uint32
	nextSignerID      uint32
	nextReinitID      uint32
}

// keyPackageTransaction stores pending key package data
type keyPackageTransaction struct {
	KeyPackage *keypackages.KeyPackage
	PrivKeys   *keypackages.KeyPackagePrivateKeys
}

// reInitState stores pending reinit flow data
type reInitState struct {
	ReInit           *group.ReInitProposal
	ResumptionSecret *ciphersuite.Secret
	OldGroupID       []byte
	KeyPackage       *keypackages.KeyPackage
	PrivKeys         *keypackages.KeyPackagePrivateKeys
	SigPrivKey       *ciphersuite.SignaturePrivateKey
}

// NewServer creates a new gRPC server instance
func NewServer() *Server {
	return &Server{}
}

func (s *Server) generateStateID() uint32 {
	return atomic.AddUint32(&s.nextStateID, 1)
}

func (s *Server) generateTransactionID() uint32 {
	return atomic.AddUint32(&s.nextTransactionID, 1)
}

func (s *Server) generateSignerID() uint32 {
	return atomic.AddUint32(&s.nextSignerID, 1)
}

func (s *Server) generateReinitID() uint32 {
	return atomic.AddUint32(&s.nextReinitID, 1)
}

// Name returns the implementation name
func (s *Server) Name(ctx context.Context, req *proto.NameRequest) (*proto.NameResponse, error) {
	return &proto.NameResponse{
		Name: "mls-go",
	}, nil
}

// SupportedCiphersuites returns supported cipher suite IDs
func (s *Server) SupportedCiphersuites(ctx context.Context, req *proto.SupportedCiphersuitesRequest) (*proto.SupportedCiphersuitesResponse, error) {
	return &proto.SupportedCiphersuitesResponse{
		Ciphersuites: []uint32{
			uint32(ciphersuite.MLS128DHKEMX25519),         // CS1
			uint32(ciphersuite.MLS128DHKEMP256),           // CS2
			uint32(ciphersuite.MLS128DHKEMX25519ChaCha20), // CS3
		},
	}, nil
}

// CreateGroup creates a new group
func (s *Server) CreateGroup(ctx context.Context, req *proto.CreateGroupRequest) (*proto.CreateGroupResponse, error) {
	cs := ciphersuite.CipherSuite(req.CipherSuite)
	if !cs.IsSupported() {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported cipher suite: %d", req.CipherSuite)
	}

	// Generate credential
	credWithKey, sigPrivKey, err := credentials.GenerateCredentialWithKeyForCS(req.Identity, cs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generating credential: %v", err)
	}

	// Generate key package
	kp, privKeys, err := keypackages.Generate(credWithKey, cs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generating key package: %v", err)
	}

	// Create group
	g, err := group.NewGroup(
		group.NewGroupID(req.GroupId),
		cs,
		kp,
		privKeys,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "creating group: %v", err)
	}

	// Store signer key for later use
	stateID := s.generateStateID()
	s.groups.Store(stateID, g)
	s.signers.Store(stateID, sigPrivKey)

	return &proto.CreateGroupResponse{
		StateId: stateID,
	}, nil
}

// CreateKeyPackage generates a key package
func (s *Server) CreateKeyPackage(ctx context.Context, req *proto.CreateKeyPackageRequest) (*proto.CreateKeyPackageResponse, error) {
	cs := ciphersuite.CipherSuite(req.CipherSuite)
	if !cs.IsSupported() {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported cipher suite: %d", req.CipherSuite)
	}

	// Generate credential
	credWithKey, _, err := credentials.GenerateCredentialWithKeyForCS(req.Identity, cs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generating credential: %v", err)
	}

	// Generate key package
	kp, privKeys, err := keypackages.Generate(credWithKey, cs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generating key package: %v", err)
	}

	// Marshal key package
	kpData := kp.Marshal()

	// Get signature key bytes
	var sigKeyBytes []byte
	if cs == ciphersuite.MLS128DHKEMX25519 || cs == ciphersuite.MLS128DHKEMX25519ChaCha20 {
		// Ed25519: use the ed25519 private key (64 bytes)
		sigKeyBytes = privKeys.Ed25519SignatureKey
	} else {
		// ECDSA P-256: use the ecdsa private key
		if privKeys.SignatureKey == nil {
			return nil, status.Errorf(codes.Internal, "ECDSA signature key is nil")
		}
		sigKeyBytes = privKeys.SignatureKey.D.Bytes()
	}

	txID := s.generateTransactionID()
	s.transactions.Store(txID, &keyPackageTransaction{
		KeyPackage: kp,
		PrivKeys:   privKeys,
	})

	return &proto.CreateKeyPackageResponse{
		TransactionId:  txID,
		KeyPackage:     kpData,
		InitPriv:       privKeys.InitKey.Bytes(),
		EncryptionPriv: privKeys.EncryptionKey.Bytes(),
		SignaturePriv:  sigKeyBytes,
	}, nil
}

// JoinGroup joins via Welcome
func (s *Server) JoinGroup(ctx context.Context, req *proto.JoinGroupRequest) (*proto.JoinGroupResponse, error) {
	// Get transaction
	txVal, ok := s.transactions.Load(req.TransactionId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "transaction not found: %d", req.TransactionId)
	}
	tx := txVal.(*keyPackageTransaction)

	// Parse welcome
	welcome, err := group.UnmarshalWelcome(req.Welcome)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parsing welcome: %v", err)
	}

	// Collect any PSKs buffered by StorePSK calls before the transaction joined.
	var externalPsks map[string][]byte
	if psksRaw, ok := s.txPsks.LoadAndDelete(req.TransactionId); ok {
		psksMap := psksRaw.(*sync.Map)
		externalPsks = make(map[string][]byte)
		psksMap.Range(func(k, v interface{}) bool {
			externalPsks[k.(string)] = v.([]byte)
			return true
		})
	}

	// Join group
	g, err := group.JoinFromWelcome(
		welcome,
		tx.KeyPackage,
		tx.PrivKeys,
		externalPsks,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "joining group: %v", err)
	}

	stateID := s.generateStateID()
	s.groups.Store(stateID, g)
	// Preserve the joiner's signature key so GroupInfo and Protect work after joining.
	s.signers.Store(stateID, tx.PrivKeys.GetSignaturePrivateKey())

	return &proto.JoinGroupResponse{
		StateId:            stateID,
		EpochAuthenticator: g.EpochAuthenticator(),
	}, nil
}

// GroupInfo returns the GroupInfo for a group
func (s *Server) GroupInfo(ctx context.Context, req *proto.GroupInfoRequest) (*proto.GroupInfoResponse, error) {
	gVal, ok := s.groups.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "group not found: %d", req.StateId)
	}
	g := gVal.(*group.Group)

	// Get signer key
	signerVal, ok := s.signers.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.Internal, "signer key not found for state: %d", req.StateId)
	}
	signerPrivKey := signerVal.(*ciphersuite.SignaturePrivateKey)

	groupInfo, err := g.GetGroupInfo(signerPrivKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "getting group info: %v", err)
	}

	giData := groupInfo.Marshal()

	var ratchetTree []byte
	if req.ExternalTree {
		ratchetTree = g.RatchetTree.MarshalTree()
	}

	return &proto.GroupInfoResponse{
		GroupInfo:   giData,
		RatchetTree: ratchetTree,
	}, nil
}

// StateAuth returns the state authentication secret (epoch authenticator)
func (s *Server) StateAuth(ctx context.Context, req *proto.StateAuthRequest) (*proto.StateAuthResponse, error) {
	gVal, ok := s.groups.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "group not found: %d", req.StateId)
	}
	g := gVal.(*group.Group)

	return &proto.StateAuthResponse{
		StateAuthSecret: g.EpochAuthenticator(),
	}, nil
}

// Export exports a secret using the MLS exporter
func (s *Server) Export(ctx context.Context, req *proto.ExportRequest) (*proto.ExportResponse, error) {
	gVal, ok := s.groups.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "group not found: %d", req.StateId)
	}
	g := gVal.(*group.Group)

	exported, err := g.Export(req.Label, req.Context, int(req.KeyLength))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "exporting secret: %v", err)
	}

	return &proto.ExportResponse{
		ExportedSecret: exported,
	}, nil
}

// Protect encrypts an application message for the group (RFC 9420 §6.3).
func (s *Server) Protect(ctx context.Context, req *proto.ProtectRequest) (*proto.ProtectResponse, error) {
	gVal, ok := s.groups.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "group not found: %d", req.StateId)
	}
	g := gVal.(*group.Group)

	signerVal, ok := s.signers.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.Internal, "signer key not found for state: %d", req.StateId)
	}
	sigKey := signerVal.(*ciphersuite.SignaturePrivateKey)

	pm, err := g.SendApplicationMessage(req.Plaintext, req.AuthenticatedData, sigKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encrypting message: %v", err)
	}

	// Wrap in MLSMessage wire format (version + wire_format + payload).
	msg := framing.NewMLSMessagePrivate(pm)
	return &proto.ProtectResponse{Ciphertext: msg.Marshal()}, nil
}

// Unprotect decrypts an application message (RFC 9420 §6.3).
func (s *Server) Unprotect(ctx context.Context, req *proto.UnprotectRequest) (*proto.UnprotectResponse, error) {
	gVal, ok := s.groups.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "group not found: %d", req.StateId)
	}
	g := gVal.(*group.Group)

	msg, err := framing.UnmarshalMLSMessage(req.Ciphertext)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parsing ciphertext: %v", err)
	}

	pm, ok := msg.AsPrivate()
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "ciphertext is not a PrivateMessage")
	}

	plaintext, authData, err := g.ReceiveApplicationMessage(pm)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "decrypting message: %v", err)
	}

	return &proto.UnprotectResponse{
		Plaintext:         plaintext,
		AuthenticatedData: authData,
	}, nil
}

// StorePSK stores a pre-shared key so it is available when the group commits
// or when a joiner processes a Welcome that references the PSK.
func (s *Server) StorePSK(ctx context.Context, req *proto.StorePSKRequest) (*proto.StorePSKResponse, error) {
	id := req.StateOrTransactionId
	// Check transactions first to avoid collision with group state IDs.
	// Transactions are transient and should be resolved before conflicts arise.
	if _, ok := s.transactions.Load(id); ok {
		// The id refers to a key-package transaction (joiner not yet in a group).
		// Buffer the PSK so JoinGroup can pass it to JoinFromWelcome.
		psksRaw, _ := s.txPsks.LoadOrStore(id, &sync.Map{})
		psksMap := psksRaw.(*sync.Map)
		psksMap.Store(string(req.PskId), append([]byte(nil), req.PskSecret...))
		return &proto.StorePSKResponse{}, nil
	}
	if gVal, ok := s.groups.Load(id); ok {
		// Existing group member: load directly into the group's PSK cache.
		g := gVal.(*group.Group)
		g.LoadPsk(req.PskId, req.PskSecret)
		return &proto.StorePSKResponse{}, nil
	}
	return nil, status.Errorf(codes.NotFound, "state or transaction not found: %d", id)
}

// Free releases a group state
func (s *Server) Free(ctx context.Context, req *proto.FreeRequest) (*proto.FreeResponse, error) {
	s.groups.Delete(req.StateId)
	s.signers.Delete(req.StateId)
	return &proto.FreeResponse{}, nil
}

// ExternalJoin performs an ExternalCommit to join a group without a Welcome (RFC 9420 §11.2.4).
//
// ExternalCommit generates its own HPKE key material internally; the caller
// only needs a signature key and the GroupInfo (with optional ratchet tree).
func (s *Server) ExternalJoin(ctx context.Context, req *proto.ExternalJoinRequest) (*proto.ExternalJoinResponse, error) {
	groupInfo, err := group.UnmarshalGroupInfo(req.GroupInfo)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parsing group info: %v", err)
	}

	cs := groupInfo.GroupContext.CipherSuite

	credWithKey, sigPrivKey, err := credentials.GenerateCredentialWithKeyForCS(req.Identity, cs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generating credential: %v", err)
	}

	// Attach ratchet tree from the request if the GroupInfo didn't include one
	// (ExternalPub extension path — RFC 9420 §11.2.2).
	if len(req.RatchetTree) > 0 {
		tree, err := treesync.UnmarshalTree(req.RatchetTree, cs)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "parsing ratchet tree: %v", err)
		}
		groupInfo.RatchetTree = tree
	}

	// RFC §12.4.3.2: if remove_prior is set, find the joiner's prior leaf in the tree
	// matched by credential identity and include a Remove proposal.
	removePriorLeaf := -1
	if req.RemovePrior {
		// Find the ratchet tree — prefer groupInfo.RatchetTree, fall back to extensions.
		rtree := groupInfo.RatchetTree
		if rtree == nil {
			for _, ext := range groupInfo.Extensions {
				if ext.Type == uint16(mlsext.ExtensionTypeRatchetTree) {
					parsed, parseErr := treesync.UnmarshalTree(ext.Data, cs)
					if parseErr == nil {
						rtree = parsed
					}
					break
				}
			}
		}
		if len(req.RatchetTree) > 0 && rtree == nil {
			parsed, parseErr := treesync.UnmarshalTree(req.RatchetTree, cs)
			if parseErr == nil {
				rtree = parsed
			}
		}
		if rtree != nil {
			for i := uint32(0); i < rtree.NumLeaves; i++ {
				leaf := rtree.GetLeaf(treesync.LeafIndex(i))
				if leaf == nil || leaf.LeafData == nil || leaf.LeafData.Credential == nil {
					continue
				}
				if string(leaf.LeafData.Credential.Identity) == string(req.Identity) {
					removePriorLeaf = int(i)
					break
				}
			}
		}
	}
	g, staged, err := group.ExternalCommit(groupInfo, cs, sigPrivKey, sigPrivKey.PublicKey(), removePriorLeaf, credWithKey.Credential)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "external commit: %v", err)
	}

	// Build ExternalCommit wire bytes: PublicMessage wrapping the signed AC.
	pm := &framing.PublicMessage{
		Content: staged.AuthenticatedContent.Content,
		Auth:    staged.AuthenticatedContent.Auth,
	}
	commitData := framing.NewMLSMessagePublic(pm).Marshal()

	stateID := s.generateStateID()
	s.groups.Store(stateID, g)
	s.signers.Store(stateID, sigPrivKey)

	return &proto.ExternalJoinResponse{
		StateId:            stateID,
		Commit:             commitData,
		EpochAuthenticator: g.EpochAuthenticator(),
	}, nil
}

// AddProposal creates an add proposal (Oleada 2).
//
// AddMember stores the proposal in g.Proposals automatically (RFC 9420 §12.1).
// The returned bytes are the raw Proposal TLV, used by the test runner to
// reference proposals by value in subsequent Commit and HandleCommit calls.
func (s *Server) AddProposal(ctx context.Context, req *proto.AddProposalRequest) (*proto.ProposalResponse, error) {
	gVal, ok := s.groups.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "group not found: %d", req.StateId)
	}
	g := gVal.(*group.Group)

	kp, err := keypackages.UnmarshalKeyPackage(req.KeyPackage)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parsing key package: %v", err)
	}

	proposal, err := g.AddMember(kp)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "creating add proposal: %v", err)
	}

	return &proto.ProposalResponse{Proposal: group.ProposalMarshal(proposal)}, nil
}

// UpdateProposal creates an Update proposal (RFC 9420 §12.1.2).
// Generates a fresh HPKE leaf key and signs the new leaf node.
func (s *Server) UpdateProposal(ctx context.Context, req *proto.UpdateProposalRequest) (*proto.ProposalResponse, error) {
	gVal, ok := s.groups.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "group not found: %d", req.StateId)
	}
	g := gVal.(*group.Group)

	signerVal, ok := s.signers.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.Internal, "signer key not found for state: %d", req.StateId)
	}
	sigKey := signerVal.(*ciphersuite.SignaturePrivateKey)

	proposal, err := g.SelfUpdate(sigKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "creating update proposal: %v", err)
	}
	log.Printf("UpdateProposal: state_id=%d ownLeaf=%d PendingUpdatePrivKey_set=%v", req.StateId, g.OwnLeafIndex, g.PendingUpdatePrivKey != nil)
	return &proto.ProposalResponse{Proposal: group.ProposalMarshal(proposal)}, nil
}

// RemoveProposal creates a remove proposal (Oleada 2).
//
// Searches members by identity bytes to find the target leaf index.
// RemoveMember stores the proposal in g.Proposals (RFC 9420 §12.1).
func (s *Server) RemoveProposal(ctx context.Context, req *proto.RemoveProposalRequest) (*proto.ProposalResponse, error) {
	gVal, ok := s.groups.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "group not found: %d", req.StateId)
	}
	g := gVal.(*group.Group)

	// Find member by identity — Credential.Identity is a []byte field, not a method.
	targetLeafIndex := group.LeafNodeIndex(0)
	found := false
	memberCount := g.MemberCount()
	for i := 0; i < memberCount; i++ {
		if member, ok := g.GetMember(group.LeafNodeIndex(i)); ok {
			if string(member.Credential.Identity) == string(req.RemovedId) {
				targetLeafIndex = group.LeafNodeIndex(i)
				found = true
				break
			}
		}
	}

	if !found {
		return nil, status.Errorf(codes.NotFound, "member with identity %s not found", req.RemovedId)
	}

	proposal, err := g.RemoveMember(targetLeafIndex)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "creating remove proposal: %v", err)
	}

	return &proto.ProposalResponse{Proposal: group.ProposalMarshal(proposal)}, nil
}

// ExternalPSKProposal creates an external PSK proposal (RFC 9420 §12.1.4).
func (s *Server) ExternalPSKProposal(ctx context.Context, req *proto.ExternalPSKProposalRequest) (*proto.ProposalResponse, error) {
	gVal, ok := s.groups.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "group not found: %d", req.StateId)
	}
	g := gVal.(*group.Group)

	// RFC §8.4: psk_nonce MUST be a fresh random value of length KDF.Nh.
	nonce := make([]byte, g.CipherSuite.HashLength())
	if _, err := rand.Read(nonce); err != nil {
		return nil, status.Errorf(codes.Internal, "generating psk nonce: %v", err)
	}

	proposal := group.NewPreSharedKeyProposal(1 /* external */, req.PskId)
	proposal.PreSharedKey.PskID.Nonce = nonce

	g.Proposals.AddProposal(proposal, g.OwnLeafIndex)
	return &proto.ProposalResponse{Proposal: group.ProposalMarshal(proposal)}, nil
}

// ResumptionPSKProposal creates a resumption PSK proposal (RFC 9420 §12.1.4 / §8.4).
// EpochId is the MLS epoch number whose resumption secret should be referenced.
func (s *Server) ResumptionPSKProposal(ctx context.Context, req *proto.ResumptionPSKProposalRequest) (*proto.ProposalResponse, error) {
	gVal, ok := s.groups.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "group not found: %d", req.StateId)
	}
	g := gVal.(*group.Group)

	nonce := make([]byte, g.CipherSuite.HashLength())
	if _, err := rand.Read(nonce); err != nil {
		return nil, status.Errorf(codes.Internal, "generating psk nonce: %v", err)
	}

	proposal := &group.Proposal{
		Type: group.ProposalTypePreSharedKey,
		PreSharedKey: &group.PreSharedKeyProposal{
			PskType: 2, // resumption
			PskID: group.PskID{
				PskType:    2,
				Usage:      1, // application
				PskGroupID: g.GroupID.AsSlice(),
				PskEpoch:   req.EpochId,
				Nonce:      nonce,
			},
		},
	}

	g.Proposals.AddProposal(proposal, g.OwnLeafIndex)
	return &proto.ProposalResponse{Proposal: group.ProposalMarshal(proposal)}, nil
}

// GroupContextExtensionsProposal creates a GroupContextExtensions proposal (RFC 9420 §12.1.7).
func (s *Server) GroupContextExtensionsProposal(ctx context.Context, req *proto.GroupContextExtensionsProposalRequest) (*proto.ProposalResponse, error) {
	gVal, ok := s.groups.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "group not found: %d", req.StateId)
	}
	g := gVal.(*group.Group)

	exts := make([]group.Extension, len(req.Extensions))
	for i, e := range req.Extensions {
		exts[i] = group.Extension{Type: uint16(e.ExtensionType), Data: e.ExtensionData}
	}

	proposal := group.NewGroupContextExtensionsProposal(exts)
	g.Proposals.AddProposal(proposal, g.OwnLeafIndex)
	return &proto.ProposalResponse{Proposal: group.ProposalMarshal(proposal)}, nil
}

// proposalFromDescription creates a *group.Proposal from an interop ProposalDescription
// (used by the byValue field in CommitRequest).
func (s *Server) proposalFromDescription(g *group.Group, desc *proto.ProposalDescription) (*group.Proposal, error) {
	ptype := string(desc.ProposalType)
	switch ptype {
	case "add":
		kp, err := keypackages.UnmarshalKeyPackage(desc.KeyPackage)
		if err != nil {
			return nil, fmt.Errorf("parsing key package: %w", err)
		}
		return group.NewAddProposal(kp), nil

	case "remove":
		// RemovedId is the identity bytes; find the leaf index.
		memberCount := g.MemberCount()
		for i := range memberCount {
			if m, ok := g.GetMember(group.LeafNodeIndex(i)); ok {
				if string(m.Credential.Identity) == string(desc.RemovedId) {
					return group.NewRemoveProposal(group.LeafNodeIndex(i)), nil
				}
			}
		}
		return nil, fmt.Errorf("member with identity %s not found", desc.RemovedId)

	case "externalPSK":
		nonce := make([]byte, g.CipherSuite.HashLength())
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("generating psk nonce: %w", err)
		}
		p := group.NewPreSharedKeyProposal(1 /* external */, desc.PskId)
		p.PreSharedKey.PskID.Nonce = nonce
		return p, nil

	case "resumptionPSK":
		nonce := make([]byte, g.CipherSuite.HashLength())
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("generating psk nonce: %w", err)
		}
		return &group.Proposal{
			Type: group.ProposalTypePreSharedKey,
			PreSharedKey: &group.PreSharedKeyProposal{
				PskType: 2,
				PskID: group.PskID{
					PskType:    2,
					Usage:      1,
					PskGroupID: g.GroupID.AsSlice(),
					PskEpoch:   desc.EpochId,
					Nonce:      nonce,
				},
			},
		}, nil

	case "groupContextExtensions":
		exts := make([]group.Extension, len(desc.Extensions))
		for i, e := range desc.Extensions {
			exts[i] = group.Extension{Type: uint16(e.ExtensionType), Data: e.ExtensionData}
		}
		return group.NewGroupContextExtensionsProposal(exts), nil

	default:
		return nil, fmt.Errorf("unsupported byValue proposal type: %s", ptype)
	}
}

// Commit creates a commit for all pending proposals (Oleada 2).
//
// Flow per RFC 9420 §12.4:
//  1. Capture OLD epoch init_secret (needed for Welcome's joiner_secret derivation).
//  2. CommitWithFormat → *StagedCommit (stores staged in g.PendingCommit).
//  3. MergeCommit → advances committer's epoch to StateOperational.
//  4. CreateWelcome for any new members added via pending Add proposals.
//
// HandlePendingCommit is a no-op after this (MergeCommit already applied).
func (s *Server) Commit(ctx context.Context, req *proto.CommitRequest) (*proto.CommitResponse, error) {
	gVal, ok := s.groups.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "group not found: %d", req.StateId)
	}
	g := gVal.(*group.Group)

	signerVal, ok := s.signers.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.Internal, "signer key not found for state: %d", req.StateId)
	}
	sigKey := signerVal.(*ciphersuite.SignaturePrivateKey)

	// Add byReference proposals from other actors that aren't in g.Proposals yet.
	// byReference[i] = raw proposal bytes (ProposalMarshal output) from another actor's
	// AddProposal/ExternalPSKProposal/etc. response.
	for _, propBytes := range req.ByReference {
		p, err := group.UnmarshalProposal(propBytes)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "byReference proposal: %v", err)
		}
		// Only add if not already present (own proposals are already there).
		alreadyPresent := false
		for _, sp := range g.Proposals.Proposals {
			if string(group.ProposalMarshal(sp.Proposal)) == string(propBytes) {
				alreadyPresent = true
				break
			}
		}
		if alreadyPresent {
			continue
		}
		// Infer sender leaf index. For Update proposals the sender MUST be the
		// member whose current signature key matches the new leaf node's sig key
		// (RFC §12.1.2: a member updates their own leaf). Default to OwnLeafIndex
		// for other proposal types where sender identity doesn't affect validation.
		sender := g.OwnLeafIndex
		if p.Type == group.ProposalTypeUpdate && p.Update != nil {
			newSigKey := p.Update.LeafNode.SignatureKeyBytes
			for i := range g.MemberCount() {
				leaf := g.RatchetTree.GetLeaf(treesync.LeafIndex(i))
				if leaf != nil && leaf.LeafData != nil {
					if string(leaf.LeafData.SigKeyBytes()) == string(newSigKey) {
						sender = group.LeafNodeIndex(i)
						break
					}
				}
			}
		}
		g.Proposals.AddProposal(p, sender)
	}

	// Add any inline (byValue) proposals to g.Proposals before committing.
	for _, desc := range req.ByValue {
		p, err := s.proposalFromDescription(g, desc)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "byValue proposal: %v", err)
		}
		g.Proposals.AddProposal(p, g.OwnLeafIndex)
	}

	staged, err := g.CommitWithFormat(sigKey, sigKey.PublicKey(), nil, framing.WireFormatPublicMessage)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "creating commit: %v", err)
	}

	// staged.JoinerSecret is the actual joiner_secret = ExpandWithLabel(intermediate, "joiner", GC, Nh),
	// cloned in CommitWithFormat before ComputePskSecret zeroes it via HKDFExtract.
	// staged.RootPathSecret (commit_secret) is also zeroed by that point — don't use it.
	joinerSecret := staged.JoinerSecret

	// Advance committer's own epoch; CreateWelcome requires StateOperational.
	if err := g.MergeCommit(staged); err != nil {
		return nil, status.Errorf(codes.Internal, "merging commit: %v", err)
	}

	// Collect key packages of newly added members from the commit's proposals.
	var newMemberKPs []*keypackages.KeyPackage
	for _, prop := range staged.Proposals {
		if prop.Type == group.ProposalTypeAdd && prop.Add != nil {
			newMemberKPs = append(newMemberKPs, prop.Add.KeyPackage)
		}
	}

	// Build commit wire bytes: PublicMessage wrapping the signed AuthenticatedContent.
	pm := &framing.PublicMessage{
		Content: staged.AuthenticatedContent.Content,
		Auth:    staged.AuthenticatedContent.Auth,
	}
	commitData := framing.NewMLSMessagePublic(pm).Marshal()

	// Create Welcome for new members if any Add proposals were committed.
	var welcomeData []byte
	if len(newMemberKPs) > 0 {
		welcome, err := g.CreateWelcome(newMemberKPs, joinerSecret, nil, sigKey, staged.PskIDs, staged.RawPskSecret)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "creating welcome: %v", err)
		}
		welcomeData = welcome.Marshal()
	}

	var ratchetTree []byte
	if req.ExternalTree {
		ratchetTree = g.RatchetTree.MarshalTree()
	}

	return &proto.CommitResponse{
		Commit:      commitData,
		Welcome:     welcomeData,
		RatchetTree: ratchetTree,
	}, nil
}

// HandleCommit processes a commit received from another group member (Oleada 2).
//
// The commit arrives as an MLSMessage wire blob (PublicMessage wrapper).
// ProcessReceivedCommit takes *framing.AuthenticatedContent and uses the
// receiver's own HPKE private key (g.MyLeafEncryptionKey) to decrypt path secrets.
func (s *Server) HandleCommit(ctx context.Context, req *proto.HandleCommitRequest) (*proto.HandleCommitResponse, error) {
	gVal, ok := s.groups.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "group not found: %d", req.StateId)
	}
	g := gVal.(*group.Group)

	// Parse commit from MLSMessage wire bytes.
	msg, err := framing.UnmarshalMLSMessage(req.Commit)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parsing commit message: %v", err)
	}
	pubMsg, ok := msg.AsPublic()
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "commit must be a PublicMessage")
	}

	// Reconstruct AuthenticatedContent from the parsed PublicMessage fields.
	// GroupContext is from the current (pre-commit) epoch as required by RFC §6.1.
	ac := &framing.AuthenticatedContent{
		WireFormat:   framing.WireFormatPublicMessage,
		Content:      pubMsg.Content,
		Auth:         pubMsg.Auth,
		GroupContext: g.GroupContext.Marshal(),
	}
	senderLeafIdx := treesync.LeafIndex(pubMsg.Content.Sender.LeafIndex)

	log.Printf("HandleCommit: state_id=%d ownLeaf=%d PendingUpdatePrivKey_set=%v", req.StateId, g.OwnLeafIndex, g.PendingUpdatePrivKey != nil)
	if err := g.ProcessReceivedCommit(ac, senderLeafIdx, g.MyLeafEncryptionKey); err != nil {
		return nil, status.Errorf(codes.Internal, "processing commit: %v", err)
	}

	newStateID := s.generateStateID()
	s.groups.Store(newStateID, g)
	if signerVal, ok := s.signers.Load(req.StateId); ok {
		s.signers.Store(newStateID, signerVal)
	}

	return &proto.HandleCommitResponse{
		StateId:            newStateID,
		EpochAuthenticator: g.EpochAuthenticator(),
	}, nil
}

// HandlePendingCommit handles a pending commit (own commit, Oleada 2).
//
// Commit() already calls MergeCommit() immediately, so by the time
// HandlePendingCommit is called the group is already in the new epoch.
// We assign a new state ID for the already-advanced group state.
func (s *Server) HandlePendingCommit(ctx context.Context, req *proto.HandlePendingCommitRequest) (*proto.HandleCommitResponse, error) {
	gVal, ok := s.groups.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "group not found: %d", req.StateId)
	}
	g := gVal.(*group.Group)

	// If for any reason the commit was not yet merged (e.g. state is StatePendingCommit),
	// apply it now. Otherwise this is a no-op (Commit already merged above).
	if g.PendingCommit != nil {
		if err := g.MergeCommit(g.PendingCommit); err != nil {
			return nil, status.Errorf(codes.Internal, "merging pending commit: %v", err)
		}
	}

	newStateID := s.generateStateID()
	s.groups.Store(newStateID, g)
	if signerVal, ok := s.signers.Load(req.StateId); ok {
		s.signers.Store(newStateID, signerVal)
	}

	return &proto.HandleCommitResponse{
		StateId:            newStateID,
		EpochAuthenticator: g.EpochAuthenticator(),
	}, nil
}

// ReInitProposal creates a ReInit proposal and stores it in the group (Oleada 3, RFC 9420 §12.1.5).
func (s *Server) ReInitProposal(ctx context.Context, req *proto.ReInitProposalRequest) (*proto.ProposalResponse, error) {
	gVal, ok := s.groups.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "group not found: %d", req.StateId)
	}
	g := gVal.(*group.Group)

	proposal := group.NewReInitProposal(
		req.GroupId,
		keypackages.MLS10,
		keypackages.CipherSuite(req.CipherSuite),
		nil, // extensions: not provided by the proto
	)

	// Store proposal in the group so it is picked up by the next Commit.
	g.Proposals.AddProposal(proposal, g.OwnLeafIndex)

	return &proto.ProposalResponse{Proposal: group.ProposalMarshal(proposal)}, nil
}

// ReInitCommit commits pending proposals for a reinitialization (Oleada 3).
//
// Identical to Commit: the ReInit proposal was stored via ReInitProposal and
// will be included in the commit automatically (RFC 9420 §12.4).
func (s *Server) ReInitCommit(ctx context.Context, req *proto.CommitRequest) (*proto.CommitResponse, error) {
	return s.Commit(ctx, req)
}

// HandlePendingReInitCommit handles the committer's own ReInit commit (Oleada 3).
//
// After the commit is merged the resumption_secret is extracted from the new
// epoch's EpochSecrets. A fresh KeyPackage for the new group's cipher suite is
// generated and stored under a reinit_id for use by ReInitWelcome later.
func (s *Server) HandlePendingReInitCommit(ctx context.Context, req *proto.HandlePendingCommitRequest) (*proto.HandleReInitCommitResponse, error) {
	gVal, ok := s.groups.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "group not found: %d", req.StateId)
	}
	g := gVal.(*group.Group)

	// Capture proposals before MergeCommit clears them.
	var proposals []*group.Proposal
	if g.PendingCommit != nil {
		proposals = g.PendingCommit.Proposals
		if err := g.MergeCommit(g.PendingCommit); err != nil {
			return nil, status.Errorf(codes.Internal, "merging pending commit: %v", err)
		}
	}

	return s.finalizeReInitCommit(g, proposals)
}

// HandleReInitCommit processes a ReInit commit from another member (Oleada 3).
//
// Parses the commit, processes it via ProcessReceivedCommit, then extracts
// the ReInit proposal to bootstrap the pending reinit state.
func (s *Server) HandleReInitCommit(ctx context.Context, req *proto.HandleCommitRequest) (*proto.HandleReInitCommitResponse, error) {
	gVal, ok := s.groups.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "group not found: %d", req.StateId)
	}
	g := gVal.(*group.Group)

	// Pre-load proposals from the request so they can be resolved by-reference.
	var proposals []*group.Proposal
	for _, pBytes := range req.Proposal {
		p, err := group.UnmarshalProposal(pBytes)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "parsing proposal: %v", err)
		}
		proposals = append(proposals, p)
		g.Proposals.AddProposal(p, g.OwnLeafIndex)
	}

	msg, err := framing.UnmarshalMLSMessage(req.Commit)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parsing commit message: %v", err)
	}
	pubMsg, ok := msg.AsPublic()
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "commit must be a PublicMessage")
	}

	ac := &framing.AuthenticatedContent{
		WireFormat:   framing.WireFormatPublicMessage,
		Content:      pubMsg.Content,
		Auth:         pubMsg.Auth,
		GroupContext: g.GroupContext.Marshal(),
	}
	senderLeafIdx := treesync.LeafIndex(pubMsg.Content.Sender.LeafIndex)

	if err := g.ProcessReceivedCommit(ac, senderLeafIdx, g.MyLeafEncryptionKey); err != nil {
		return nil, status.Errorf(codes.Internal, "processing commit: %v", err)
	}

	return s.finalizeReInitCommit(g, proposals)
}

// finalizeReInitCommit is shared logic for both HandlePendingReInitCommit and
// HandleReInitCommit. After the commit has been merged it:
//  1. Finds the ReInit proposal in the committed proposals slice.
//  2. Extracts the resumption_secret from the new epoch's EpochSecrets.
//  3. Generates a fresh KeyPackage for the new group's cipher suite.
//  4. Stores the reinit state under a new reinit_id.
func (s *Server) finalizeReInitCommit(g *group.Group, proposals []*group.Proposal) (*proto.HandleReInitCommitResponse, error) {
	// Find the ReInit proposal in the committed proposals.
	var reInitProposal *group.ReInitProposal
	for _, p := range proposals {
		if p.Type == group.ProposalTypeReInit && p.ReInit != nil {
			reInitProposal = p.ReInit
			break
		}
	}
	if reInitProposal == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "no ReInit proposal found in last commit")
	}

	if g.EpochSecrets == nil || g.EpochSecrets.ResumptionSecret == nil {
		return nil, status.Errorf(codes.Internal, "resumption secret not available after reinit commit")
	}
	resumptionSecret := g.EpochSecrets.ResumptionSecret.Clone()
	oldGroupID := append([]byte(nil), g.GroupID.AsSlice()...)

	// Generate a fresh identity + KP for the new group.
	newCS := reInitProposal.CipherSuite
	var identity []byte
	if m, ok := g.GetMember(g.OwnLeafIndex); ok {
		identity = append([]byte(nil), m.Credential.Identity...)
	} else {
		identity = []byte("reinit-member")
	}
	credWithKey, sigPrivKey, err := credentials.GenerateCredentialWithKeyForCS(identity, newCS)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generating reinit credential: %v", err)
	}
	kp, privKeys, err := keypackages.Generate(credWithKey, newCS)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generating reinit key package: %v", err)
	}

	reinitID := s.generateReinitID()
	s.reinits.Store(reinitID, &reInitState{
		ReInit:           reInitProposal,
		ResumptionSecret: resumptionSecret,
		OldGroupID:       oldGroupID,
		KeyPackage:       kp,
		PrivKeys:         privKeys,
		SigPrivKey:       sigPrivKey,
	})

	sigKeyBytes, err := privKeys.SignatureKey.Bytes()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "getting reinit sig key bytes: %v", err)
	}
	_ = sigKeyBytes
	kpData := kp.Marshal()

	return &proto.HandleReInitCommitResponse{
		ReinitId:           reinitID,
		KeyPackage:         kpData,
		EpochAuthenticator: g.EpochAuthenticator(),
	}, nil
}

// ReInitWelcome creates the new group and Welcome for a reinitialization (Oleada 3, RFC 9420 §11.3).
//
// Uses NewGroupFromReInit to create the new group (epoch 0), then adds all
// provided key packages as Add proposals, commits, and returns a Welcome.
func (s *Server) ReInitWelcome(ctx context.Context, req *proto.ReInitWelcomeRequest) (*proto.CreateSubgroupResponse, error) {
	ri, ok := s.reinits.Load(req.ReinitId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "reinit not found: %d", req.ReinitId)
	}
	state := ri.(*reInitState)

	newGroup, err := group.NewGroupFromReInit(
		state.ReInit,
		state.ResumptionSecret,
		state.OldGroupID,
		state.KeyPackage,
		state.PrivKeys,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "creating reinit group: %v", err)
	}

	// Parse and add all provided key packages as Add proposals.
	var newMemberKPs []*keypackages.KeyPackage
	for _, kpBytes := range req.KeyPackage {
		kp, err := keypackages.UnmarshalKeyPackage(kpBytes)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "parsing key package: %v", err)
		}
		if _, err := newGroup.AddMember(kp); err != nil {
			return nil, status.Errorf(codes.Internal, "adding member to reinit group: %v", err)
		}
		newMemberKPs = append(newMemberKPs, kp)
	}

	// Commit the Add proposals (if any).
	staged, err := newGroup.CommitWithFormat(state.SigPrivKey, state.SigPrivKey.PublicKey(), nil, framing.WireFormatPublicMessage)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "committing reinit adds: %v", err)
	}

	// Use staged.JoinerSecret (cloned before ComputePskSecret zeroes it — same fix as Commit handler).
	joinerSecret := staged.JoinerSecret

	if err := newGroup.MergeCommit(staged); err != nil {
		return nil, status.Errorf(codes.Internal, "merging reinit commit: %v", err)
	}

	var welcomeData []byte
	if len(newMemberKPs) > 0 {
		welcome, err := newGroup.CreateWelcome(newMemberKPs, joinerSecret, nil, state.SigPrivKey, staged.PskIDs, staged.RawPskSecret)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "creating reinit welcome: %v", err)
		}
		welcomeData = welcome.Marshal()
	}

	stateID := s.generateStateID()
	s.groups.Store(stateID, newGroup)
	s.signers.Store(stateID, state.SigPrivKey)

	var ratchetTree []byte
	if req.ExternalTree {
		ratchetTree = newGroup.RatchetTree.MarshalTree()
	}

	return &proto.CreateSubgroupResponse{
		StateId:            stateID,
		Welcome:            welcomeData,
		RatchetTree:        ratchetTree,
		EpochAuthenticator: newGroup.EpochAuthenticator(),
	}, nil
}

// HandleReInitWelcome joins the new group via a Welcome after reinitialization (Oleada 3).
func (s *Server) HandleReInitWelcome(ctx context.Context, req *proto.HandleReInitWelcomeRequest) (*proto.JoinGroupResponse, error) {
	ri, ok := s.reinits.Load(req.ReinitId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "reinit not found: %d", req.ReinitId)
	}
	state := ri.(*reInitState)

	welcome, err := group.UnmarshalWelcome(req.Welcome)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parsing welcome: %v", err)
	}

	newGroup, err := group.JoinFromWelcome(welcome, state.KeyPackage, state.PrivKeys, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "joining reinit group: %v", err)
	}

	stateID := s.generateStateID()
	s.groups.Store(stateID, newGroup)
	s.signers.Store(stateID, state.SigPrivKey)

	return &proto.JoinGroupResponse{
		StateId:            stateID,
		EpochAuthenticator: newGroup.EpochAuthenticator(),
	}, nil
}

// CreateBranch creates a subgroup branch (Oleada 3).
// Not implemented: no core branching API available.
func (s *Server) CreateBranch(ctx context.Context, req *proto.CreateBranchRequest) (*proto.CreateSubgroupResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "CreateBranch not implemented")
}

// HandleBranch joins a branched subgroup via Welcome (Oleada 3).
//
// Branches use the same JoinFromWelcome path as regular Welcome. The
// transaction_id refers to a KeyPackage previously created via NewMemberAddProposal.
func (s *Server) HandleBranch(ctx context.Context, req *proto.HandleBranchRequest) (*proto.HandleBranchResponse, error) {
	txVal, ok := s.transactions.Load(req.TransactionId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "transaction not found: %d", req.TransactionId)
	}
	tx := txVal.(*keyPackageTransaction)

	welcome, err := group.UnmarshalWelcome(req.Welcome)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parsing welcome: %v", err)
	}

	newGroup, err := group.JoinFromWelcome(welcome, tx.KeyPackage, tx.PrivKeys, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "joining branch group: %v", err)
	}

	stateID := s.generateStateID()
	s.groups.Store(stateID, newGroup)
	s.signers.Store(stateID, tx.PrivKeys.GetSignaturePrivateKey())

	return &proto.HandleBranchResponse{
		StateId:            stateID,
		EpochAuthenticator: newGroup.EpochAuthenticator(),
	}, nil
}

// NewMemberAddProposal creates a KeyPackage and an Add proposal for a new
// external member (Oleada 3, RFC 9420 §12.1.8).
//
// The proposal bytes and private key material are returned so the caller can
// (a) forward the proposal to an existing group member who will commit it, and
// (b) later call HandleBranch with the resulting Welcome.
func (s *Server) NewMemberAddProposal(ctx context.Context, req *proto.NewMemberAddProposalRequest) (*proto.NewMemberAddProposalResponse, error) {
	groupInfo, err := group.UnmarshalGroupInfo(req.GroupInfo)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parsing group info: %v", err)
	}

	cs := groupInfo.GroupContext.CipherSuite
	credWithKey, _, err := credentials.GenerateCredentialWithKeyForCS(req.Identity, cs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generating credential: %v", err)
	}

	kp, privKeys, err := keypackages.Generate(credWithKey, cs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generating key package: %v", err)
	}

	// Build an Add proposal for this new member.
	proposal := group.NewAddProposal(kp)
	proposalBytes := group.ProposalMarshal(proposal)

	sigKeyBytes, err := privKeys.SignatureKey.Bytes()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "getting sig key bytes: %v", err)
	}

	txID := s.generateTransactionID()
	s.transactions.Store(txID, &keyPackageTransaction{
		KeyPackage: kp,
		PrivKeys:   privKeys,
	})

	return &proto.NewMemberAddProposalResponse{
		TransactionId:  txID,
		Proposal:       proposalBytes,
		InitPriv:       privKeys.InitKey.Bytes(),
		EncryptionPriv: privKeys.EncryptionKey.Bytes(),
		SignaturePriv:  sigKeyBytes,
	}, nil
}

// CreateExternalSigner generates an external signer identity (Oleada 3, RFC 9420 §12.1.8.1).
//
// The external_sender bytes are encoded as a single ExternalSender entry:
//
//	VLBytes(signature_key) || VLBytes(credential)
//
// This matches the per-entry layout of the ExternalSenders extension (§12.1.8.1).
func (s *Server) CreateExternalSigner(ctx context.Context, req *proto.CreateExternalSignerRequest) (*proto.CreateExternalSignerResponse, error) {
	cs := ciphersuite.CipherSuite(req.CipherSuite)
	if !cs.IsSupported() {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported cipher suite: %d", req.CipherSuite)
	}

	credWithKey, sigPrivKey, err := credentials.GenerateCredentialWithKeyForCS(req.Identity, cs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generating external signer credential: %v", err)
	}

	sigPubBytes := credWithKey.SignatureKeyBytes
	credBytes := credWithKey.Credential.Marshal()

	// Encode: VLBytes(sigKey) || VLBytes(cred) — one ExternalSender entry.
	extSenderBytes := append(mlsVLBytes(sigPubBytes), mlsVLBytes(credBytes)...)

	signerID := s.generateSignerID()
	s.externalSigners.Store(signerID, sigPrivKey)

	return &proto.CreateExternalSignerResponse{
		SignerId:       signerID,
		ExternalSender: extSenderBytes,
	}, nil
}

// AddExternalSigner creates a GroupContextExtensions proposal adding the
// provided external signer to the ExternalSenders extension (Oleada 3).
func (s *Server) AddExternalSigner(ctx context.Context, req *proto.AddExternalSignerRequest) (*proto.ProposalResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "AddExternalSigner not implemented")
}

// ExternalSignerProposal creates a proposal signed by an external signer (Oleada 3).
func (s *Server) ExternalSignerProposal(ctx context.Context, req *proto.ExternalSignerProposalRequest) (*proto.ProposalResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "ExternalSignerProposal not implemented")
}

// mlsVLBytes encodes data as a MLS variable-length byte vector (RFC 9420 §3.5).
// Lengths 0–63 use 1 byte; 64–16383 use 2 bytes with the high nibble set to 0x40.
func mlsVLBytes(data []byte) []byte {
	n := len(data)
	var out []byte
	switch {
	case n < 64:
		out = []byte{byte(n)}
	case n < 16384:
		out = []byte{byte(0x40 | (n >> 8)), byte(n & 0xff)}
	default:
		// 4-byte varint (high 2 bits = 10)
		out = []byte{
			byte(0x80 | (n >> 24)),
			byte(n >> 16),
			byte(n >> 8),
			byte(n),
		}
	}
	return append(out, data...)
}
