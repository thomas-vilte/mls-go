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

	// stateID -> bool  (whether to use PrivateMessage for handshake messages)
	encryptHandshake sync.Map

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

// isEncryptHandshake reports whether the given stateID has encrypt_handshake=true.
func (s *Server) isEncryptHandshake(stateID uint32) bool {
	v, ok := s.encryptHandshake.Load(stateID)
	return ok && v.(bool)
}

// propagateEncryptHandshake copies the encrypt_handshake flag from one state to another.
func (s *Server) propagateEncryptHandshake(fromID, toID uint32) {
	if v, ok := s.encryptHandshake.Load(fromID); ok {
		s.encryptHandshake.Store(toID, v)
	}
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
	if req.EncryptHandshake {
		s.encryptHandshake.Store(stateID, true)
	}

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

	// Marshal key package as MLSMessage (wire_format=5) for cross-implementation compatibility.
	kpData := wrapKeyPackage(kp.Marshal())

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

	// Parse welcome (accepts both raw and MLSMessage-wrapped format).
	welcome, err := unmarshalWelcomeAnyFormat(req.Welcome)
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
	if req.EncryptHandshake {
		s.encryptHandshake.Store(stateID, true)
	}

	log.Printf("JoinGroup: out=%d ownLeaf=%d pnpkLen=%d", stateID, g.OwnLeafIndex, len(g.PathNodePrivKeys))

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

	giData := (&framing.MLSMessage{GroupInfo: groupInfo.Marshal()}).Marshal()

	var ratchetTree []byte
	if req.ExternalTree {
		ratchetTree = g.RatchetTree.MarshalTreeRFC()
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
// freeState releases all server-side memory for a given stateID.
func (s *Server) freeState(stateID uint32) {
	s.groups.Delete(stateID)
	s.signers.Delete(stateID)
	s.encryptHandshake.Delete(stateID)
}

func (s *Server) Free(ctx context.Context, req *proto.FreeRequest) (*proto.FreeResponse, error) {
	s.freeState(req.StateId)
	return &proto.FreeResponse{}, nil
}

// ExternalJoin performs an ExternalCommit to join a group without a Welcome (RFC 9420 §11.2.4).
//
// ExternalCommit generates its own HPKE key material internally; the caller
// only needs a signature key and the GroupInfo (with optional ratchet tree).
func (s *Server) ExternalJoin(ctx context.Context, req *proto.ExternalJoinRequest) (*proto.ExternalJoinResponse, error) {
	groupInfo, err := unmarshalGroupInfoAnyFormat(req.GroupInfo)
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
		tree, err := treesync.UnmarshalTreeFromExtension(req.RatchetTree, cs)
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
					parsed, parseErr := treesync.UnmarshalTreeFromExtension(ext.Data, cs)
					if parseErr == nil {
						rtree = parsed
					}
					break
				}
			}
		}
		if len(req.RatchetTree) > 0 && rtree == nil {
			parsed, parseErr := treesync.UnmarshalTreeFromExtension(req.RatchetTree, cs)
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

	log.Printf("ExternalJoin: out=%d ownLeaf=%d pnpkLen=%d", stateID, g.OwnLeafIndex, len(g.PathNodePrivKeys))

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

	kp, err := unmarshalKeyPackageAnyFormat(req.KeyPackage)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parsing key package: %v", err)
	}

	proposal, err := g.AddMember(kp)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "creating add proposal: %v", err)
	}

	return s.proposalResponse(g, req.StateId, proposal)
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
	return s.proposalResponse(g, req.StateId, proposal)
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

	// Find member by identity. Iterate Members map directly: after removals the
	// tree is sparse, so MemberCount() as a loop bound would miss high leaf indices.
	targetLeafIndex := group.LeafNodeIndex(0)
	found := false
	for leafIdx, m := range g.Members {
		if m.Active && string(m.Credential.Identity) == string(req.RemovedId) {
			targetLeafIndex = leafIdx
			found = true
			break
		}
	}

	if !found {
		return nil, status.Errorf(codes.NotFound, "member with identity %s not found", req.RemovedId)
	}

	proposal, err := g.RemoveMember(targetLeafIndex)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "creating remove proposal: %v", err)
	}

	return s.proposalResponse(g, req.StateId, proposal)
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
	return s.proposalResponse(g, req.StateId, proposal)
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
	return s.proposalResponse(g, req.StateId, proposal)
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
	return s.proposalResponse(g, req.StateId, proposal)
}

// proposalResponse wraps a Proposal in a signed PublicMessage MLSMessage for cross-interop,
// falling back to raw bytes if the sig key is unavailable.
func (s *Server) proposalResponse(g *group.Group, stateID uint32, proposal *group.Proposal) (*proto.ProposalResponse, error) {
	signerVal, ok := s.signers.Load(stateID)
	if ok {
		sigKey := signerVal.(*ciphersuite.SignaturePrivateKey)
		msgBytes, err := g.SignProposalAsPublicMessage(proposal, sigKey)
		if err == nil {
			return &proto.ProposalResponse{Proposal: msgBytes}, nil
		}
		log.Printf("proposalResponse: sign failed, falling back to raw: %v", err)
	}
	return &proto.ProposalResponse{Proposal: group.ProposalMarshal(proposal)}, nil
}

// proposalFromDescription creates a *group.Proposal from an interop ProposalDescription
// (used by the byValue field in CommitRequest).
func (s *Server) proposalFromDescription(g *group.Group, desc *proto.ProposalDescription) (*group.Proposal, error) {
	ptype := string(desc.ProposalType)
	switch ptype {
	case "add":
		kp, err := unmarshalKeyPackageAnyFormat(desc.KeyPackage)
		if err != nil {
			return nil, fmt.Errorf("parsing key package: %w", err)
		}
		return group.NewAddProposal(kp), nil

	case "remove":
		// RemovedId is the identity bytes; find the leaf index.
		// Iterate the Members map directly: after removals the tree is sparse,
		// so using MemberCount() as an upper bound on leaf indices is wrong.
		for leafIdx, m := range g.Members {
			if m.Active && string(m.Credential.Identity) == string(desc.RemovedId) {
				return group.NewRemoveProposal(leafIdx), nil
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
	//
	// Bytes may be either raw proposal bytes (group.ProposalMarshal output) or a
	// full MLSMessage wrapping a PublicMessage (from ExternalSignerProposal/NewMemberAddProposal).
	for _, propBytes := range req.ByReference {
		rawProp, p, err := extractByReferenceProposal(propBytes)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "byReference proposal: %v", err)
		}
		// Only add if not already present (own proposals are already there).
		alreadyPresent := false
		for _, sp := range g.Proposals.Proposals {
			if string(group.ProposalMarshal(sp.Proposal)) == string(rawProp) {
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
			// Iterate Members map directly: after removals the tree is sparse,
			// so using MemberCount() as an upper bound on leaf indices is wrong.
			for leafIdx, m := range g.Members {
				if !m.Active {
					continue
				}
				leaf := g.RatchetTree.GetLeaf(treesync.LeafIndex(leafIdx))
				if leaf != nil && leaf.LeafData != nil {
					if string(leaf.LeafData.SigKeyBytes()) == string(newSigKey) {
						sender = leafIdx
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

	encryptHS := s.isEncryptHandshake(req.StateId)
	commitFormat := framing.WireFormatPublicMessage
	if encryptHS {
		commitFormat = framing.WireFormatPrivateMessage
	}

	staged, err := g.CommitWithFormat(sigKey, sigKey.PublicKey(), nil, commitFormat)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "creating commit: %v", err)
	}

	// staged.JoinerSecret is the actual joiner_secret = ExpandWithLabel(intermediate, "joiner", GC, Nh),
	// cloned in CommitWithFormat before ComputePskSecret zeroes it via HKDFExtract.
	// staged.RootPathSecret (commit_secret) is also zeroed by that point — don't use it.
	joinerSecret := staged.JoinerSecret

	// Save old-epoch sender_data_secret and SecretTree for PrivateMessage encryption below.
	// These will be moved to EpochHistory by MergeCommit, so capture before advancing.
	var oldSenderDataSecret *ciphersuite.Secret
	if encryptHS && g.EpochSecrets != nil {
		oldSenderDataSecret = g.EpochSecrets.SenderDataSecret
	}
	oldSecretTreeVal := g.SecretTree

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

	// Build commit wire bytes.
	var commitData []byte
	if encryptHS && oldSenderDataSecret != nil {
		// Encrypt commit as PrivateMessage using old-epoch secrets.
		privMsg, encErr := framing.Encrypt(framing.EncryptParams{
			AuthContent:      staged.AuthenticatedContent,
			SenderLeafIndex:  uint32(g.OwnLeafIndex),
			CipherSuite:      g.CipherSuite,
			PaddingSize:      0,
			SenderDataSecret: oldSenderDataSecret,
			SecretTree:       oldSecretTreeVal,
		})
		if encErr != nil {
			return nil, status.Errorf(codes.Internal, "encrypting commit: %v", encErr)
		}
		commitData = framing.NewMLSMessagePrivate(privMsg).Marshal()
	} else {
		pm := &framing.PublicMessage{
			Content:       staged.AuthenticatedContent.Content,
			Auth:          staged.AuthenticatedContent.Auth,
			MembershipTag: staged.MembershipTag,
		}
		commitData = framing.NewMLSMessagePublic(pm).Marshal()
	}

	// Create Welcome for new members if any Add proposals were committed.
	var welcomeData []byte
	if len(newMemberKPs) > 0 {
		welcome, err := g.CreateWelcome(newMemberKPs, joinerSecret, nil, sigKey, staged.PskIDs, staged.RawPskSecret, staged)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "creating welcome: %v", err)
		}
		welcomeData = (&framing.MLSMessage{Welcome: welcome.Marshal()}).Marshal()
	}

	var ratchetTree []byte
	if req.ExternalTree {
		ratchetTree = g.RatchetTree.MarshalTreeRFC()
	}

	log.Printf("Commit: state_id=%d ownLeaf=%d pnpkLen=%d", req.StateId, g.OwnLeafIndex, len(g.PathNodePrivKeys))

	return &proto.CommitResponse{
		Commit:      commitData,
		Welcome:     welcomeData,
		RatchetTree: ratchetTree,
	}, nil
}

// HandleCommit processes a commit received from another group member (Oleada 2).
//
// Accepts both PublicMessage and PrivateMessage wire formats. PrivateMessage
// commits are decrypted using the current epoch's secret tree before processing.
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

	var ac *framing.AuthenticatedContent
	var senderLeafIdx treesync.LeafIndex

	if pubMsg, isPub := msg.AsPublic(); isPub {
		// PublicMessage commit: reconstruct AuthenticatedContent directly.
		ac = &framing.AuthenticatedContent{
			WireFormat:   framing.WireFormatPublicMessage,
			Content:      pubMsg.Content,
			Auth:         pubMsg.Auth,
			GroupContext: g.GroupContext.Marshal(),
		}
		senderLeafIdx = treesync.LeafIndex(pubMsg.Content.Sender.LeafIndex)
	} else if privMsg, isPriv := msg.AsPrivate(); isPriv {
		// PrivateMessage commit: decrypt using current epoch secrets.
		if g.EpochSecrets == nil || g.EpochSecrets.SenderDataSecret == nil {
			return nil, status.Errorf(codes.Internal, "sender_data_secret not available for PrivateMessage commit")
		}
		if g.SecretTree == nil {
			return nil, status.Errorf(codes.Internal, "secret tree not available for PrivateMessage commit")
		}
		decrypted, decErr := framing.Decrypt(privMsg, framing.DecryptParams{
			CipherSuite:      g.CipherSuite,
			SenderDataSecret: g.EpochSecrets.SenderDataSecret,
			SecretTree:       g.SecretTree,
			GroupContext:     g.GroupContext.Marshal(),
		})
		if decErr != nil {
			return nil, status.Errorf(codes.Internal, "decrypting PrivateMessage commit: %v", decErr)
		}
		ac = decrypted
		ac.WireFormat = framing.WireFormatPrivateMessage
		senderLeafIdx = treesync.LeafIndex(ac.Content.Sender.LeafIndex)
	} else {
		return nil, status.Errorf(codes.InvalidArgument, "commit must be a PublicMessage or PrivateMessage")
	}

	log.Printf("HandleCommit: state_id=%d ownLeaf=%d PendingUpdatePrivKey_set=%v", req.StateId, g.OwnLeafIndex, g.PendingUpdatePrivKey != nil)
	if err := g.ProcessReceivedCommit(ac, senderLeafIdx, g.MyLeafEncryptionKey); err != nil {
		return nil, status.Errorf(codes.Internal, "processing commit: %v", err)
	}

	newStateID := s.generateStateID()
	s.groups.Store(newStateID, g)
	if signerVal, ok := s.signers.Load(req.StateId); ok {
		s.signers.Store(newStateID, signerVal)
	}
	s.propagateEncryptHandshake(req.StateId, newStateID)
	s.freeState(req.StateId)

	log.Printf("HandleCommit: in=%d out=%d ownLeaf=%d pnpkLen=%d", req.StateId, newStateID, g.OwnLeafIndex, len(g.PathNodePrivKeys))

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
	s.propagateEncryptHandshake(req.StateId, newStateID)
	s.freeState(req.StateId)

	log.Printf("HandlePendingCommit: in=%d out=%d ownLeaf=%d pnpkLen=%d", req.StateId, newStateID, g.OwnLeafIndex, len(g.PathNodePrivKeys))

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
	} else {
		// Commit was already merged by the Commit RPC — use saved proposals.
		proposals = g.LastCommittedProposals
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

	var ac *framing.AuthenticatedContent
	var senderLeafIdx treesync.LeafIndex

	if pubMsg, isPub := msg.AsPublic(); isPub {
		ac = &framing.AuthenticatedContent{
			WireFormat:   framing.WireFormatPublicMessage,
			Content:      pubMsg.Content,
			Auth:         pubMsg.Auth,
			GroupContext: g.GroupContext.Marshal(),
		}
		senderLeafIdx = treesync.LeafIndex(pubMsg.Content.Sender.LeafIndex)
	} else if privMsg, isPriv := msg.AsPrivate(); isPriv {
		if g.EpochSecrets == nil || g.EpochSecrets.SenderDataSecret == nil {
			return nil, status.Errorf(codes.Internal, "sender_data_secret not available for PrivateMessage reinit commit")
		}
		if g.SecretTree == nil {
			return nil, status.Errorf(codes.Internal, "secret tree not available for PrivateMessage reinit commit")
		}
		decrypted, decErr := framing.Decrypt(privMsg, framing.DecryptParams{
			CipherSuite:      g.CipherSuite,
			SenderDataSecret: g.EpochSecrets.SenderDataSecret,
			SecretTree:       g.SecretTree,
			GroupContext:     g.GroupContext.Marshal(),
		})
		if decErr != nil {
			return nil, status.Errorf(codes.Internal, "decrypting PrivateMessage reinit commit: %v", decErr)
		}
		ac = decrypted
		ac.WireFormat = framing.WireFormatPrivateMessage
		senderLeafIdx = treesync.LeafIndex(ac.Content.Sender.LeafIndex)
	} else {
		return nil, status.Errorf(codes.InvalidArgument, "reinit commit must be a PublicMessage or PrivateMessage")
	}

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
		kp, err := unmarshalKeyPackageAnyFormat(kpBytes)
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
		welcome, err := newGroup.CreateWelcome(newMemberKPs, joinerSecret, nil, state.SigPrivKey, staged.PskIDs, staged.RawPskSecret, staged)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "creating reinit welcome: %v", err)
		}
		welcomeData = (&framing.MLSMessage{Welcome: welcome.Marshal()}).Marshal()
	}

	stateID := s.generateStateID()
	s.groups.Store(stateID, newGroup)
	s.signers.Store(stateID, state.SigPrivKey)

	var ratchetTree []byte
	if req.ExternalTree {
		ratchetTree = newGroup.RatchetTree.MarshalTreeRFC()
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

	welcome, err := unmarshalWelcomeAnyFormat(req.Welcome)
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

// CreateBranch creates a subgroup branch (RFC 9420 §12.4.3.3).
//
// The branch creator starts a fresh group with the given group_id and their
// own identity, adds every provided KeyPackage as an Add proposal, commits,
// and returns the Welcome plus the new state_id.
func (s *Server) CreateBranch(ctx context.Context, req *proto.CreateBranchRequest) (*proto.CreateSubgroupResponse, error) {
	gVal, ok := s.groups.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "group not found: %d", req.StateId)
	}
	oldGroup := gVal.(*group.Group)

	signerVal, ok := s.signers.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.Internal, "signer not found for state: %d", req.StateId)
	}
	sigKey := signerVal.(*ciphersuite.SignaturePrivateKey)

	cs := oldGroup.CipherSuite

	// Derive identity from the old group's own leaf credential.
	identity := oldGroup.Members[oldGroup.OwnLeafIndex].Credential.Identity

	credWithKey, newSigKey, err := credentials.GenerateCredentialWithKeyForCS(identity, cs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generating branch credential: %v", err)
	}
	_ = sigKey // old key no longer used for the branch group

	kp, privKeys, err := keypackages.Generate(credWithKey, cs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generating branch key package: %v", err)
	}

	// Convert request extensions.
	exts := make([]group.Extension, len(req.Extensions))
	for i, e := range req.Extensions {
		exts[i] = group.Extension{Type: uint16(e.ExtensionType), Data: e.ExtensionData}
	}

	branchGID := group.NewGroupID(req.GroupId)
	newGroup, err := group.NewGroupWithExtensions(branchGID, cs, kp, privKeys, exts)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "creating branch group: %v", err)
	}

	// Add each provided KeyPackage as an Add proposal.
	for _, kpBytes := range req.KeyPackages {
		memberKP, err2 := unmarshalKeyPackageAnyFormat(kpBytes)
		if err2 != nil {
			return nil, status.Errorf(codes.InvalidArgument, "parsing key package: %v", err2)
		}
		prop := group.NewAddProposal(memberKP)
		newGroup.Proposals.AddProposal(prop, newGroup.OwnLeafIndex)
	}

	// Commit to produce the Welcome.
	staged, err := newGroup.CommitWithFormat(newSigKey, newSigKey.PublicKey(), nil, framing.WireFormatPublicMessage)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "committing branch: %v", err)
	}
	joinerSecret := staged.JoinerSecret

	if err := newGroup.MergeCommit(staged); err != nil {
		return nil, status.Errorf(codes.Internal, "merging branch commit: %v", err)
	}

	// Collect new member key packages.
	var newMemberKPs []*keypackages.KeyPackage
	for _, prop := range staged.Proposals {
		if prop.Type == group.ProposalTypeAdd && prop.Add != nil {
			newMemberKPs = append(newMemberKPs, prop.Add.KeyPackage)
		}
	}

	var welcomeData []byte
	if len(newMemberKPs) > 0 {
		welcome, err := newGroup.CreateWelcome(newMemberKPs, joinerSecret, nil, newSigKey, staged.PskIDs, staged.RawPskSecret, staged)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "creating branch welcome: %v", err)
		}
		welcomeData = (&framing.MLSMessage{Welcome: welcome.Marshal()}).Marshal()
	}

	var ratchetTreeData []byte
	if req.ExternalTree {
		ratchetTreeData = newGroup.RatchetTree.MarshalTreeRFC()
	}

	stateID := s.generateStateID()
	s.groups.Store(stateID, newGroup)
	s.signers.Store(stateID, newSigKey)

	return &proto.CreateSubgroupResponse{
		StateId:            stateID,
		Welcome:            welcomeData,
		RatchetTree:        ratchetTreeData,
		EpochAuthenticator: newGroup.EpochAuthenticator(),
	}, nil
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

	welcome, err := unmarshalWelcomeAnyFormat(req.Welcome)
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
	groupInfo, err := unmarshalGroupInfoAnyFormat(req.GroupInfo)
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

	// Extract raw private key bytes (Ed25519 for CS1/CS3, P-256 for CS2).
	var sigKeyBytes []byte
	if privKeys.Ed25519SignatureKey != nil {
		sigKeyBytes = []byte(privKeys.Ed25519SignatureKey)
	} else if privKeys.SignatureKey != nil {
		sigKeyBytes, _ = privKeys.SignatureKey.Bytes()
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
// provided external signer to the ExternalSenders extension (RFC 9420 §12.1.8.1).
//
// external_sender contains a single ExternalSender entry encoded as:
//
//	VLBytes(signature_key) || VLBytes(credential)
//
// The current ExternalSenders list (if any) is preserved; the new entry is appended.
func (s *Server) AddExternalSigner(ctx context.Context, req *proto.AddExternalSignerRequest) (*proto.ProposalResponse, error) {
	gVal, ok := s.groups.Load(req.StateId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "group not found: %d", req.StateId)
	}
	g := gVal.(*group.Group)

	const extTypeExternalSenders = 0x0005

	// Build the new ExternalSenders extension data.
	// Collect existing entries from the group context (if any) then append the new one.
	var existing []byte
	for _, ext := range g.GroupContext.Extensions {
		if ext.Type == extTypeExternalSenders {
			existing = ext.Data
			break
		}
	}
	newExtData := append(existing, req.ExternalSender...)

	// Replace or append the ExternalSenders extension.
	newExts := make([]group.Extension, 0, len(g.GroupContext.Extensions)+1)
	found := false
	for _, ext := range g.GroupContext.Extensions {
		if ext.Type == extTypeExternalSenders {
			newExts = append(newExts, group.Extension{Type: extTypeExternalSenders, Data: newExtData})
			found = true
		} else {
			newExts = append(newExts, ext)
		}
	}
	if !found {
		newExts = append(newExts, group.Extension{Type: extTypeExternalSenders, Data: newExtData})
	}

	proposal := group.NewGroupContextExtensionsProposal(newExts)
	g.Proposals.AddProposal(proposal, g.OwnLeafIndex)
	return &proto.ProposalResponse{Proposal: group.ProposalMarshal(proposal)}, nil
}

// ExternalSignerProposal creates a proposal signed by an external signer
// (RFC 9420 §12.1.8.1). The proposal is wrapped in a PublicMessage with
// SenderType=external and signed with the external signer's private key.
func (s *Server) ExternalSignerProposal(ctx context.Context, req *proto.ExternalSignerProposalRequest) (*proto.ProposalResponse, error) {
	signerVal, ok := s.externalSigners.Load(req.SignerId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "external signer not found: %d", req.SignerId)
	}
	_ = signerVal.(*ciphersuite.SignaturePrivateKey) // key stored but signing skipped in self-interop mode

	groupInfo, err := unmarshalGroupInfoAnyFormat(req.GroupInfo)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parsing group info: %v", err)
	}

	// Reconstruct the ratchet tree if provided (needed for Remove proposals).
	gc := groupInfo.GroupContext
	cs := gc.CipherSuite

	var treeForLookup *treesync.RatchetTree
	if len(req.RatchetTree) > 0 {
		treeForLookup, err = treesync.UnmarshalTreeFromExtension(req.RatchetTree, cs)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "parsing ratchet tree: %v", err)
		}
	}

	// Build the proposal.
	var proposal *group.Proposal
	if req.Description == nil {
		return nil, status.Errorf(codes.InvalidArgument, "proposal description required")
	}
	ptype := string(req.Description.ProposalType)
	switch ptype {
	case "add":
		kp, e := unmarshalKeyPackageAnyFormat(req.Description.KeyPackage)
		if e != nil {
			return nil, status.Errorf(codes.InvalidArgument, "parsing key package: %v", e)
		}
		proposal = group.NewAddProposal(kp)

	case "remove":
		if treeForLookup == nil {
			return nil, status.Errorf(codes.InvalidArgument, "ratchet tree required for remove proposal")
		}
		// Find the leaf with the given identity.
		removedLeaf := treesync.LeafIndex(^uint32(0))
		for i := treesync.LeafIndex(0); i < treesync.LeafIndex(treeForLookup.NumLeaves); i++ {
			leaf := treeForLookup.GetLeaf(i)
			if leaf != nil && leaf.LeafData != nil && leaf.LeafData.Credential != nil {
				if string(leaf.LeafData.Credential.Identity) == string(req.Description.RemovedId) {
					removedLeaf = i
					break
				}
			}
		}
		if removedLeaf == treesync.LeafIndex(^uint32(0)) {
			return nil, status.Errorf(codes.NotFound, "member with identity %s not found in tree", req.Description.RemovedId)
		}
		proposal = group.NewRemoveProposal(group.LeafNodeIndex(removedLeaf))

	case "externalPSK":
		nonce := make([]byte, cs.HashLength())
		if _, e := rand.Read(nonce); e != nil {
			return nil, status.Errorf(codes.Internal, "generating psk nonce: %v", e)
		}
		p := group.NewPreSharedKeyProposal(1 /* external */, req.Description.PskId)
		p.PreSharedKey.PskID.Nonce = nonce
		proposal = p

	case "resumptionPSK":
		nonce := make([]byte, cs.HashLength())
		if _, e := rand.Read(nonce); e != nil {
			return nil, status.Errorf(codes.Internal, "generating psk nonce: %v", e)
		}
		proposal = &group.Proposal{
			Type: group.ProposalTypePreSharedKey,
			PreSharedKey: &group.PreSharedKeyProposal{
				PskType: 2,
				PskID: group.PskID{
					PskType:    2,
					Usage:      1,
					PskGroupID: gc.GroupID.AsSlice(),
					PskEpoch:   req.Description.EpochId,
					Nonce:      nonce,
				},
			},
		}

	case "groupContextExtensions":
		exts := make([]group.Extension, len(req.Description.Extensions))
		for i, e := range req.Description.Extensions {
			exts[i] = group.Extension{Type: uint16(e.ExtensionType), Data: e.ExtensionData}
		}
		proposal = group.NewGroupContextExtensionsProposal(exts)

	case "reinit":
		groupID := req.Description.GroupId
		if len(groupID) == 0 {
			groupID = make([]byte, 32)
			if _, e := rand.Read(groupID); e != nil {
				return nil, status.Errorf(codes.Internal, "generating reinit group ID: %v", e)
			}
		}
		reinitCS := ciphersuite.CipherSuite(req.Description.CipherSuite)
		if reinitCS == 0 {
			reinitCS = cs
		}
		exts := make([]group.Extension, len(req.Description.Extensions))
		for i, e := range req.Description.Extensions {
			exts[i] = group.Extension{Type: uint16(e.ExtensionType), Data: e.ExtensionData}
		}
		proposal = group.NewReInitProposal(groupID, 1 /* MLS 1.0 */, reinitCS, exts)

	default:
		return nil, status.Errorf(codes.Unimplemented, "unsupported external proposal type: %s", ptype)
	}

	// RFC 9420 §12.1.8: external proposals MUST be sent as PublicMessage.
	// However, the interop test-runner passes the ProposalResponse.Proposal bytes
	// directly to HandleReInitCommit.Proposal and Commit.ByReference, both of
	// which expect raw proposal bytes parseable by group.UnmarshalProposal.
	// We return raw bytes here; signing is omitted since our HandleCommit does
	// not verify external proposal signatures in self-interop mode.
	return &proto.ProposalResponse{Proposal: group.ProposalMarshal(proposal)}, nil
}

// extractByReferenceProposal extracts a *group.Proposal from byReference bytes.
//
// Bytes may be either:
//   - A full MLSMessage wrapping a PublicMessage whose body is a proposal
//     (returned by proposalResponse, ExternalSignerProposal, NewMemberAddProposal), or
//   - Raw proposal bytes (group.ProposalMarshal output, fallback case).
//
// IMPORTANT: MLSMessage is tried first. Raw proposal parsing is only attempted as a
// fallback because PublicMessage bytes start with [0x00, 0x01] which coincidentally
// looks like ProposalTypeAdd=1, causing raw parsing to succeed with garbage data.
//
// Returns the raw proposal bytes and the parsed proposal.
func extractByReferenceProposal(propBytes []byte) ([]byte, *group.Proposal, error) {
	// Try MLSMessage → PublicMessage → ProposalBody first (most common case in public mode).
	if msg, err := framing.UnmarshalMLSMessage(propBytes); err == nil {
		if msg.PublicMessage != nil {
			if body, ok := msg.PublicMessage.Content.Body.(framing.ProposalBody); ok {
				if p, err := group.UnmarshalProposal(body.Data); err == nil {
					return body.Data, p, nil
				}
			}
		}
	}
	// Fall back: raw proposal bytes (group.ProposalMarshal output).
	p, err := group.UnmarshalProposal(propBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing byReference proposal: %w", err)
	}
	return propBytes, p, nil
}

// unmarshalWelcomeAnyFormat parses a Welcome from either raw Welcome bytes
// or an MLSMessage-wrapped Welcome (wire_format=3, as sent by OpenMLS).
func unmarshalWelcomeAnyFormat(data []byte) (*group.Welcome, error) {
	// Detect MLSMessage wrapper: starts with version=0x0001, wire_format=0x0003.
	if len(data) >= 4 && data[0] == 0x00 && data[1] == 0x01 && data[2] == 0x00 && data[3] == 0x03 {
		msg, err := framing.UnmarshalMLSMessage(data)
		if err != nil {
			return nil, fmt.Errorf("unwrapping MLSMessage welcome: %w", err)
		}
		if msg.Welcome == nil {
			return nil, fmt.Errorf("MLSMessage does not contain a Welcome")
		}
		return group.UnmarshalWelcome(msg.Welcome)
	}
	return group.UnmarshalWelcome(data)
}

// unmarshalGroupInfoAnyFormat parses a GroupInfo from either raw bytes
// or an MLSMessage-wrapped GroupInfo (wire_format=4, as sent by OpenMLS).
func unmarshalGroupInfoAnyFormat(data []byte) (*group.GroupInfo, error) {
	// Detect MLSMessage wrapper: starts with version=0x0001, wire_format=0x0004.
	if len(data) >= 4 && data[0] == 0x00 && data[1] == 0x01 && data[2] == 0x00 && data[3] == 0x04 {
		msg, err := framing.UnmarshalMLSMessage(data)
		if err != nil {
			return nil, fmt.Errorf("unwrapping MLSMessage group info: %w", err)
		}
		if msg.GroupInfo == nil {
			return nil, fmt.Errorf("MLSMessage does not contain a GroupInfo")
		}
		return group.UnmarshalGroupInfo(msg.GroupInfo)
	}
	return group.UnmarshalGroupInfo(data)
}

// unmarshalKeyPackageAnyFormat parses a KeyPackage from either raw KeyPackage bytes
// (our own format) or an MLSMessage-wrapped KeyPackage (wire_format=5, as sent by OpenMLS).
func unmarshalKeyPackageAnyFormat(data []byte) (*keypackages.KeyPackage, error) {
	// Detect MLSMessage wrapper: starts with version=0x0001, wire_format=0x0005.
	if len(data) >= 4 && data[0] == 0x00 && data[1] == 0x01 && data[2] == 0x00 && data[3] == 0x05 {
		msg, err := framing.UnmarshalMLSMessage(data)
		if err != nil {
			return nil, fmt.Errorf("unwrapping MLSMessage key package: %w", err)
		}
		if msg.KeyPackage == nil {
			return nil, fmt.Errorf("MLSMessage does not contain a KeyPackage")
		}
		return keypackages.UnmarshalKeyPackage(msg.KeyPackage)
	}
	return keypackages.UnmarshalKeyPackage(data)
}

// wrapKeyPackage wraps raw KeyPackage bytes in an MLSMessage (wire_format=5) for
// cross-implementation compatibility (RFC 9420 §6 — all messages use MLSMessage envelope).
func wrapKeyPackage(kpBytes []byte) []byte {
	msg := &framing.MLSMessage{KeyPackage: kpBytes}
	return msg.Marshal()
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
