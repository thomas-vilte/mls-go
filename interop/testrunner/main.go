package main

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/thomas-vilte/mls-go/interop/server/proto"
)

// ClientMode represents the mode for assigning clients to roles.
type ClientMode string

// HandshakeMode represents the mode for handshake message encryption.
type HandshakeMode string

// ScriptAction represents a type of action in a test script.
type ScriptAction string

const (
	// ClientModeAll runs all combinations of client-to-role assignments.
	ClientModeAll ClientMode = "allCombinations"
	// ClientModeRandom runs a single random assignment of clients to roles.
	ClientModeRandom ClientMode = "random"

	// HandshakeModeAll runs both encrypted and plaintext handshakes.
	HandshakeModeAll HandshakeMode = "all"
	// HandshakeModePrivate runs only encrypted handshakes.
	HandshakeModePrivate HandshakeMode = "private"
	// HandshakeModePublic runs only plaintext handshakes.
	HandshakeModePublic HandshakeMode = "public"

	// ActionCreateGroup creates a group with the specified members.
	ActionCreateGroup ScriptAction = "createGroup"
	// ActionCreateKeyPackage creates a key package for a client.
	ActionCreateKeyPackage ScriptAction = "createKeyPackage"
	// ActionJoinGroup joins a group using a welcome message.
	ActionJoinGroup ScriptAction = "joinGroup"
	// ActionExternalJoin performs an external join.
	ActionExternalJoin ScriptAction = "externalJoin"
	// ActionInstallExternalPSK installs an external PSK for specified clients.
	ActionInstallExternalPSK ScriptAction = "installExternalPSK"
	// ActionGroupInfo retrieves group information.
	ActionGroupInfo ScriptAction = "groupInfo"
	// ActionAddProposal creates an add proposal.
	ActionAddProposal ScriptAction = "addProposal"
	// ActionUpdateProposal creates an update proposal.
	ActionUpdateProposal ScriptAction = "updateProposal"
	// ActionRemoveProposal creates a remove proposal.
	ActionRemoveProposal ScriptAction = "removeProposal"
	// ActionExternalPSKProposal creates an external PSK proposal.
	ActionExternalPSKProposal ScriptAction = "externalPSKProposal"
	// ActionResumptionPSKProposal creates a resumption PSK proposal.
	ActionResumptionPSKProposal ScriptAction = "resumptionPSKProposal"
	// ActionGroupContextExtensionsProposal creates a group context extensions proposal.
	ActionGroupContextExtensionsProposal ScriptAction = "groupContextExtensionsProposal"
	// ActionFullCommit creates a commit and applies it to all members and joiners.
	ActionFullCommit ScriptAction = "fullCommit"
	// ActionCommit creates a commit without applying it.
	ActionCommit ScriptAction = "commit"
	// ActionHandleCommit handles an incoming commit.
	ActionHandleCommit ScriptAction = "handleCommit"
	// ActionHandlePendingCommit handles a pending commit at the committer.
	ActionHandlePendingCommit ScriptAction = "handlePendingCommit"
	// ActionProtect encrypts application data.
	ActionProtect ScriptAction = "protect"
	// ActionUnprotect decrypts application data.
	ActionUnprotect ScriptAction = "unprotect"
	// ActionReInit reinitializes a group.
	ActionReInit ScriptAction = "reinit"
	// ActionBranch branches a group into a new group.
	ActionBranch ScriptAction = "branch"
	// ActionNewMemberAddProposal creates a self-signed add proposal from a new member.
	ActionNewMemberAddProposal ScriptAction = "newMemberAddProposal"
	// ActionAddExternalSigner adds an external signer to a group.
	ActionAddExternalSigner ScriptAction = "addExternalSigner"
	// ActionExternalSignerProposal creates a proposal signed by an external signer.
	ActionExternalSignerProposal ScriptAction = "externalSignerProposal"

	// TimeoutSeconds is the default timeout for RPC calls.
	TimeoutSeconds = 120
)

// ScriptStep represents a single step in a test script.
type ScriptStep struct {
	// Actor is the name of the actor performing this step.
	Actor string `json:"actor"`
	// Action is the action to perform.
	Action ScriptAction `json:"action"`
	// Raw is the raw JSON of the step parameters.
	Raw []byte `json:"raw"`
}

// CreateGroupStepParams contains parameters for creating a group.
type CreateGroupStepParams struct {
	// Members is the list of initial members to add.
	Members []string `json:"members"`
}

// JoinGroupStepParams contains parameters for joining a group.
type JoinGroupStepParams struct {
	// Welcome is the index of the welcome message.
	Welcome int `json:"welcome"`
}

// ExternalJoinStepParams contains parameters for an external join.
type ExternalJoinStepParams struct {
	// Joiner is the name of the joiner.
	Joiner string `json:"joiner"`
	// Members is the list of existing members.
	Members []string `json:"members"`
	// ExternalTree indicates whether to use an external ratchet tree.
	ExternalTree bool `json:"externalTree"`
	// RemovePrior indicates whether to remove prior members.
	RemovePrior bool `json:"removePrior"`
	// PSKs is the list of PSK indices.
	PSKs []int `json:"psks"`
}

// GroupInfoStepParams contains parameters for retrieving group info.
type GroupInfoStepParams struct {
	// ExternalTree indicates whether to include an external ratchet tree.
	ExternalTree bool `json:"externalTree"`
}

// InstallExternalPSKStepParams contains parameters for installing an external PSK.
type InstallExternalPSKStepParams struct {
	// Clients is the list of clients to install the PSK on.
	Clients []string `json:"clients"`
}

// AddProposalStepParams contains parameters for an add proposal.
type AddProposalStepParams struct {
	// KeyPackage is the index of the key package.
	KeyPackage int `json:"keyPackage"`
}

// RemoveProposalStepParams contains parameters for a remove proposal.
type RemoveProposalStepParams struct {
	// Removed is the name of the member to remove.
	Removed string `json:"removed"`
}

// ExternalPSKProposalStepParams contains parameters for an external PSK proposal.
type ExternalPSKProposalStepParams struct {
	// PskId is the index of the PSK ID.
	PskId int `json:"pskID"`
}

// ResumptionPSKProposalStepParams contains parameters for a resumption PSK proposal.
type ResumptionPSKProposalStepParams struct {
	// EpochId is the epoch ID for the resumption PSK.
	EpochId int `json:"epochID"`
}

// GroupContextExtensionsProposalStepParams contains parameters for a group context extensions proposal.
type GroupContextExtensionsProposalStepParams struct {
	// Extensions is the list of extensions to propose.
	Extensions []*pb.Extension `json:"extensions"`
}

// ProposalDescription describes a proposal to include in a commit.
type ProposalDescription struct {
	// ProposalType is the type of proposal (e.g. "add", "remove").
	ProposalType string `json:"proposalType"`
	// KeyPackage is the index of the key package (for add proposals).
	KeyPackage int `json:"keyPackage"`
	// Removed is the name of the member to remove (for remove proposals).
	Removed string `json:"removed"`
	// PskId is the index of the PSK ID (for external PSK proposals).
	PskId int `json:"pskID"`
	// EpochId is the epoch ID (for resumption PSK proposals).
	EpochId int `json:"epochID"`
	// Extensions is the list of extensions (for GCE proposals).
	Extensions []*pb.Extension `json:"extensions"`
	// ChangeGroupId indicates whether to generate a new group ID.
	ChangeGroupId bool `json:"changeGroupID"`
	// ChangeCipherSuite indicates whether to change the ciphersuite.
	ChangeCipherSuite bool `json:"changeCipherSuite"`
}

// ProposalDescriptionToProto converts a ProposalDescription to a protobuf ProposalDescription.
func (proposalDescription *ProposalDescription) ProposalDescriptionToProto(config *ScriptActorConfig) (*pb.ProposalDescription, error) {
	proposalDescProto := &pb.ProposalDescription{ProposalType: []byte(proposalDescription.ProposalType)}
	var err error

	switch proposalDescription.ProposalType {
	case "add":
		proposalDescProto.KeyPackage, err = config.GetMessage(proposalDescription.KeyPackage, "key_package")
	case "remove":
		proposalDescProto.RemovedId = []byte(proposalDescription.Removed)
	case "externalPSK":
		proposalDescProto.PskId, err = config.GetMessage(proposalDescription.PskId, "psk_id")
	case "resumptionPSK":
		proposalDescProto.EpochId = uint64(proposalDescription.EpochId)
	case "groupContextExtensions":
		proposalDescProto.Extensions = proposalDescription.Extensions
	case "reinit":
		proposalDescProto.Extensions = proposalDescription.Extensions
		if proposalDescription.ChangeCipherSuite {
			err = config.ChangeCipherSuite()
			if err != nil {
				return nil, err
			}
		}
		proposalDescProto.CipherSuite = config.CipherSuite
		proposalDescProto.GroupId, err = config.NewGroupID(proposalDescription.ChangeGroupId)

	default:
		err = fmt.Errorf("unknown proposal type [%s]", proposalDescription.ProposalType)
	}

	if err != nil {
		return nil, err
	}

	return proposalDescProto, nil
}

// FullCommitStepParams contains parameters for a full commit step.
type FullCommitStepParams struct {
	// ByReference is the list of proposal indices to include by reference.
	ByReference []int `json:"byReference"`
	// ByValue is the list of proposals to include by value.
	ByValue []ProposalDescription `json:"byValue"`
	// Members is the list of existing members to apply the commit to.
	Members []string `json:"members"`
	// Joiners is the list of new members to join after the commit.
	Joiners []string `json:"joiners"`
	// ForcePath indicates whether to force a path update.
	ForcePath bool `json:"force_path"`
	// ExternalTree indicates whether to use an external ratchet tree.
	ExternalTree bool `json:"external_tree"`
}

// CommitStepParams contains parameters for a commit step.
type CommitStepParams struct {
	// ByReference is the list of proposal indices to include by reference.
	ByReference []int `json:"byReference"`
	// ByValue is the list of proposals to include by value.
	ByValue []ProposalDescription `json:"byValue"`
	// ForcePath indicates whether to force a path update.
	ForcePath bool `json:"force_path"`
	// ExternalTree indicates whether to use an external ratchet tree.
	ExternalTree bool `json:"external_tree"`
}

// HandleCommitStepParams contains parameters for handling a commit.
type HandleCommitStepParams struct {
	// Commit is the index of the commit message.
	Commit int `json:"commit"`
	// ByReference is the list of proposal indices referenced in the commit.
	ByReference []int `json:"byReference"`
}

// ProtectStepParams contains parameters for encrypting application data.
type ProtectStepParams struct {
	// AuthenticatedData is the authenticated data.
	AuthenticatedData string `json:"authenticatedData"`
	// Plaintext is the plaintext to encrypt.
	Plaintext string `json:"plaintext"`
}

// UnprotectStepParams contains parameters for decrypting application data.
type UnprotectStepParams struct {
	// Ciphertext is the index of the ciphertext to decrypt.
	Ciphertext int `json:"ciphertext"`
}

// ReInitStepParams contains parameters for reinitializing a group.
type ReInitStepParams struct {
	// Proposer is the name of the proposer (empty if using external proposal).
	Proposer string `json:"proposer"`
	// Committer is the name of the committer.
	Committer string `json:"committer"`
	// Welcomer is the name of the welcomer.
	Welcomer string `json:"welcomer"`
	// Members is the list of existing members.
	Members []string `json:"members"`
	// ChangeCipherSuite indicates whether to change the ciphersuite.
	ChangeCipherSuite bool `json:"changeCipherSuite"`
	// ChangeGroupID indicates whether to change the group ID.
	ChangeGroupID bool `json:"changeGroupID"`
	// Extensions is the list of extensions for the new group.
	Extensions []*pb.Extension `json:"extensions"`
	// ForcePath indicates whether to force a path update.
	ForcePath bool `json:"forcePath"`
	// ExternalTree indicates whether to use an external ratchet tree.
	ExternalTree bool `json:"externalTree"`
	// ExternalReinitProposal is the index of an external reinit proposal.
	ExternalReinitProposal int `json:"externalReinitProposal"`
}

// BranchStepParams contains parameters for branching a group.
type BranchStepParams struct {
	// Members is the list of members to include in the branch.
	Members []string `json:"members"`
	// ForcePath indicates whether to force a path update.
	ForcePath bool `json:"force_path"`
	// ExternalTree indicates whether to use an external ratchet tree.
	ExternalTree bool `json:"external_tree"`
	// Extensions is the list of extensions for the new branch.
	Extensions []*pb.Extension `json:"extensions"`
}

// NewMemberAddProposalStepParams contains parameters for a new member add proposal.
type NewMemberAddProposalStepParams struct {
	// Joiner is the name of the joining member.
	Joiner string `json:"joiner"`
}

// AddExternalSignerStepParams contains parameters for adding an external signer.
type AddExternalSignerStepParams struct {
	// Signer is the name of the external signer.
	Signer string `json:"signer"`
}

// ExternalSignerProposalStepParams contains parameters for creating a proposal signed by an external signer.
type ExternalSignerProposalStepParams struct {
	// Member is the name of the group member providing group info.
	Member string `json:"member"`
	// Description is the proposal description.
	Description ProposalDescription `json:"description"`
}

func (step *ScriptStep) UnmarshalJSON(data []byte) error {
	var parsed map[string]interface{}
	err := json.Unmarshal(data, &parsed)
	if err != nil {
		return err
	}

	if action, ok := parsed["action"]; ok {
		step.Action = ScriptAction(action.(string))
	} else {
		return fmt.Errorf("incomplete step: Missing action")
	}

	if actor, ok := parsed["actor"]; ok {
		step.Actor = actor.(string)
	}

	step.Raw = make([]byte, len(data))
	copy(step.Raw, data)

	return nil
}

// Script is a sequence of script steps.
type Script []ScriptStep

func (s Script) Actors() []string {
	actorMap := map[string]bool{}
	for _, step := range s {
		if len(step.Actor) == 0 {
			continue
		}

		actorMap[step.Actor] = true

		if step.Action == ActionCreateGroup {
			var params CreateGroupStepParams
			err := json.Unmarshal(step.Raw, &params)
			if err != nil {
				continue
			}

			for _, member := range params.Members {
				actorMap[member] = true
			}
		}

		if step.Action == ActionExternalJoin {
			var params ExternalJoinStepParams
			err := json.Unmarshal(step.Raw, &params)
			if err != nil {
				continue
			}

			actorMap[params.Joiner] = true
		}

		if step.Action == ActionNewMemberAddProposal {
			var params NewMemberAddProposalStepParams
			err := json.Unmarshal(step.Raw, &params)
			if err != nil {
				continue
			}

			actorMap[params.Joiner] = true
		}

		if step.Action == ActionAddExternalSigner {
			var params AddExternalSignerStepParams
			err := json.Unmarshal(step.Raw, &params)
			if err != nil {
				continue
			}

			actorMap[params.Signer] = true
		}
	}

	actors := make([]string, 0, len(actorMap))
	for actor := range actorMap {
		actors = append(actors, actor)
	}

	return actors
}

// RunConfig represents the test runner configuration.
type RunConfig struct {
	// Mode is the client assignment mode.
	Mode ClientMode `json:"mode,omitempty"`
	// Scripts is a map of script names to script steps.
	Scripts map[string]Script `json:"scripts,omitempty"`
}

// /
// / Results
// /

// RPCTranscriptEntry records a single RPC call in a script execution.
type RPCTranscriptEntry struct {
	// Actor is the name of the actor.
	Actor string `json:"actor"`
	// RPC is the name of the RPC method.
	RPC string `json:"rpc"`
	// Request is the request payload.
	Request interface{} `json:"request"`
	// Response is the response payload.
	Response interface{} `json:"response"`
}

// ScriptResult holds the result of running a script with a specific configuration.
type ScriptResult struct {
	// CipherSuite is the ciphersuite used.
	CipherSuite uint32 `json:"cipher_suite"`
	// Actors maps actor names to client names.
	Actors map[string]string `json:"actors"`
	// EncryptHandshake indicates whether handshake messages were encrypted.
	EncryptHandshake bool `json:"encrypt_flag"`

	// Transcript is the RPC transcript (only populated on failure).
	Transcript []RPCTranscriptEntry `json:"transcript,omitempty"`
	// Error is the error message if the script failed.
	Error interface{} `json:"error,omitempty"`
	// FailedStep is the index of the step that failed.
	FailedStep *int `json:"failed_step,omitempty"`
	// FailedStepJSON is the raw JSON of the failed step.
	FailedStepJSON string `json:"failed_step_json,omitempty"`
}

// ScriptResults is a list of script results.
type ScriptResults []ScriptResult

// TestResults holds results for all scripts.
type TestResults struct {
	// Scripts maps script names to their results.
	Scripts map[string]ScriptResults `json:"scripts"`
}

// Client represents a connection to an MLS client.
type Client struct {
	conn      *grpc.ClientConn
	rpc       pb.MLSClientClient
	name      string
	supported map[uint32]bool
}

func ctx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*TimeoutSeconds)
	go func() {
		<-ctx.Done()
		cancel()
	}()
	return ctx
}

// NewClient creates a new Client connected to the given address.
func NewClient(addr string) (*Client, error) {
	c := &Client{}
	var err error

	defer func() {
		if err != nil && c.conn != nil {
			_ = c.conn.Close()
		}
	}()

	c.conn, err = grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	c.rpc = pb.NewMLSClientClient(c.conn)

	// Get the client's name and supported ciphersuites
	nr, err := c.rpc.Name(ctx(), &pb.NameRequest{})
	if err != nil {
		_ = c.conn.Close()
		return nil, err
	}

	scr, err := c.rpc.SupportedCiphersuites(ctx(), &pb.SupportedCiphersuitesRequest{})
	if err != nil {
		_ = c.conn.Close()
		return nil, err
	}

	c.name = nr.GetName()
	c.supported = map[uint32]bool{}
	for _, suite := range scr.GetCiphersuites() {
		c.supported[suite] = true
	}

	return c, nil
}

// ClientPool manages a pool of connected MLS clients.
type ClientPool struct {
	clients      []*Client
	suiteSupport map[uint32][]int
}

// NewClientPool creates a ClientPool from a list of client addresses.
func NewClientPool(configs []string) (*ClientPool, error) {
	p := &ClientPool{
		clients:      make([]*Client, len(configs)),
		suiteSupport: map[uint32][]int{},
	}

	var err error
	for i, addr := range configs {
		p.clients[i], err = NewClient(addr)
		if err != nil {
			p.Close()
			return nil, err
		}

		for suite := range p.clients[i].supported {
			p.suiteSupport[suite] = append(p.suiteSupport[suite], i)
		}
	}

	return p, nil
}

func (p *ClientPool) Close() {
	for _, c := range p.clients {
		_ = c.conn.Close()
	}
}

func randomCombination(vals, slots int) []int {
	combo := make([]int, slots)
	for i := range combo {
		combo[i] = rand.Intn(vals)
	}
	return combo
}

func combinations(vals, slots int) [][]int {
	return combinationsInner(vals, slots, [][]int{{}})
}

func combinationsInner(vals int, slots int, base [][]int) [][]int {
	if slots == 0 {
		return base
	}

	ix := make([]bool, vals)
	out := make([][]int, 0, vals*len(base))
	for _, tuple := range base {
		for v := range ix {
			out = append(out, append(tuple, v))
		}
	}

	return combinationsInner(vals, slots-1, out)
}

// ScriptActorConfig represents the configuration for running a single script iteration.
// Each script is run for each combination of ciphersuite, client-to-role assignment,
// and encrypted or plaintext handshake.
// ScriptActorConfig holds the configuration for running a script with specific actors.
type ScriptActorConfig struct {
	// CipherSuite is the ciphersuite to use.
	CipherSuite uint32
	// EncryptHandshake indicates whether to encrypt handshake messages.
	EncryptHandshake bool
	// ActorClients maps actor names to client connections.
	ActorClients map[string]*Client

	stateID       map[string]uint32
	transactionID map[string]uint32
	signerID      map[string]uint32
	messageCache  []map[string]string
	transcript    []RPCTranscriptEntry
}

func (config *ScriptActorConfig) Log(actor string, rpc string, request, response interface{}) {
	// Keep only the last 200 entries to bound memory for large scripts (e.g. deep_random).
	const maxTranscriptEntries = 200
	config.transcript = append(config.transcript, RPCTranscriptEntry{actor, rpc, request, response})
	if len(config.transcript) > maxTranscriptEntries {
		config.transcript = config.transcript[len(config.transcript)-maxTranscriptEntries:]
	}
}

func (config *ScriptActorConfig) StoreMessage(index int, key string, message []byte) {
	config.messageCache[index][key] = hex.EncodeToString(message)
}

func (config *ScriptActorConfig) GetMessage(index int, key string) ([]byte, error) {
	messageHex, ok := config.messageCache[index][key]
	if !ok {
		return nil, fmt.Errorf("no message for key %s at step %d", key, index)
	}

	message, err := hex.DecodeString(messageHex)
	if err != nil {
		return nil, err
	}

	return message, nil
}

func (config *ScriptActorConfig) StoreInteger(index int, key string, integer uint32) {
	config.messageCache[index][key] = strconv.FormatUint(uint64(integer), 10)
}

func (config *ScriptActorConfig) NewGroupID(changeId bool) ([]byte, error) {
	newGroupID, err := config.GetMessage(0, "group_id")
	if err != nil {
		return nil, err
	}
	if changeId {
		newGroupID = append(newGroupID, []byte("++")...)
	}
	return newGroupID, nil
}

func (config *ScriptActorConfig) ChangeCipherSuite() error {
	// Compute the set of ciphersuites supported by all clients
	var supportedSuites map[uint32]bool
	for _, client := range config.ActorClients {
		// Initialize with the first client
		if supportedSuites == nil {
			supportedSuites = map[uint32]bool{}
			for suite := range client.supported {
				supportedSuites[suite] = true
			}
			continue
		}

		// Then remove suites not supported by other clients
		for suite := range supportedSuites {
			if !client.supported[suite] {
				delete(supportedSuites, suite)
			}
		}
	}

	// Remove the current ciphersuite
	delete(supportedSuites, config.CipherSuite)

	// Select one of the remaining ones
	if len(supportedSuites) == 0 {
		return fmt.Errorf("no remaining supported ciphersuite")
	}

	for suite := range supportedSuites {
		config.CipherSuite = suite
		break
	}

	return nil
}

func (config *ScriptActorConfig) RunStep(index int, step ScriptStep) error {
	switch step.Action {
	case ActionCreateGroup:
		var params CreateGroupStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		// Create the group
		groupID := []byte(uuid.New().String())
		{
			client := config.ActorClients[step.Actor]
			req := &pb.CreateGroupRequest{
				GroupId:          groupID,
				CipherSuite:      config.CipherSuite,
				EncryptHandshake: config.EncryptHandshake,
				Identity:         []byte(step.Actor),
			}
			resp, err := client.rpc.CreateGroup(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(step.Actor, "CreateGroup", req, resp)

			config.stateID[step.Actor] = resp.StateId
			config.StoreMessage(index, "group_id", groupID)
		}

		// If there are no new members to add, we're done
		if len(params.Members) == 0 {
			return nil
		}

		// Get key packages from the joiners
		keyPackages := make([][]byte, len(params.Members))
		transactionIDs := make([]uint32, len(params.Members))
		for i, member := range params.Members {
			client := config.ActorClients[member]
			req := &pb.CreateKeyPackageRequest{
				CipherSuite: config.CipherSuite,
				Identity:    []byte(member),
			}
			resp, err := client.rpc.CreateKeyPackage(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(member, "CreateKeyPackage", req, resp)

			keyPackages[i] = resp.KeyPackage
			transactionIDs[i] = resp.TransactionId
		}

		// Create and consume a Commit with inline Add proposals
		var welcome []byte
		var epochAuthenticator []byte
		{
			byValue := make([]*pb.ProposalDescription, len(keyPackages))
			for i, keyPackage := range keyPackages {
				byValue[i] = &pb.ProposalDescription{
					ProposalType: []byte("add"),
					KeyPackage:   keyPackage,
				}
			}

			client := config.ActorClients[step.Actor]
			req := &pb.CommitRequest{
				StateId: config.stateID[step.Actor],
				ByValue: byValue,
			}
			resp, err := client.rpc.Commit(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(step.Actor, "Commit", req, resp)

			welcome = resp.Welcome
		}

		// Handle the commit at the creator
		{
			client := config.ActorClients[step.Actor]
			req := &pb.HandlePendingCommitRequest{
				StateId: config.stateID[step.Actor],
			}
			resp, err := client.rpc.HandlePendingCommit(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(step.Actor, "HandlePendingCommit", req, resp)

			config.stateID[step.Actor] = resp.StateId
			epochAuthenticator = resp.EpochAuthenticator
		}

		// Initialize the joiners
		for i, member := range params.Members {
			client := config.ActorClients[member]
			req := &pb.JoinGroupRequest{
				TransactionId:    transactionIDs[i],
				Welcome:          welcome,
				EncryptHandshake: config.EncryptHandshake,
				Identity:         []byte(member),
			}
			resp, err := client.rpc.JoinGroup(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(member, "JoinGroup", req, resp)

			if !bytes.Equal(resp.EpochAuthenticator, epochAuthenticator) {
				return fmt.Errorf("joiner [%s] failed to agree on epoch authenticator", member)
			}

			config.stateID[member] = resp.StateId
		}

	case ActionCreateKeyPackage:
		client := config.ActorClients[step.Actor]
		req := &pb.CreateKeyPackageRequest{
			CipherSuite: config.CipherSuite,
			Identity:    []byte(step.Actor),
		}
		resp, err := client.rpc.CreateKeyPackage(ctx(), req)
		if err != nil {
			return err
		}
		config.Log(step.Actor, "CreateKeyPackage", req, resp)

		config.transactionID[step.Actor] = resp.TransactionId
		config.StoreMessage(index, "key_package", resp.KeyPackage)

	case ActionJoinGroup:
		client := config.ActorClients[step.Actor]
		var params JoinGroupStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		welcome, err := config.GetMessage(params.Welcome, "welcome")
		if err != nil {
			return err
		}

		txID, ok := config.transactionID[step.Actor]
		if !ok {
			return fmt.Errorf("malformed step: No transaction for %s", step.Actor)
		}

		req := &pb.JoinGroupRequest{
			TransactionId:    txID,
			Welcome:          welcome,
			EncryptHandshake: config.EncryptHandshake,
			Identity:         []byte(step.Actor),
		}
		resp, err := client.rpc.JoinGroup(ctx(), req)
		if err != nil {
			return err
		}
		config.Log(step.Actor, "JoinGroup", req, resp)

		config.stateID[step.Actor] = resp.StateId

	case ActionExternalJoin:
		var params ExternalJoinStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		// Get a GroupInfo and maybe a ratchet tree from the adder
		var groupInfo []byte
		var ratchetTree []byte
		{
			client := config.ActorClients[step.Actor]
			req := &pb.GroupInfoRequest{
				StateId:      config.stateID[step.Actor],
				ExternalTree: params.ExternalTree,
			}
			resp, err := client.rpc.GroupInfo(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(step.Actor, "GroupInfo", req, resp)

			groupInfo = resp.GroupInfo
			ratchetTree = resp.RatchetTree
		}

		config.StoreMessage(index, "group_info", groupInfo)
		config.StoreMessage(index, "ratchet_tree", ratchetTree)

		// Create an external Commit
		var commit []byte
		var epochAuthenticator []byte
		{
			psks := make([]*pb.PreSharedKey, len(params.PSKs))
			for i, pskIx := range params.PSKs {
				pskID, err := config.GetMessage(pskIx, "psk_id")
				if err != nil {
					return err
				}

				pskSecret, err := config.GetMessage(pskIx, "psk_secret")
				if err != nil {
					return err
				}

				psks[i] = &pb.PreSharedKey{PskId: pskID, PskSecret: pskSecret}
			}

			client := config.ActorClients[params.Joiner]
			req := &pb.ExternalJoinRequest{
				GroupInfo:        groupInfo,
				RatchetTree:      ratchetTree,
				EncryptHandshake: config.EncryptHandshake,
				Identity:         []byte(params.Joiner),
				RemovePrior:      params.RemovePrior,
				Psks:             psks,
			}
			resp, err := client.rpc.ExternalJoin(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(params.Joiner, "ExternalJoin", req, resp)

			config.stateID[params.Joiner] = resp.StateId

			commit = resp.Commit
			epochAuthenticator = resp.EpochAuthenticator
		}

		config.StoreMessage(index, "commit", commit)
		config.StoreMessage(index, "epoch_authenticator", epochAuthenticator)

		// Process the Commit at the adder and other members
		params.Members = append(params.Members, step.Actor)
		for _, member := range params.Members {
			client := config.ActorClients[member]
			req := &pb.HandleCommitRequest{
				StateId: config.stateID[member],
				Commit:  commit,
			}
			resp, err := client.rpc.HandleCommit(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(member, "HandleCommit", req, resp)

			if !bytes.Equal(resp.EpochAuthenticator, epochAuthenticator) {
				return fmt.Errorf("member [%s] failed to agree on epoch authenticator", member)
			}

			config.stateID[member] = resp.StateId
		}

	case ActionInstallExternalPSK:
		var params InstallExternalPSKStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		pskID := make([]byte, 32)
		if _, err := cryptorand.Read(pskID); err != nil {
			return err
		}
		config.StoreMessage(index, "psk_id", pskID)

		pskSecret := make([]byte, 32)
		if _, err := cryptorand.Read(pskSecret); err != nil {
			return err
		}
		config.StoreMessage(index, "psk_secret", pskSecret)

		for _, clientName := range params.Clients {
			client := config.ActorClients[clientName]

			id := uint32(0)
			if stateID, ok := config.stateID[clientName]; ok {
				id = stateID
			} else if txID, ok := config.transactionID[clientName]; ok {
				id = txID
			}

			req := &pb.StorePSKRequest{
				StateOrTransactionId: id,
				PskId:                pskID,
				PskSecret:            pskSecret,
			}
			resp, err := client.rpc.StorePSK(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(clientName, "StorePSK", req, resp)
		}

	case ActionGroupInfo:
		client := config.ActorClients[step.Actor]
		var params GroupInfoStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		req := &pb.GroupInfoRequest{
			StateId:      config.stateID[step.Actor],
			ExternalTree: params.ExternalTree,
		}
		resp, err := client.rpc.GroupInfo(ctx(), req)
		if err != nil {
			return err
		}
		config.Log(step.Actor, "GroupInfo", req, resp)

		config.StoreMessage(index, "group_info", resp.GroupInfo)
		config.StoreMessage(index, "ratchet_tree", resp.RatchetTree)

	case ActionAddProposal:
		client := config.ActorClients[step.Actor]
		var params AddProposalStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		keyPackage, err := config.GetMessage(params.KeyPackage, "key_package")
		if err != nil {
			return err
		}

		req := &pb.AddProposalRequest{
			StateId:    config.stateID[step.Actor],
			KeyPackage: keyPackage,
		}
		resp, err := client.rpc.AddProposal(ctx(), req)
		if err != nil {
			return err
		}
		config.Log(step.Actor, "AddProposal", req, resp)

		config.StoreMessage(index, "proposal", resp.Proposal)

	case ActionRemoveProposal:
		client := config.ActorClients[step.Actor]
		var params RemoveProposalStepParams
		err := json.Unmarshal(step.Raw, &params)

		if err != nil {
			return err
		}

		req := &pb.RemoveProposalRequest{
			StateId:   config.stateID[step.Actor],
			RemovedId: []byte(params.Removed),
		}
		resp, err := client.rpc.RemoveProposal(ctx(), req)
		if err != nil {
			return err
		}
		config.Log(step.Actor, "RemoveProposal", req, resp)

		config.StoreMessage(index, "proposal", resp.Proposal)

	case ActionUpdateProposal:
		client := config.ActorClients[step.Actor]

		req := &pb.UpdateProposalRequest{
			StateId: config.stateID[step.Actor],
		}
		resp, err := client.rpc.UpdateProposal(ctx(), req)
		if err != nil {
			return err
		}
		config.Log(step.Actor, "UpdateProposal", req, resp)

		config.StoreMessage(index, "proposal", resp.Proposal)

	case ActionExternalPSKProposal:
		client := config.ActorClients[step.Actor]
		var params ExternalPSKProposalStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		pskID, err := config.GetMessage(params.PskId, "psk_id")
		if err != nil {
			return err
		}

		req := &pb.ExternalPSKProposalRequest{
			StateId: config.stateID[step.Actor],
			PskId:   pskID,
		}
		resp, err := client.rpc.ExternalPSKProposal(ctx(), req)
		if err != nil {
			return err
		}
		config.Log(step.Actor, "ExternalPSKProposal", req, resp)

		config.StoreMessage(index, "proposal", resp.Proposal)

	case ActionResumptionPSKProposal:
		client := config.ActorClients[step.Actor]
		var params ResumptionPSKProposalStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		req := &pb.ResumptionPSKProposalRequest{
			StateId: config.stateID[step.Actor],
			EpochId: uint64(params.EpochId),
		}
		resp, err := client.rpc.ResumptionPSKProposal(ctx(), req)
		if err != nil {
			return err
		}
		config.Log(step.Actor, "ResumptionPSKProposal", req, resp)

		config.StoreMessage(index, "proposal", resp.Proposal)

	case ActionGroupContextExtensionsProposal:
		client := config.ActorClients[step.Actor]
		var params GroupContextExtensionsProposalStepParams
		err := json.Unmarshal(step.Raw, &params)

		if err != nil {
			return err
		}

		req := &pb.GroupContextExtensionsProposalRequest{
			StateId:    config.stateID[step.Actor],
			Extensions: params.Extensions,
		}
		resp, err := client.rpc.GroupContextExtensionsProposal(ctx(), req)
		if err != nil {
			return err
		}
		config.Log(step.Actor, "GroupContextExtensionsProposal", req, resp)

		config.StoreMessage(index, "proposal", resp.Proposal)

	case ActionFullCommit:
		client := config.ActorClients[step.Actor]
		var params FullCommitStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		// Create the Commit [ActionCommit]
		byRef := make([][]byte, len(params.ByReference))
		for i, ix64 := range params.ByReference {
			byRef[i], err = config.GetMessage(ix64, "proposal")
			if err != nil {
				return err
			}
		}

		byVal := make([]*pb.ProposalDescription, len(params.ByValue))
		for i, proposalDescription := range params.ByValue {
			byVal[i], err = proposalDescription.ProposalDescriptionToProto(config)
			if err != nil {
				return err
			}
		}

		commitReq := &pb.CommitRequest{
			StateId:      config.stateID[step.Actor],
			ByReference:  byRef,
			ByValue:      byVal,
			ForcePath:    params.ForcePath,
			ExternalTree: params.ExternalTree,
		}
		commitResp, err := client.rpc.Commit(ctx(), commitReq)
		if err != nil {
			return err
		}
		config.Log(step.Actor, "Commit", commitReq, commitResp)

		config.StoreMessage(index, "welcome", commitResp.Welcome)
		config.StoreMessage(index, "commit", commitResp.Commit)
		if params.ExternalTree {
			config.StoreMessage(index, "ratchet_tree", commitResp.RatchetTree)
		}

		// Apply it at the committer [ActionHandlePendingCommit]
		var epochAuthenticator []byte
		{
			req := &pb.HandlePendingCommitRequest{
				StateId: config.stateID[step.Actor],
			}
			resp, err := client.rpc.HandlePendingCommit(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(step.Actor, "HandlePendingCommit", req, resp)

			config.stateID[step.Actor] = resp.StateId
			epochAuthenticator = resp.EpochAuthenticator
		}

		config.StoreMessage(index, "epoch_authenticator", epochAuthenticator)

		// Apply it at the other members [ActionHandleCommit]
		for _, member := range params.Members {
			client := config.ActorClients[member]
			req := &pb.HandleCommitRequest{
				StateId:  config.stateID[member],
				Proposal: byRef,
				Commit:   commitResp.Commit,
			}
			resp, err := client.rpc.HandleCommit(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(member, "HandleCommit", req, resp)

			if !bytes.Equal(resp.EpochAuthenticator, epochAuthenticator) {
				return fmt.Errorf("member [%s] failed to agree on epoch authenticator", member)
			}

			config.stateID[member] = resp.StateId
		}

		// Initialize the joiners [ActionJoinGroup]
		for _, joiner := range params.Joiners {
			txID, ok := config.transactionID[joiner]
			if !ok {
				return fmt.Errorf("malformed step: No transaction for %s", joiner)
			}

			client := config.ActorClients[joiner]

			req := &pb.JoinGroupRequest{
				TransactionId:    txID,
				Welcome:          commitResp.Welcome,
				EncryptHandshake: config.EncryptHandshake,
				Identity:         []byte(joiner),
			}

			if params.ExternalTree {
				req.RatchetTree = commitResp.RatchetTree
			}

			resp, err := client.rpc.JoinGroup(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(joiner, "JoinGroup", req, resp)

			if !bytes.Equal(resp.EpochAuthenticator, epochAuthenticator) {
				return fmt.Errorf("joiner [%s] failed to agree on epoch authenticator", joiner)
			}

			config.stateID[joiner] = resp.StateId
		}

	case ActionCommit:
		client := config.ActorClients[step.Actor]
		var params CommitStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		byRef := make([][]byte, len(params.ByReference))
		for i, ix64 := range params.ByReference {
			byRef[i], err = config.GetMessage(ix64, "proposal")
			if err != nil {
				return err
			}
		}

		byVal := make([]*pb.ProposalDescription, len(params.ByValue))
		for i, proposalDescription := range params.ByValue {
			byVal[i], err = proposalDescription.ProposalDescriptionToProto(config)
			if err != nil {
				return err
			}
		}

		req := &pb.CommitRequest{
			StateId:      config.stateID[step.Actor],
			ByReference:  byRef,
			ByValue:      byVal,
			ForcePath:    params.ForcePath,
			ExternalTree: params.ExternalTree,
		}
		resp, err := client.rpc.Commit(ctx(), req)
		if err != nil {
			return err
		}
		config.Log(step.Actor, "Commit", req, resp)

		config.StoreMessage(index, "commit", resp.Commit)
		config.StoreMessage(index, "welcome", resp.Welcome)
		if params.ExternalTree {
			config.StoreMessage(index, "ratchet_tree", resp.RatchetTree)
		}

	case ActionProtect:
		client := config.ActorClients[step.Actor]
		var params ProtectStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		authenticatedData := []byte(params.AuthenticatedData)
		plaintext := []byte(params.Plaintext)
		req := &pb.ProtectRequest{
			StateId:           config.stateID[step.Actor],
			AuthenticatedData: authenticatedData,
			Plaintext:         plaintext,
		}
		resp, err := client.rpc.Protect(ctx(), req)
		if err != nil {
			return err
		}
		config.Log(step.Actor, "Protect", req, resp)

		config.StoreMessage(index, "authenticatedData", authenticatedData)
		config.StoreMessage(index, "plaintext", plaintext)
		config.StoreMessage(index, "ciphertext", resp.Ciphertext)

	case ActionUnprotect:
		client := config.ActorClients[step.Actor]
		var params UnprotectStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		ciphertext, err := config.GetMessage(params.Ciphertext, "ciphertext")
		if err != nil {
			return err
		}

		req := &pb.UnprotectRequest{
			StateId:    config.stateID[step.Actor],
			Ciphertext: ciphertext,
		}
		resp, err := client.rpc.Unprotect(ctx(), req)
		if err != nil {
			return err
		}
		config.Log(step.Actor, "Unprotect", req, resp)

		authenticatedData, err := config.GetMessage(params.Ciphertext, "authenticatedData")
		if err != nil {
			return err
		}

		plaintext, err := config.GetMessage(params.Ciphertext, "plaintext")
		if err != nil {
			return err
		}

		if !bytes.Equal(authenticatedData, resp.AuthenticatedData) {
			return fmt.Errorf("incorrect authenticated data")
		}

		if !bytes.Equal(plaintext, resp.Plaintext) {
			return fmt.Errorf("incorrect plaintext")
		}

		config.StoreMessage(index, "authenticatedData", resp.AuthenticatedData)
		config.StoreMessage(index, "plaintext", resp.Plaintext)

	case ActionHandleCommit:
		client := config.ActorClients[step.Actor]
		var params HandleCommitStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		commit, err := config.GetMessage(params.Commit, "commit")
		if err != nil {
			return err
		}

		byRef := make([][]byte, len(params.ByReference))
		for i, ix64 := range params.ByReference {
			byRef[i], err = config.GetMessage(ix64, "proposal")
			if err != nil {
				return err
			}
		}

		req := &pb.HandleCommitRequest{
			StateId:  config.stateID[step.Actor],
			Proposal: byRef,
			Commit:   commit,
		}
		resp, err := client.rpc.HandleCommit(ctx(), req)
		if err != nil {
			return err
		}
		config.Log(step.Actor, "HandleCommit", req, resp)

		config.stateID[step.Actor] = resp.StateId

	case ActionHandlePendingCommit:
		client := config.ActorClients[step.Actor]

		req := &pb.HandlePendingCommitRequest{
			StateId: config.stateID[step.Actor],
		}
		resp, err := client.rpc.HandlePendingCommit(ctx(), req)
		if err != nil {
			return err
		}
		config.Log(step.Actor, "HandlePendingCommit", req, resp)

		config.stateID[step.Actor] = resp.StateId

	// XXX(RLB): This step does not store anything in the transcript.  With the
	// KeyPackages and whatnot, it would be too complicated.  When we refactor to
	// make the transcript tracking more elegant, we can add the tracking here.
	case ActionReInit:
		var params ReInitStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		// Compute sets of members less the committer and the welcomer
		notCommitter := map[string]bool{params.Welcomer: true}
		notWelcomer := map[string]bool{params.Committer: true}
		for _, member := range params.Members {
			notCommitter[member] = true
			notWelcomer[member] = true
		}
		if params.Proposer != "" {
			notCommitter[params.Proposer] = true
			notWelcomer[params.Proposer] = true
		}

		delete(notCommitter, params.Committer)
		delete(notWelcomer, params.Welcomer)

		// Decide on the parameters to send
		newGroupID, err := config.NewGroupID(params.ChangeGroupID)
		if err != nil {
			return err
		}

		if params.ChangeCipherSuite {
			err = config.ChangeCipherSuite()
			if err != nil {
				return err
			}
		}

		// Have the proposer create the Proposal or get the external proposal created
		// earlier
		var proposal []byte
		if params.Proposer != "" {
			client := config.ActorClients[params.Proposer]
			req := &pb.ReInitProposalRequest{
				StateId:     config.stateID[params.Proposer],
				CipherSuite: config.CipherSuite,
				GroupId:     newGroupID,
				Extensions:  params.Extensions,
			}
			resp, err := client.rpc.ReInitProposal(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(params.Proposer, "ReInitProposal", req, resp)

			proposal = resp.Proposal
		} else {
			proposal, err = config.GetMessage(params.ExternalReinitProposal, "proposal")
			if err != nil {
				return err
			}
		}

		// Have the committer commit the Proposal and advance their state
		// XXX(RLB): This only supports committing ReInit by reference.  We might
		// want to refactor so that it can be done by value as well.
		var commit []byte
		var epochAuthenticator []byte
		reinitIDs := map[string]uint32{}
		keyPackages := map[string][]byte{}
		{
			client := config.ActorClients[params.Committer]
			commitReq := &pb.CommitRequest{
				StateId:     config.stateID[params.Committer],
				ByReference: [][]byte{proposal},
			}
			commitResp, err := client.rpc.ReInitCommit(ctx(), commitReq)
			if err != nil {
				return err
			}
			config.Log(params.Committer, "ReInitCommit", commitReq, commitResp)

			commit = commitResp.Commit

			req := &pb.HandlePendingCommitRequest{
				StateId: config.stateID[params.Committer],
			}
			resp, err := client.rpc.HandlePendingReInitCommit(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(params.Committer, "HandlePendingReInitCommit", req, resp)

			reinitIDs[params.Committer] = resp.ReinitId
			keyPackages[params.Committer] = resp.KeyPackage
			epochAuthenticator = resp.EpochAuthenticator
		}

		// Have everyone except the committer handle the Commit
		for member := range notCommitter {
			client := config.ActorClients[member]
			req := &pb.HandleCommitRequest{
				StateId:  config.stateID[member],
				Proposal: [][]byte{proposal},
				Commit:   commit,
			}
			resp, err := client.rpc.HandleReInitCommit(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(member, "HandleReInitCommit", req, resp)

			if !bytes.Equal(resp.EpochAuthenticator, epochAuthenticator) {
				return fmt.Errorf("member [%s] failed to agree on epoch authenticator", member)
			}

			reinitIDs[member] = resp.ReinitId
			keyPackages[member] = resp.KeyPackage
		}

		// Have the welcomer create the Welcome
		// XXX(RLB) Note that this assumes that the welcomer will advance its state
		// as a side effect of `ReInitWelcome()`
		var welcome []byte
		var ratchetTree []byte
		var reinitEpochAuthenticator []byte
		{
			var keyPackageList [][]byte
			for member := range notWelcomer {
				keyPackageList = append(keyPackageList, keyPackages[member])
			}

			client := config.ActorClients[params.Welcomer]
			req := &pb.ReInitWelcomeRequest{
				ReinitId:     reinitIDs[params.Welcomer],
				KeyPackage:   keyPackageList,
				ForcePath:    params.ForcePath,
				ExternalTree: params.ExternalTree,
			}
			resp, err := client.rpc.ReInitWelcome(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(params.Welcomer, "ReInitWelcome", req, resp)

			config.stateID[params.Welcomer] = resp.StateId
			welcome = resp.Welcome
			reinitEpochAuthenticator = resp.EpochAuthenticator
			if params.ExternalTree {
				ratchetTree = resp.RatchetTree
			}
		}

		// Have everyone except the welcomer process the Welcome
		for member := range notWelcomer {
			client := config.ActorClients[member]
			req := &pb.HandleReInitWelcomeRequest{
				ReinitId:    reinitIDs[member],
				Welcome:     welcome,
				RatchetTree: ratchetTree,
			}
			resp, err := client.rpc.HandleReInitWelcome(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(member, "HandleReInitWelcome", req, resp)

			if !bytes.Equal(resp.EpochAuthenticator, reinitEpochAuthenticator) {
				return fmt.Errorf("member [%s] failed to agree on reinit epoch authenticator", member)
			}

			config.stateID[member] = resp.StateId
		}

	case ActionBranch:
		// XXX(RLB): Note that after this step, the state IDs remembered by the test
		// runner will be for the members' states in the *new* group.  It would be
		// nice to test that both the old and new groups now work.  But it's not
		// clear how to do that in the scripting language.
		// XXX(RLB): Also, this step does not write any output to the transcript
		// right now, for similar reasons to ActionReInit and previous XXX note.
		var params BranchStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		// Get KeyPackages from the members
		transactionIDs := map[string]uint32{}
		var keyPackages [][]byte
		for _, member := range params.Members {
			client := config.ActorClients[member]
			req := &pb.CreateKeyPackageRequest{
				CipherSuite: config.CipherSuite,
				Identity:    []byte(member),
			}
			resp, err := client.rpc.CreateKeyPackage(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(member, "CreateKeyPackage", req, resp)

			transactionIDs[member] = resp.TransactionId
			keyPackages = append(keyPackages, resp.KeyPackage)
		}

		// Have the committer create a branch Welcome
		var welcome []byte
		var ratchetTree []byte
		var epochAuthenticator []byte
		{
			client := config.ActorClients[step.Actor]
			req := &pb.CreateBranchRequest{
				StateId:      config.stateID[step.Actor],
				GroupId:      []byte(uuid.New().String()),
				Extensions:   params.Extensions,
				KeyPackages:  keyPackages,
				ForcePath:    params.ForcePath,
				ExternalTree: params.ExternalTree,
			}
			resp, err := client.rpc.CreateBranch(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(step.Actor, "CreateBranch", req, resp)

			welcome = resp.Welcome
			epochAuthenticator = resp.EpochAuthenticator
			if params.ExternalTree {
				ratchetTree = resp.RatchetTree
			}

			config.stateID[step.Actor] = resp.StateId
		}

		// Apply the Welcome at each other member
		for _, member := range params.Members {
			client := config.ActorClients[member]
			req := &pb.HandleBranchRequest{
				StateId:       config.stateID[member],
				TransactionId: transactionIDs[member],
				Welcome:       welcome,
				RatchetTree:   ratchetTree,
			}
			resp, err := client.rpc.HandleBranch(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(member, "HandleBranch", req, resp)

			if !bytes.Equal(resp.EpochAuthenticator, epochAuthenticator) {
				return fmt.Errorf("member [%s] failed to agree on epoch authenticator", member)
			}

			config.stateID[member] = resp.StateId
		}

	case ActionNewMemberAddProposal:
		var params NewMemberAddProposalStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		// Get a GroupInfo from the `actor`
		var groupInfo []byte
		{
			client := config.ActorClients[step.Actor]
			req := &pb.GroupInfoRequest{
				StateId: config.stateID[step.Actor],
			}
			resp, err := client.rpc.GroupInfo(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(step.Actor, "GroupInfo", req, resp)

			groupInfo = resp.GroupInfo
		}

		// Get a self-signed Add proposal from the joiner
		{
			client := config.ActorClients[params.Joiner]
			req := &pb.NewMemberAddProposalRequest{
				GroupInfo: groupInfo,
				Identity:  []byte(params.Joiner),
			}
			resp, err := client.rpc.NewMemberAddProposal(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(params.Joiner, "NewMemberAddProposal", req, resp)

			config.transactionID[params.Joiner] = resp.TransactionId
			config.StoreMessage(index, "proposal", resp.Proposal)
			config.StoreMessage(index, "init_priv", resp.InitPriv)
			config.StoreMessage(index, "encryption_priv", resp.EncryptionPriv)
			config.StoreMessage(index, "signature_priv", resp.SignaturePriv)
		}

	case ActionAddExternalSigner:
		var params AddExternalSignerStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		// Create the external signer
		var externalSender []byte
		{
			client := config.ActorClients[params.Signer]
			req := &pb.CreateExternalSignerRequest{
				CipherSuite: config.CipherSuite,
				Identity:    []byte(params.Signer),
			}
			resp, err := client.rpc.CreateExternalSigner(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(params.Signer, "CreateExternalSigner", req, resp)

			config.signerID[params.Signer] = resp.SignerId
			externalSender = resp.ExternalSender
		}

		// Create a GroupContextExtensions proposal adding the signer
		{
			client := config.ActorClients[step.Actor]
			req := &pb.AddExternalSignerRequest{
				StateId:        config.stateID[step.Actor],
				ExternalSender: externalSender,
			}
			resp, err := client.rpc.AddExternalSigner(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(step.Actor, "AddExternalSigner", req, resp)

			config.StoreMessage(index, "proposal", resp.Proposal)
		}

	case ActionExternalSignerProposal:
		var params ExternalSignerProposalStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		// Get GroupInfo and ratchet tree from the `member`
		var groupInfo []byte
		var ratchetTree []byte
		{
			client := config.ActorClients[params.Member]
			req := &pb.GroupInfoRequest{
				StateId:      config.stateID[params.Member],
				ExternalTree: true,
			}
			resp, err := client.rpc.GroupInfo(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(params.Member, "GroupInfo", req, resp)

			groupInfo = resp.GroupInfo
			ratchetTree = resp.RatchetTree
		}

		// Get a proposal from the `actor`
		{
			client := config.ActorClients[step.Actor]
			description, err := params.Description.ProposalDescriptionToProto(config)
			if err != nil {
				return err
			}

			req := &pb.ExternalSignerProposalRequest{
				SignerId:    config.signerID[step.Actor],
				GroupInfo:   groupInfo,
				RatchetTree: ratchetTree,
				Description: description,
			}
			resp, err := client.rpc.ExternalSignerProposal(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(step.Actor, "ExternalSignerProposal", req, resp)

			config.StoreMessage(index, "proposal", resp.Proposal)
		}

	default:
		return fmt.Errorf("unknown action: %s", step.Action)
	}

	return nil
}

func (config *ScriptActorConfig) Run(script Script) ScriptResult {
	config.stateID = map[string]uint32{}
	config.transactionID = map[string]uint32{}
	config.signerID = map[string]uint32{}
	config.messageCache = make([]map[string]string, len(script))

	for i := range config.messageCache {
		config.messageCache[i] = map[string]string{}
	}

	// Prepare a partial result to return if we need to abort
	result := ScriptResult{
		CipherSuite:      config.CipherSuite,
		Actors:           map[string]string{},
		EncryptHandshake: config.EncryptHandshake,
	}

	actors := script.Actors()
	for i := range actors {
		result.Actors[actors[i]] = config.ActorClients[actors[i]].name
	}

	// Run the steps to completion or error
	for i, step := range script {
		err := config.RunStep(i, step)

		if err != nil {
			// Store the (bounded) transcript only on failure for debugging.
			result.Transcript = config.transcript
			result.Error = err.Error()
			result.FailedStep = new(int)
			*result.FailedStep = i
			result.FailedStepJSON = string(step.Raw)
			break
		}
	}

	// Release the resources on the clients that were created for this test
	for actor, stateID := range config.stateID {
		client := config.ActorClients[actor]
		req := &pb.FreeRequest{
			StateId: stateID,
		}
		_, err := client.rpc.Free(ctx(), req)
		if err != nil {
			result.Error = err.Error()
			result.FailedStep = new(int)
			*result.FailedStep = len(script)
		}
	}

	return result
}

func (p *ClientPool) ScriptMatrix(actors []string, clientMode ClientMode, suite int, hsMode HandshakeMode) []ScriptActorConfig {
	suite32 := uint32(suite)
	var suites []uint32
	if suite == 0 {
		suites = []uint32{}
		for suite, clients := range p.suiteSupport {
			// Only include suites supported by ALL clients (for meaningful cross-impl tests).
			if len(clients) == len(p.clients) {
				suites = append(suites, suite)
			}
		}
	} else if _, ok := p.suiteSupport[suite32]; ok {
		suites = []uint32{suite32}
	} else {
		panic(fmt.Sprintf("Unsupported ciphersuite: %d", suite))
	}

	encryptOptions := []bool{true, false}
	switch hsMode {
	case HandshakeModeAll:
		// Default

	case HandshakeModePrivate:
		encryptOptions = []bool{true}

	case HandshakeModePublic:
		encryptOptions = []bool{false}
	}

	var configs []ScriptActorConfig
	for _, suite := range suites {
		clients := p.suiteSupport[suite]

		for _, encrypt := range encryptOptions {
			var combos [][]int
			// Fall back to random if allCombinations would explode (vals^slots > threshold).
			effectiveMode := clientMode
			if effectiveMode == ClientModeAll && len(actors) > 10 {
				effectiveMode = ClientModeRandom
			}
			switch effectiveMode {
			case ClientModeAll:
				combos = combinations(len(clients), len(actors))

			case ClientModeRandom:
				combos = [][]int{randomCombination(len(clients), len(actors))}
			}

			for _, combo := range combos {
				config := ScriptActorConfig{
					CipherSuite:      suite,
					EncryptHandshake: encrypt,
					ActorClients:     map[string]*Client{},
				}

				for i := range actors {
					// combo[i] is an index into the clients subset; map back to p.clients.
					config.ActorClients[actors[i]] = p.clients[clients[combo[i]]]
				}

				configs = append(configs, config)
			}
		}
	}

	return configs
}

func (p *ClientPool) RunScript(_ string, clientMode ClientMode, suite int, hsMode HandshakeMode, script Script, failFast bool) ScriptResults {
	actors := script.Actors()
	configs := p.ScriptMatrix(actors, clientMode, suite, hsMode)

	results := make(ScriptResults, 0, len(configs))
	for _, config := range configs {
		result := config.Run(script)
		results = append(results, result)
		if failFast && result.FailedStep != nil {
			break
		}
	}

	return results
}

// /
// / Main logic
// /

// stringListFlag is a flag value that accumulates multiple string values.
type stringListFlag []string

func (i *stringListFlag) String() string {
	return "repeated options"
}

func (i *stringListFlag) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var (
	clientsOpt stringListFlag
	configOpt  string
	randomOpt  bool
	suiteOpt   int
	privateOpt bool
	publicOpt  bool
	failFast   bool
	quiet      bool
)

func init() {
	flag.Var(&clientsOpt, "client", "host:port for a client")
	flag.StringVar(&configOpt, "config", "config.json", "config file name")
	flag.BoolVar(&randomOpt, "random", false, "run a random assignment of clients to roles")
	flag.IntVar(&suiteOpt, "suite", 0, "only run tests for a single ciphersuite")
	flag.BoolVar(&privateOpt, "private", false, "only run tests with handshake messages as PrivateMessage")
	flag.BoolVar(&publicOpt, "public", false, "only run tests with handshake messages as PublicMessage")
	flag.BoolVar(&failFast, "fail-fast", false, "abort after the first failure")
	flag.BoolVar(&quiet, "quiet", false, "don't print the results")
	flag.Parse()
}

func main() {
	// Determine the operating modes
	clientMode := ClientModeAll
	if randomOpt {
		clientMode = ClientModeRandom
	}

	hsMode := HandshakeModeAll
	if privateOpt && !publicOpt {
		hsMode = HandshakeModePrivate
	} else if !privateOpt && publicOpt {
		hsMode = HandshakeModePublic
	}

	// Load and parse the config
	jsonData, err := os.ReadFile(configOpt)
	chk("Failure to read config file", err)

	config := new(RunConfig)
	err = json.Unmarshal(jsonData, config)
	chk("Failure to parse config file", err)

	// Connect to clients
	clientPool, err := NewClientPool(clientsOpt)
	chk("Failure to connect to clients", err)
	defer clientPool.Close()

	// Run scripts
	results := TestResults{
		Scripts: map[string]ScriptResults{},
	}
	for name, script := range config.Scripts {
		results.Scripts[name] = clientPool.RunScript(name, clientMode, suiteOpt, hsMode, script, failFast)
	}

	resultsJSON, err := json.MarshalIndent(results, "", "  ")
	chk("Error marshaling results", err)

	if !quiet {
		fmt.Println(string(resultsJSON))
	}

	for _, results := range results.Scripts {
		for _, result := range results {
			if result.FailedStep != nil {
				log.Fatal("Test failed")
			}
		}
	}
}

// chk logs a fatal error if err is not nil.
func chk(message string, err error) {
	if err != nil {
		log.Fatalf("Error: %s - %v", message, err)
	}
}
