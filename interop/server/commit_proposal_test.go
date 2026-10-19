package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/interop/server/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestHandleCommitRejectsMissingProposal(t *testing.T) {
	t.Parallel()

	cs := uint32(ciphersuite.MLS128DHKEMX25519)
	ctx := t.Context()
	server := NewServer()

	// Establish a group with Alice, Bob and Charlie.
	aliceState, err := server.CreateGroup(ctx, &proto.CreateGroupRequest{
		GroupId:     []byte("missing-proposal"),
		CipherSuite: cs,
		Identity:    []byte("alice"),
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if aliceState == nil {
		t.Fatal("CreateGroup returned nil")
	}

	bobKP, err := server.CreateKeyPackage(ctx, &proto.CreateKeyPackageRequest{CipherSuite: cs, Identity: []byte("bob")})
	if err != nil {
		t.Fatalf("CreateKeyPackage(bob): %v", err)
	}
	if bobKP == nil {
		t.Fatal("CreateKeyPackage(bob) returned nil")
	}
	charlieKP, err := server.CreateKeyPackage(ctx, &proto.CreateKeyPackageRequest{CipherSuite: cs, Identity: []byte("charlie")})
	if err != nil {
		t.Fatalf("CreateKeyPackage(charlie): %v", err)
	}
	if charlieKP == nil {
		t.Fatal("CreateKeyPackage(charlie) returned nil")
	}

	if _, err := server.AddProposal(ctx, &proto.AddProposalRequest{StateId: aliceState.StateId, KeyPackage: bobKP.KeyPackage}); err != nil {
		t.Fatalf("AddProposal(alice): %v", err)
	}

	if _, err := server.AddProposal(ctx, &proto.AddProposalRequest{StateId: aliceState.StateId, KeyPackage: charlieKP.KeyPackage}); err != nil {
		t.Fatalf("AddProposal(charlie): %v", err)
	}

	commit1, err := server.Commit(ctx, &proto.CommitRequest{StateId: aliceState.StateId})
	if err != nil {
		t.Fatalf("Commit1: %v", err)
	}
	if commit1 == nil {
		t.Fatal("Commit1 returned nil")
	}

	bobJoin, err := server.JoinGroup(ctx, &proto.JoinGroupRequest{TransactionId: bobKP.TransactionId, Welcome: commit1.Welcome})
	if err != nil {
		t.Fatalf("JoinGroup(bob): %v", err)
	}
	if bobJoin == nil {
		t.Fatal("JoinGroup(bob) returned nil")
	}
	charlieJoin, err := server.JoinGroup(ctx, &proto.JoinGroupRequest{TransactionId: charlieKP.TransactionId, Welcome: commit1.Welcome})
	if err != nil {
		t.Fatalf("JoinGroup(charlie): %v", err)
	}
	if charlieJoin == nil {
		t.Fatal("JoinGroup(charlie) returned nil")
	}

	// All three members must agree before testing a missing proposal.
	aliceAuth1, err := server.StateAuth(ctx, &proto.StateAuthRequest{StateId: aliceState.StateId})
	if err != nil {
		t.Fatalf("StateAuth(alice): %v", err)
	}
	if aliceAuth1 == nil {
		t.Fatal("StateAuth(alice) returned nil")
	}
	if !bytes.Equal(aliceAuth1.StateAuthSecret, bobJoin.EpochAuthenticator) {
		t.Fatal("epoch auth mismatch alice/bob after commit1")
	}
	if !bytes.Equal(aliceAuth1.StateAuthSecret, charlieJoin.EpochAuthenticator) {
		t.Fatal("epoch auth mismatch alice/charlie after commit1")
	}

	// Build a commit referencing Dave's Add without delivering that proposal.
	daveKP, err := server.CreateKeyPackage(ctx, &proto.CreateKeyPackageRequest{CipherSuite: cs, Identity: []byte("dave")})
	if err != nil {
		t.Fatalf("CreateKeyPackage(dave): %v", err)
	}
	if daveKP == nil {
		t.Fatal("CreateKeyPackage(dave) returned nil")
	}
	if _, err := server.AddProposal(ctx, &proto.AddProposalRequest{StateId: aliceState.StateId, KeyPackage: daveKP.KeyPackage}); err != nil {
		t.Fatalf("AddProposal(alice): %v", err)
	}
	commit2, err := server.Commit(ctx, &proto.CommitRequest{StateId: aliceState.StateId})
	if err != nil {
		t.Fatalf("Commit2: %v", err)
	}
	if commit2 == nil {
		t.Fatal("Commit2 returned nil")
	}

	receivers := []struct {
		name    string
		stateID uint32
	}{
		{name: "bob", stateID: bobJoin.StateId},
		{name: "charlie", stateID: charlieJoin.StateId},
	}
	for _, receiver := range receivers {
		t.Run(receiver.name, func(t *testing.T) {
			response, err := server.HandleCommit(t.Context(), &proto.HandleCommitRequest{
				StateId: receiver.stateID,
				Commit:  commit2.Commit,
			})
			if err == nil {
				t.Fatal("HandleCommit accepted a commit with a missing proposal")
			}
			if got := status.Code(err); got != codes.Internal {
				t.Fatalf("HandleCommit status = %v, want %v: %v", got, codes.Internal, err)
			}
			if !strings.Contains(status.Convert(err).Message(), group.ErrUnknownProposalRef.Error()) {
				t.Fatalf("HandleCommit error = %v, want unknown proposal reference", err)
			}
			if response != nil {
				t.Fatal("HandleCommit returned a response for a rejected commit")
			}
		})
	}
}
