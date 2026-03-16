package main

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/interop/server/proto"
)

func TestServerSmoke(t *testing.T) {
	server := NewServer()

	resp, err := server.Name(context.Background(), &proto.NameRequest{})
	if err != nil {
		t.Fatalf("Name() failed: %v", err)
	}
	if resp.Name != "mls-go" {
		t.Errorf("Name() = %q, want %q", resp.Name, "mls-go")
	}

	csResp, err := server.SupportedCiphersuites(context.Background(), &proto.SupportedCiphersuitesRequest{})
	if err != nil {
		t.Fatalf("SupportedCiphersuites() failed: %v", err)
	}
	if len(csResp.Ciphersuites) != 3 {
		t.Errorf("SupportedCiphersuites() returned %d suites, want 3", len(csResp.Ciphersuites))
	}
}

func TestServerIntegration(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer lis.Close()

	s := grpc.NewServer()
	server := NewServer()
	proto.RegisterMLSClientServer(s, server)

	go func() {
		if err := s.Serve(lis); err != nil {
			t.Errorf("Serve() failed: %v", err)
		}
	}()
	defer s.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	client := proto.NewMLSClientClient(conn)

	resp, err := client.Name(ctx, &proto.NameRequest{})
	if err != nil {
		t.Fatalf("Name() via gRPC failed: %v", err)
	}
	if resp.Name != "mls-go" {
		t.Errorf("Name() = %q, want %q", resp.Name, "mls-go")
	}

	createResp, err := client.CreateGroup(ctx, &proto.CreateGroupRequest{
		GroupId:          []byte("test-group"),
		CipherSuite:      uint32(ciphersuite.MLS128DHKEMP256),
		EncryptHandshake: true,
		Identity:         []byte("alice"),
	})
	if err != nil {
		t.Fatalf("CreateGroup() failed: %v", err)
	}
	if createResp.StateId == 0 {
		t.Error("CreateGroup() returned state_id = 0")
	}

	t.Logf("Successfully created group with state_id: %d", createResp.StateId)

	kpResp, err := client.CreateKeyPackage(ctx, &proto.CreateKeyPackageRequest{
		CipherSuite: uint32(ciphersuite.MLS128DHKEMP256),
		Identity:    []byte("bob"),
	})
	if err != nil {
		t.Fatalf("CreateKeyPackage() failed: %v", err)
	}
	if kpResp.TransactionId == 0 {
		t.Error("CreateKeyPackage() returned transaction_id = 0")
	}
	if len(kpResp.KeyPackage) == 0 {
		t.Error("CreateKeyPackage() returned empty key package")
	}

	t.Logf("Successfully created key package with transaction_id: %d", kpResp.TransactionId)

	_, err = client.Free(ctx, &proto.FreeRequest{
		StateId: createResp.StateId,
	})
	if err != nil {
		t.Fatalf("Free() failed: %v", err)
	}

	t.Log("Smoke test passed!")
}

// TestEpochAuthenticatorAgreement verifies that Alice and Bob agree on the
// epoch authenticator after Bob joins via Welcome (the bug was that the
// joiner_secret stored in GroupSecrets was the intermediate value, not the
// real joiner_secret = ExpandWithLabel(intermediate, "joiner", GC, Nh)).
func TestEpochAuthenticatorAgreement(t *testing.T) {
	ctx := context.Background()
	server := NewServer()
	cs := uint32(ciphersuite.MLS128DHKEMP256)

	aliceGroup, err := server.CreateGroup(ctx, &proto.CreateGroupRequest{
		GroupId:     []byte("agree-test"),
		CipherSuite: cs,
		Identity:    []byte("alice"),
	})
	if err != nil {
		t.Fatalf("CreateGroup(alice): %v", err)
	}

	bobKP, err := server.CreateKeyPackage(ctx, &proto.CreateKeyPackageRequest{
		CipherSuite: cs,
		Identity:    []byte("bob"),
	})
	if err != nil {
		t.Fatalf("CreateKeyPackage(bob): %v", err)
	}

	_, err = server.AddProposal(ctx, &proto.AddProposalRequest{
		StateId:    aliceGroup.StateId,
		KeyPackage: bobKP.KeyPackage,
	})
	if err != nil {
		t.Fatalf("AddProposal: %v", err)
	}

	commitResp, err := server.Commit(ctx, &proto.CommitRequest{
		StateId: aliceGroup.StateId,
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if len(commitResp.Welcome) == 0 {
		t.Fatal("Commit returned empty Welcome")
	}

	bobJoin, err := server.JoinGroup(ctx, &proto.JoinGroupRequest{
		TransactionId: bobKP.TransactionId,
		Welcome:       commitResp.Welcome,
	})
	if err != nil {
		t.Fatalf("JoinGroup(bob): %v", err)
	}

	aliceAuth, err := server.StateAuth(ctx, &proto.StateAuthRequest{StateId: aliceGroup.StateId})
	if err != nil {
		t.Fatalf("StateAuth(alice): %v", err)
	}

	if !bytes.Equal(aliceAuth.StateAuthSecret, bobJoin.EpochAuthenticator) {
		t.Errorf("epoch authenticator mismatch:\n  alice: %x\n  bob:   %x",
			aliceAuth.StateAuthSecret, bobJoin.EpochAuthenticator)
	} else {
		t.Logf("epoch authenticator agrees: %x", aliceAuth.StateAuthSecret)
	}
}
