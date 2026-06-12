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
	if resp == nil {
		t.Fatal("Name() returned nil")
	}
	if resp.Name != "mls-go" {
		t.Errorf("Name() = %q, want %q", resp.Name, "mls-go")
	}

	csResp, err := server.SupportedCiphersuites(context.Background(), &proto.SupportedCiphersuitesRequest{})
	if err != nil {
		t.Fatalf("SupportedCiphersuites() failed: %v", err)
	}
	if csResp == nil {
		t.Fatal("SupportedCiphersuites() returned nil")
	}
	if len(csResp.Ciphersuites) != 4 {
		t.Errorf("SupportedCiphersuites() returned %d suites, want 4", len(csResp.Ciphersuites))
	}
}

func TestServerIntegration(t *testing.T) {
	lc := net.ListenConfig{}
	lis, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
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

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Fatalf("failed to close connection: %v", err)
		}
	}()

	client := proto.NewMLSClientClient(conn)

	resp, err := client.Name(ctx, &proto.NameRequest{})
	if err != nil {
		t.Fatalf("Name() via gRPC failed: %v", err)
	}
	if resp == nil {
		t.Fatal("Name() returned nil")
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
	if createResp == nil {
		t.Fatal("CreateGroup() returned nil")
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
	if kpResp == nil {
		t.Fatal("CreateKeyPackage() returned nil")
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

// TestThreePersonCommitAfterWelcome exercises the path_secret plumbing:
// Alice creates group, adds Bob+Charlie, they join via Welcome,
// then Bob commits and Alice+Charlie handle it.
// Charlie needs PathNodePrivKeys (derived from path_secret in Welcome) to decrypt.
func TestThreePersonCommitAfterWelcome(t *testing.T) {
	for _, csID := range []uint32{
		uint32(ciphersuite.MLS128DHKEMX25519),
		uint32(ciphersuite.MLS128DHKEMP256),
		uint32(ciphersuite.MLS128DHKEMX25519ChaCha20),
		uint32(ciphersuite.MLS256DHKEMP521AES256GCM),
	} {
		cs := ciphersuite.CipherSuite(csID)
		t.Run(cs.String(), func(t *testing.T) {
			testThreePersonCommitAfterWelcome(t, csID)
		})
	}
}

func testThreePersonCommitAfterWelcome(t *testing.T, cs uint32) {
	ctx := context.Background()
	server := NewServer()

	// 1. Alice creates group
	aliceGroup, err := server.CreateGroup(ctx, &proto.CreateGroupRequest{
		GroupId:     []byte("3p-test"),
		CipherSuite: cs,
		Identity:    []byte("alice"),
	})
	if err != nil {
		t.Fatalf("CreateGroup(alice): %v", err)
	}
	if aliceGroup == nil {
		t.Fatal("CreateGroup(alice) returned nil")
	}

	// 2. Create key packages for Bob and Charlie
	bobKP, err := server.CreateKeyPackage(ctx, &proto.CreateKeyPackageRequest{
		CipherSuite: cs, Identity: []byte("bob"),
	})
	if err != nil {
		t.Fatalf("CreateKeyPackage(bob): %v", err)
	}
	if bobKP == nil {
		t.Fatal("CreateKeyPackage(bob) returned nil")
	}
	charlieKP, err := server.CreateKeyPackage(ctx, &proto.CreateKeyPackageRequest{
		CipherSuite: cs, Identity: []byte("charlie"),
	})
	if err != nil {
		t.Fatalf("CreateKeyPackage(charlie): %v", err)
	}
	if charlieKP == nil {
		t.Fatal("CreateKeyPackage(charlie) returned nil")
	}

	// 3. Alice adds Bob and Charlie
	_, err = server.AddProposal(ctx, &proto.AddProposalRequest{
		StateId: aliceGroup.StateId, KeyPackage: bobKP.KeyPackage,
	})
	if err != nil {
		t.Fatalf("AddProposal(bob): %v", err)
	}
	_, err = server.AddProposal(ctx, &proto.AddProposalRequest{
		StateId: aliceGroup.StateId, KeyPackage: charlieKP.KeyPackage,
	})
	if err != nil {
		t.Fatalf("AddProposal(charlie): %v", err)
	}

	// 4. Alice commits
	commitResp, err := server.Commit(ctx, &proto.CommitRequest{
		StateId: aliceGroup.StateId,
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if commitResp == nil {
		t.Fatal("Commit returned nil")
	}
	if len(commitResp.Welcome) == 0 {
		t.Fatal("Commit returned empty Welcome")
	}

	// 5. Bob and Charlie join via Welcome
	bobJoin, err := server.JoinGroup(ctx, &proto.JoinGroupRequest{
		TransactionId: bobKP.TransactionId,
		Welcome:       commitResp.Welcome,
	})
	if err != nil {
		t.Fatalf("JoinGroup(bob): %v", err)
	}
	if bobJoin == nil {
		t.Fatal("JoinGroup(bob) returned nil")
	}
	charlieJoin, err := server.JoinGroup(ctx, &proto.JoinGroupRequest{
		TransactionId: charlieKP.TransactionId,
		Welcome:       commitResp.Welcome,
	})
	if err != nil {
		t.Fatalf("JoinGroup(charlie): %v", err)
	}
	if charlieJoin == nil {
		t.Fatal("JoinGroup(charlie) returned nil")
	}

	// Verify epoch authenticators match after Welcome
	aliceAuth, err := server.StateAuth(ctx, &proto.StateAuthRequest{StateId: aliceGroup.StateId})
	if err != nil {
		t.Fatalf("StateAuth(alice): %v", err)
	}
	if aliceAuth == nil {
		t.Fatal("StateAuth(alice) returned nil")
	}
	if !bytes.Equal(aliceAuth.StateAuthSecret, bobJoin.EpochAuthenticator) {
		t.Fatalf("epoch auth mismatch alice/bob after Welcome")
	}
	if !bytes.Equal(aliceAuth.StateAuthSecret, charlieJoin.EpochAuthenticator) {
		t.Fatalf("epoch auth mismatch alice/charlie after Welcome")
	}
	t.Logf("All 3 agree on epoch auth after Welcome: %x", aliceAuth.StateAuthSecret[:8])

	// 6. Bob commits (empty commit / self-update)
	bobCommitResp, err := server.Commit(ctx, &proto.CommitRequest{
		StateId: bobJoin.StateId,
	})
	if err != nil {
		t.Fatalf("Commit(bob): %v", err)
	}
	if bobCommitResp == nil {
		t.Fatal("Commit(bob) returned nil")
	}

	// 7. Alice and Charlie handle Bob's commit
	aliceHandle, err := server.HandleCommit(ctx, &proto.HandleCommitRequest{
		StateId: aliceGroup.StateId,
		Commit:  bobCommitResp.Commit,
	})
	if err != nil {
		t.Fatalf("HandleCommit(alice): %v", err)
	}
	if aliceHandle == nil {
		t.Fatal("HandleCommit(alice) returned nil")
	}
	charlieHandle, err := server.HandleCommit(ctx, &proto.HandleCommitRequest{
		StateId: charlieJoin.StateId,
		Commit:  bobCommitResp.Commit,
	})
	if err != nil {
		t.Fatalf("HandleCommit(charlie): %v", err)
	}
	if charlieHandle == nil {
		t.Fatal("HandleCommit(charlie) returned nil")
	}

	// 8. Verify all epoch authenticators match after Bob's commit
	bobAuth, err := server.StateAuth(ctx, &proto.StateAuthRequest{StateId: bobJoin.StateId})
	if err != nil {
		t.Fatalf("StateAuth(bob): %v", err)
	}
	if bobAuth == nil {
		t.Fatal("StateAuth(bob) returned nil")
	}
	if !bytes.Equal(bobAuth.StateAuthSecret, aliceHandle.EpochAuthenticator) {
		t.Errorf("epoch auth mismatch bob/alice after commit:\n  bob:   %x\n  alice: %x",
			bobAuth.StateAuthSecret, aliceHandle.EpochAuthenticator)
	}
	if !bytes.Equal(bobAuth.StateAuthSecret, charlieHandle.EpochAuthenticator) {
		t.Errorf("epoch auth mismatch bob/charlie after commit:\n  bob:     %x\n  charlie: %x",
			bobAuth.StateAuthSecret, charlieHandle.EpochAuthenticator)
	}
	t.Logf("All 3 agree on epoch auth after Bob's commit: %x", bobAuth.StateAuthSecret[:8])
}

// TestPathSecretInWelcome exercises the path_secret plumbing in Welcome:
// Alice(0), Bob(1), Charlie(2) exist. Alice adds Dave(3). Dave joins via
// Welcome with a path_secret (LCA of Alice and Dave is root, which is in
// the filtered direct path). Then Charlie commits and Dave handles it,
// requiring PathNodePrivKeys derived from the Welcome path_secret.
func TestPathSecretInWelcome(t *testing.T) {
	for _, csID := range []uint32{
		uint32(ciphersuite.MLS128DHKEMX25519),
		uint32(ciphersuite.MLS128DHKEMP256),
		uint32(ciphersuite.MLS128DHKEMX25519ChaCha20),
		uint32(ciphersuite.MLS256DHKEMP521AES256GCM),
	} {
		cs := ciphersuite.CipherSuite(csID)
		t.Run(cs.String(), func(t *testing.T) {
			testPathSecretInWelcome(t, csID)
		})
	}
}

func testPathSecretInWelcome(t *testing.T, cs uint32) {
	ctx := context.Background()
	server := NewServer()

	// 1. Alice creates group, adds Bob and Charlie in the first commit
	aliceState, err := server.CreateGroup(ctx, &proto.CreateGroupRequest{
		GroupId: []byte("ps-test"), CipherSuite: cs, Identity: []byte("alice"),
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

	// Bob and Charlie handle Alice's commit (they need to stay in sync)
	// Actually they joined via Welcome, so they're already at the new epoch.
	// But they need to process future commits. Let's verify epoch auth first.
	aliceAuth1, err := server.StateAuth(ctx, &proto.StateAuthRequest{StateId: aliceState.StateId})
	if err != nil {
		t.Fatalf("StateAuth(alice): %v", err)
	}
	if aliceAuth1 == nil {
		t.Fatal("StateAuth(alice) returned nil")
	}
	if !bytes.Equal(aliceAuth1.StateAuthSecret, bobJoin.EpochAuthenticator) {
		t.Fatalf("epoch auth mismatch alice/bob after commit1")
	}
	if !bytes.Equal(aliceAuth1.StateAuthSecret, charlieJoin.EpochAuthenticator) {
		t.Fatalf("epoch auth mismatch alice/charlie after commit1")
	}
	t.Logf("3 members agree after commit1")

	// 2. Now Alice adds Dave — this should produce a Welcome WITH path_secret
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

	// Bob and Charlie handle commit2
	bobHandle2, err := server.HandleCommit(ctx, &proto.HandleCommitRequest{StateId: bobJoin.StateId, Commit: commit2.Commit})
	if err != nil {
		t.Fatalf("HandleCommit(bob, commit2): %v", err)
	}
	if bobHandle2 == nil {
		t.Fatal("HandleCommit(bob, commit2) returned nil")
	}
	charlieHandle2, err := server.HandleCommit(ctx, &proto.HandleCommitRequest{StateId: charlieJoin.StateId, Commit: commit2.Commit})
	if err != nil {
		t.Fatalf("HandleCommit(charlie, commit2): %v", err)
	}
	if charlieHandle2 == nil {
		t.Fatal("HandleCommit(charlie, commit2) returned nil")
	}

	// Dave joins via Welcome (should receive path_secret)
	daveJoin, err := server.JoinGroup(ctx, &proto.JoinGroupRequest{TransactionId: daveKP.TransactionId, Welcome: commit2.Welcome})
	if err != nil {
		t.Fatalf("JoinGroup(dave): %v", err)
	}
	if daveJoin == nil {
		t.Fatal("JoinGroup(dave) returned nil")
	}

	// Verify all 4 agree
	aliceAuth2, err := server.StateAuth(ctx, &proto.StateAuthRequest{StateId: aliceState.StateId})
	if err != nil {
		t.Fatalf("StateAuth(alice): %v", err)
	}
	if aliceAuth2 == nil {
		t.Fatal("StateAuth(alice) returned nil")
	}
	if !bytes.Equal(aliceAuth2.StateAuthSecret, bobHandle2.EpochAuthenticator) {
		t.Fatalf("epoch auth mismatch alice/bob after commit2")
	}
	if !bytes.Equal(aliceAuth2.StateAuthSecret, charlieHandle2.EpochAuthenticator) {
		t.Fatalf("epoch auth mismatch alice/charlie after commit2")
	}
	if !bytes.Equal(aliceAuth2.StateAuthSecret, daveJoin.EpochAuthenticator) {
		t.Fatalf("epoch auth mismatch alice/dave after commit2")
	}
	t.Logf("4 members agree after commit2 (Dave joined with path_secret)")

	// 3. Charlie commits — Dave needs PathNodePrivKeys from Welcome to decrypt
	charlieCommit, err := server.Commit(ctx, &proto.CommitRequest{StateId: charlieHandle2.StateId})
	if err != nil {
		t.Fatalf("Commit(charlie): %v", err)
	}
	if charlieCommit == nil {
		t.Fatal("Commit(charlie) returned nil")
	}

	aliceHandle3, err := server.HandleCommit(ctx, &proto.HandleCommitRequest{StateId: aliceState.StateId, Commit: charlieCommit.Commit})
	if err != nil {
		t.Fatalf("HandleCommit(alice, commit3): %v", err)
	}
	if aliceHandle3 == nil {
		t.Fatal("HandleCommit(alice, commit3) returned nil")
	}
	bobHandle3, err := server.HandleCommit(ctx, &proto.HandleCommitRequest{StateId: bobHandle2.StateId, Commit: charlieCommit.Commit})
	if err != nil {
		t.Fatalf("HandleCommit(bob, commit3): %v", err)
	}
	if bobHandle3 == nil {
		t.Fatal("HandleCommit(bob, commit3) returned nil")
	}
	daveHandle3, err := server.HandleCommit(ctx, &proto.HandleCommitRequest{StateId: daveJoin.StateId, Commit: charlieCommit.Commit})
	if err != nil {
		t.Fatalf("HandleCommit(dave, commit3): %v", err)
	}
	if daveHandle3 == nil {
		t.Fatal("HandleCommit(dave, commit3) returned nil")
	}

	charlieAuth3, err := server.StateAuth(ctx, &proto.StateAuthRequest{StateId: charlieHandle2.StateId})
	if err != nil {
		t.Fatalf("StateAuth(charlie): %v", err)
	}
	if charlieAuth3 == nil {
		t.Fatal("StateAuth(charlie) returned nil")
	}
	if !bytes.Equal(charlieAuth3.StateAuthSecret, aliceHandle3.EpochAuthenticator) {
		t.Errorf("epoch auth mismatch charlie/alice after commit3")
	}
	if !bytes.Equal(charlieAuth3.StateAuthSecret, bobHandle3.EpochAuthenticator) {
		t.Errorf("epoch auth mismatch charlie/bob after commit3")
	}
	if !bytes.Equal(charlieAuth3.StateAuthSecret, daveHandle3.EpochAuthenticator) {
		t.Errorf("epoch auth mismatch charlie/dave after commit3")
	}
	t.Logf("All 4 agree after Charlie's commit (Dave used PathNodePrivKeys)")
}

// TestExternalJoinHandleCommit verifies that an existing member can process an
// ExternalJoin commit — specifically that the excluded set for the external joiner
// is computed correctly so decryptPathSecret succeeds.
func TestExternalJoinHandleCommit(t *testing.T) {
	for _, csID := range []uint32{
		uint32(ciphersuite.MLS128DHKEMX25519),
		uint32(ciphersuite.MLS128DHKEMP256),
		uint32(ciphersuite.MLS128DHKEMX25519ChaCha20),
		uint32(ciphersuite.MLS256DHKEMP521AES256GCM),
	} {
		cs := ciphersuite.CipherSuite(csID)
		t.Run(cs.String(), func(t *testing.T) {
			testExternalJoinHandleCommit(t, csID)
		})
	}
}

func testExternalJoinHandleCommit(t *testing.T, cs uint32) {
	ctx := context.Background()
	server := NewServer()

	// 1. Alice creates a group
	aliceState, err := server.CreateGroup(ctx, &proto.CreateGroupRequest{
		GroupId:     []byte("ext-join-test"),
		CipherSuite: cs,
		Identity:    []byte("alice"),
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if aliceState == nil {
		t.Fatal("CreateGroup returned nil")
	}

	// 2. Bob creates a key package and Alice adds him
	bobKP, err := server.CreateKeyPackage(ctx, &proto.CreateKeyPackageRequest{
		CipherSuite: cs, Identity: []byte("bob"),
	})
	if err != nil {
		t.Fatalf("CreateKeyPackage(bob): %v", err)
	}
	if bobKP == nil {
		t.Fatal("CreateKeyPackage(bob) returned nil")
	}
	_, err = server.AddProposal(ctx, &proto.AddProposalRequest{
		StateId: aliceState.StateId, KeyPackage: bobKP.KeyPackage,
	})
	if err != nil {
		t.Fatalf("AddProposal(bob): %v", err)
	}

	commitResp, err := server.Commit(ctx, &proto.CommitRequest{StateId: aliceState.StateId})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if commitResp == nil {
		t.Fatal("Commit returned nil")
	}

	// Alice handles her own commit
	alicePendingResp, err := server.HandlePendingCommit(ctx, &proto.HandlePendingCommitRequest{
		StateId: aliceState.StateId,
	})
	if err != nil {
		t.Fatalf("HandlePendingCommit(alice): %v", err)
	}
	if alicePendingResp == nil {
		t.Fatal("HandlePendingCommit(alice) returned nil")
	}
	aliceStateID := alicePendingResp.StateId

	// Bob joins via Welcome
	bobJoin, err := server.JoinGroup(ctx, &proto.JoinGroupRequest{
		TransactionId: bobKP.TransactionId,
		Welcome:       commitResp.Welcome,
	})
	if err != nil {
		t.Fatalf("JoinGroup(bob): %v", err)
	}
	if bobJoin == nil {
		t.Fatal("JoinGroup(bob) returned nil")
	}
	bobStateID := bobJoin.StateId

	if !bytes.Equal(alicePendingResp.EpochAuthenticator, bobJoin.EpochAuthenticator) {
		t.Fatalf("epoch auth mismatch after Alice commits + Bob joins")
	}

	// 3. Get GroupInfo from Alice for Charlie's external join
	giResp, err := server.GroupInfo(ctx, &proto.GroupInfoRequest{
		StateId: aliceStateID, ExternalTree: true,
	})
	if err != nil {
		t.Fatalf("GroupInfo: %v", err)
	}
	if giResp == nil {
		t.Fatal("GroupInfo returned nil")
	}

	// 4. Charlie does ExternalJoin
	charlieExtJoin, err := server.ExternalJoin(ctx, &proto.ExternalJoinRequest{
		GroupInfo:   giResp.GroupInfo,
		RatchetTree: giResp.RatchetTree,
		Identity:    []byte("charlie"),
	})
	if err != nil {
		t.Fatalf("ExternalJoin(charlie): %v", err)
	}
	if charlieExtJoin == nil {
		t.Fatal("ExternalJoin(charlie) returned nil")
	}

	// 5. Alice and Bob handle Charlie's external commit — this was the failing case
	aliceHandled, err := server.HandleCommit(ctx, &proto.HandleCommitRequest{
		StateId: aliceStateID,
		Commit:  charlieExtJoin.Commit,
	})
	if err != nil {
		t.Fatalf("HandleCommit(alice, external): %v", err)
	}
	if aliceHandled == nil {
		t.Fatal("HandleCommit(alice, external) returned nil")
	}

	bobHandled, err := server.HandleCommit(ctx, &proto.HandleCommitRequest{
		StateId: bobStateID,
		Commit:  charlieExtJoin.Commit,
	})
	if err != nil {
		t.Fatalf("HandleCommit(bob, external): %v", err)
	}
	if bobHandled == nil {
		t.Fatal("HandleCommit(bob, external) returned nil")
	}

	// All three should agree on epoch authenticator
	if !bytes.Equal(charlieExtJoin.EpochAuthenticator, aliceHandled.EpochAuthenticator) {
		t.Fatalf("epoch auth: charlie != alice after external join")
	}
	if !bytes.Equal(charlieExtJoin.EpochAuthenticator, bobHandled.EpochAuthenticator) {
		t.Fatalf("epoch auth: charlie != bob after external join")
	}
	t.Logf("all 3 agree on epoch auth: %x", charlieExtJoin.EpochAuthenticator)
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
	if aliceGroup == nil {
		t.Fatal("CreateGroup(alice) returned nil")
	}

	bobKP, err := server.CreateKeyPackage(ctx, &proto.CreateKeyPackageRequest{
		CipherSuite: cs,
		Identity:    []byte("bob"),
	})
	if err != nil {
		t.Fatalf("CreateKeyPackage(bob): %v", err)
	}
	if bobKP == nil {
		t.Fatal("CreateKeyPackage(bob) returned nil")
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
	if commitResp == nil {
		t.Fatal("Commit returned nil")
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
	if bobJoin == nil {
		t.Fatal("JoinGroup(bob) returned nil")
	}

	aliceAuth, err := server.StateAuth(ctx, &proto.StateAuthRequest{StateId: aliceGroup.StateId})
	if err != nil {
		t.Fatalf("StateAuth(alice): %v", err)
	}
	if aliceAuth == nil {
		t.Fatal("StateAuth(alice) returned nil")
	}

	if !bytes.Equal(aliceAuth.StateAuthSecret, bobJoin.EpochAuthenticator) {
		t.Errorf("epoch authenticator mismatch:\n  alice: %x\n  bob:   %x",
			aliceAuth.StateAuthSecret, bobJoin.EpochAuthenticator)
	} else {
		t.Logf("epoch authenticator agrees: %x", aliceAuth.StateAuthSecret)
	}
}
