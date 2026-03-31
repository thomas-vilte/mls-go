package mlstest

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/thomas-vilte/mls-go"
	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
)

// NewGroup creates n high-level clients and establishes a single shared group.
//
// Client 0 creates the group and invites the remaining clients one by one.
func NewGroup(t testing.TB, n int, cs ciphersuite.CipherSuite) []*mls.Client {
	clients, _ := NewGroupWithID(t, n, cs)
	return clients
}

// NewGroupWithID creates n high-level clients, establishes a single shared group,
// and returns both the clients and the resulting group ID.
func NewGroupWithID(t testing.TB, n int, cs ciphersuite.CipherSuite) (clients []*mls.Client, groupID []byte) {
	t.Helper()
	if n < 1 {
		t.Fatalf("NewGroup requires at least one client, got %d", n)
	}
	ctx := context.Background()
	clients = make([]*mls.Client, 0, n)
	for i := 0; i < n; i++ {
		client, err := mls.NewClient([]byte(fmt.Sprintf("client-%d", i)), cs)
		if err != nil {
			t.Fatalf("NewClient(%d): %v", i, err)
		}
		clients = append(clients, client)
	}
	if n == 1 {
		groupID, err := clients[0].CreateGroup(ctx)
		if err != nil {
			t.Fatalf("CreateGroup: %v", err)
		}
		return clients, groupID
	}

	groupID, err := clients[0].CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	for i := 1; i < n; i++ {
		kp, err := clients[i].FreshKeyPackageBytes(ctx)
		if err != nil {
			t.Fatalf("FreshKeyPackageBytes(%d): %v", i, err)
		}
		commit, welcome, err := clients[0].InviteMember(ctx, groupID, kp)
		if err != nil {
			t.Fatalf("InviteMember(%d): %v", i, err)
		}
		if err := Broadcast(t, clients[:i+1], commit, welcome); err != nil {
			t.Fatalf("Broadcast(%d): %v", i, err)
		}
	}
	return clients, groupID
}

// Broadcast applies a commit and/or welcome to the provided clients.
//
// Existing members process the commit. Clients with a matching pending key package
// join from the welcome. Clients that cannot consume a given message are ignored.
func Broadcast(t testing.TB, clients []*mls.Client, commit, welcome []byte) error {
	t.Helper()
	ctx := context.Background()
	var groupID []byte
	if len(commit) > 0 {
		derivedGroupID, err := groupIDFromCommit(commit)
		if err != nil {
			return err
		}
		groupID = derivedGroupID
	}
	for i, client := range clients {
		joined := false
		if len(welcome) > 0 {
			if _, err := client.JoinGroup(ctx, welcome); err == nil {
				joined = true
			} else if !errors.Is(err, mls.ErrNoPendingKeyPackage) {
				return fmt.Errorf("JoinGroup: %w", err)
			}
		}
		if len(commit) == 0 || len(groupID) == 0 || joined || i == 0 {
			continue
		}
		if err := client.ProcessCommit(ctx, groupID, commit); err != nil {
			if errors.Is(err, mls.ErrGroupNotFound) {
				continue
			}
			return fmt.Errorf("ProcessCommit: %w", err)
		}
	}
	return nil
}

func groupIDFromCommit(commit []byte) ([]byte, error) {
	msg, err := framing.UnmarshalMLSMessage(commit)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling commit MLSMessage: %w", err)
	}
	if pub, ok := msg.AsPublic(); ok {
		return append([]byte(nil), pub.Content.GroupID...), nil
	}
	if priv, ok := msg.AsPrivate(); ok {
		return append([]byte(nil), priv.GroupID...), nil
	}
	return nil, mls.ErrUnexpectedMessageType
}
