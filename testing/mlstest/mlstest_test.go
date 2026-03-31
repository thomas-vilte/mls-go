package mlstest

import (
	"context"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go"
	"github.com/thomas-vilte/mls-go/ciphersuite"
)

func TestNewGroup(t *testing.T) {
	t.Parallel()
	clients, groupID := NewGroupWithID(t, 3, ciphersuite.MLS128DHKEMP256)
	if len(clients) != 3 {
		t.Fatalf("client count = %d, want 3", len(clients))
	}
	ctx := context.Background()
	members, err := clients[0].ListMembers(ctx, groupID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 3 {
		t.Fatalf("member count = %d, want 3", len(members))
	}
}

func TestFakeStoreFailureInjection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fake := NewFakeStore()
	client, err := mls.NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256, mls.WithStorage(fake, fake))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	fake.FailSave = true
	if _, err := client.CreateGroup(ctx); err == nil {
		t.Fatal("expected CreateGroup to fail when SaveGroupState fails")
	}

	fake.FailSave = false
	groupID, err := client.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	fake.LoadErr = errors.New("boom")
	fake.FailLoad = true
	_, err = client.ListMembers(ctx, groupID)
	if err == nil {
		t.Fatal("expected ListMembers to fail when LoadGroupState fails")
	}
	if !errors.Is(err, fake.LoadErr) {
		t.Fatalf("expected load error %v, got %v", fake.LoadErr, err)
	}
}
