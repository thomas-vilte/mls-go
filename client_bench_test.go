package mls

import (
	"context"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

func BenchmarkClientSendMessage(b *testing.B) {
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256
	alice, err := NewClient([]byte("alice-bench"), cs)
	if err != nil {
		b.Fatalf("NewClient(alice): %v", err)
	}
	bob, err := NewClient([]byte("bob-bench"), cs)
	if err != nil {
		b.Fatalf("NewClient(bob): %v", err)
	}
	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		b.Fatalf("FreshKeyPackageBytes: %v", err)
	}
	groupID, err := alice.CreateGroup(ctx)
	if err != nil {
		b.Fatalf("CreateGroup: %v", err)
	}
	_, welcome, err := alice.InviteMember(ctx, groupID, bobKP)
	if err != nil {
		b.Fatalf("InviteMember: %v", err)
	}
	bobGroupID, err := bob.JoinGroup(ctx, welcome)
	if err != nil {
		b.Fatalf("JoinGroup: %v", err)
	}
	data := []byte("benchmark-message-payload")

	b.ResetTimer()
	for b.Loop() {
		msg, err := alice.SendMessage(ctx, groupID, data)
		if err != nil {
			b.Fatalf("SendMessage: %v", err)
		}
		if _, err := bob.ReceiveMessage(ctx, bobGroupID, msg); err != nil {
			b.Fatalf("ReceiveMessage: %v", err)
		}
	}
}
