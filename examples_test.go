package mls_test

import (
	"context"
	"fmt"

	"github.com/thomas-vilte/mls-go"
	"github.com/thomas-vilte/mls-go/ciphersuite"
)

func Example_basicFlow() {
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256

	alice, _ := mls.NewClient([]byte("alice"), cs)
	bob, _ := mls.NewClient([]byte("bob"), cs)

	bobKP, _ := bob.FreshKeyPackageBytes(ctx)
	groupID, _ := alice.CreateGroup(ctx)
	_, welcome, _ := alice.InviteMember(ctx, groupID, bobKP)
	bobGroupID, _ := bob.JoinGroup(ctx, welcome)

	msg, _ := alice.SendMessage(ctx, groupID, []byte("hello bob"))
	received, _ := bob.ReceiveMessage(ctx, bobGroupID, msg)

	fmt.Printf("%s: %s\n", received.SenderIdentity, received.Plaintext)
	// Output:
	// alice: hello bob
}

func Example_threeMembers() {
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256

	alice, _ := mls.NewClient([]byte("alice"), cs)
	bob, _ := mls.NewClient([]byte("bob"), cs)
	charlie, _ := mls.NewClient([]byte("charlie"), cs)

	bobKP, _ := bob.FreshKeyPackageBytes(ctx)
	groupID, _ := alice.CreateGroup(ctx)
	_, bobWelcome, _ := alice.InviteMember(ctx, groupID, bobKP)
	bobGroupID, _ := bob.JoinGroup(ctx, bobWelcome)

	charlieKP, _ := charlie.FreshKeyPackageBytes(ctx)
	commit, charlieWelcome, _ := alice.InviteMember(ctx, groupID, charlieKP)
	_ = bob.ProcessCommit(ctx, bobGroupID, commit)
	_, _ = charlie.JoinGroup(ctx, charlieWelcome)

	members, _ := alice.ListMembers(ctx, groupID)
	fmt.Println(len(members))
	// Output:
	// 3
}
