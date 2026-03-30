package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/thomas-vilte/mls-go"
	"github.com/thomas-vilte/mls-go/ciphersuite"
)

func main() {
	cs := ciphersuite.MLS128DHKEMP256
	// Each client owns its identity, signing key, and local group state.
	alice, err := mls.NewClient([]byte("alice"), cs)
	if err != nil {
		log.Fatal(err)
	}
	bob, err := mls.NewClient([]byte("bob"), cs)
	if err != nil {
		log.Fatal(err)
	}
	// Bob generates a fresh single-use KeyPackage and shares it with Alice.
	bobKeyPackage, err := bob.FreshKeyPackageBytes()
	if err != nil {
		log.Fatal(err)
	}
	// Alice creates a new group.
	groupID, err := alice.CreateGroup()
	if err != nil {
		log.Fatal(err)
	}
	// Alice invites Bob.
	commitBytes, welcomeBytes, err := alice.InviteMember(groupID, bobKeyPackage)
	if err != nil {
		log.Fatal(err)
	}
	// Existing members process the commit.
	// In this two-member example, Alice is the committer and already merged it.
	_ = commitBytes
	// Bob joins from the Welcome bytes.
	bobGroupID, err := bob.JoinGroup(welcomeBytes)
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(groupID, bobGroupID) {
		log.Fatal("group IDs do not match")
	}
	// Alice sends an encrypted application message to Bob.
	aliceToBob, err := alice.SendMessage(groupID, []byte("hello bob"))
	if err != nil {
		log.Fatal(err)
	}
	receivedByBob, err := bob.ReceiveMessage(bobGroupID, aliceToBob)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Bob received: %s\n", string(receivedByBob))
	// Bob replies.
	bobToAlice, err := bob.SendMessage(bobGroupID, []byte("hello alice"))
	if err != nil {
		log.Fatal(err)
	}
	receivedByAlice, err := alice.ReceiveMessage(groupID, bobToAlice)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Alice received: %s\n", string(receivedByAlice))
	fmt.Printf("Group established with mls.Client: %x\n", groupID)
}
