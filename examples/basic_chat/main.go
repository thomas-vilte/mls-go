package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/keypackages"
)

func main() {
	cs := ciphersuite.MLS128DHKEMP256

	// Alice creates her credential and a fresh single-use KeyPackage.
	aliceCred, aliceSigPriv, err := credentials.GenerateCredentialWithKeyForCS([]byte("alice"), cs)
	if err != nil {
		log.Fatal(err)
	}
	aliceKP, aliceKPPriv, err := keypackages.Generate(aliceCred, cs)
	if err != nil {
		log.Fatal(err)
	}

	// Bob also prepares a fresh KeyPackage to be invited.
	bobCred, bobSigPriv, err := credentials.GenerateCredentialWithKeyForCS([]byte("bob"), cs)
	if err != nil {
		log.Fatal(err)
	}
	bobKP, bobKPPriv, err := keypackages.Generate(bobCred, cs)
	if err != nil {
		log.Fatal(err)
	}

	groupID, err := group.NewGroupIDRandom()
	if err != nil {
		log.Fatal(err)
	}

	// Alice starts a new group as the only initial member.
	aliceGroup, err := group.NewGroup(groupID, cs, aliceKP, aliceKPPriv)
	if err != nil {
		log.Fatal(err)
	}

	// Alice proposes to add Bob.
	if _, err := aliceGroup.AddMember(bobKP); err != nil {
		log.Fatal(err)
	}

	// Alice commits the pending Add proposal.
	staged, err := aliceGroup.Commit(aliceSigPriv, aliceSigPriv.PublicKey(), nil)
	if err != nil {
		log.Fatal(err)
	}

	var newMembersKPs []*keypackages.KeyPackage
	for _, prop := range staged.Proposals() {
		if prop.Type == group.ProposalTypeAdd && prop.Add != nil {
			newMembersKPs = append(newMembersKPs, prop.Add.KeyPackage)
		}
	}

	joinerSecret := staged.JoinerSecret()

	// The committer must merge its own staged commit before continuing.
	if err := aliceGroup.MergeCommit(staged); err != nil {
		log.Fatal(err)
	}

	// Alice creates the Welcome that Bob will receive out of band.
	welcome, err := aliceGroup.CreateWelcomeWithOptions(newMembersKPs, group.CreateWelcomeOptions{
		JoinerSecret:  joinerSecret,
		SignerPrivKey: aliceSigPriv,
		PskIDs:        staged.PskIDs(),
		PskSecret:     staged.RawPskSecret(),
		StagedCommit:  staged,
	})
	if err != nil {
		log.Fatal(err)
	}

	// On the wire, Welcome is carried as MLSMessage bytes.
	welcomeWire := (&framing.MLSMessage{Welcome: welcome.Marshal()}).Marshal()
	welcomeMsg, err := framing.UnmarshalMLSMessage(welcomeWire)
	if err != nil {
		log.Fatal(err)
	}
	parsedWelcome, err := group.UnmarshalWelcome(welcomeMsg.Welcome)
	if err != nil {
		log.Fatal(err)
	}

	// Bob joins from the Welcome bytes. He does not need to process the commit
	// separately because he was not a group member before this Welcome.
	bobGroup, err := group.JoinFromWelcome(parsedWelcome, bobKP, bobKPPriv, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Alice sends an application message to Bob.
	aliceToBobPM, err := aliceGroup.SendMessage([]byte("hello bob"), aliceSigPriv)
	if err != nil {
		log.Fatal(err)
	}
	aliceToBobWire := framing.NewMLSMessagePrivate(aliceToBobPM).Marshal()

	receivedByBob, err := receiveApplicationMessage(bobGroup, aliceToBobWire)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Bob received: %s\n", string(receivedByBob))

	// Bob replies on the same group epoch.
	bobToAlicePM, err := bobGroup.SendMessage([]byte("hello alice"), bobSigPriv)
	if err != nil {
		log.Fatal(err)
	}
	bobToAliceWire := framing.NewMLSMessagePrivate(bobToAlicePM).Marshal()

	receivedByAlice, err := receiveApplicationMessage(aliceGroup, bobToAliceWire)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Alice received: %s\n", string(receivedByAlice))

	if !bytes.Equal(aliceGroup.GroupID().AsSlice(), bobGroup.GroupID().AsSlice()) {
		log.Fatal("group IDs do not match")
	}

	fmt.Printf("Group established at epoch %d\n", aliceGroup.Epoch())
}

func receiveApplicationMessage(g *group.Group, wire []byte) ([]byte, error) {
	msg, err := framing.UnmarshalMLSMessage(wire)
	if err != nil {
		return nil, err
	}

	pm, ok := msg.AsPrivate()
	if !ok {
		return nil, fmt.Errorf("expected PrivateMessage")
	}

	plaintext, _, err := g.ReceiveApplicationMessage(pm)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
