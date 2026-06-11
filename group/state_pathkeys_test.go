package group

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/treesync"
)

func TestStateSerialization_PreservesPathNodePrivKeys(t *testing.T) {
	aliceGroup, bobGroup, alicePriv, bobPriv := setupTwoMemberGroup(t)

	bobGroup.myLeafEncryptionKey = bobPriv.EncryptionKey.Bytes()

	aliceSigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)
	aliceSigPub := aliceSigPriv.PublicKey()

	charlieCred, _, err := credentials.GenerateCredentialWithKey([]byte("Charlie"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(Charlie): %v", err)
	}
	charlieKP, _, err := keypackages.Generate(charlieCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage(Charlie): %v", err)
	}

	if _, err := aliceGroup.AddMember(charlieKP); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	stagedCommit, err := aliceGroup.Commit(aliceSigPriv, aliceSigPub, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	ac := stagedCommit.AuthenticatedContent()
	if err := bobGroup.ProcessReceivedCommit(ac, treesync.LeafIndex(aliceGroup.ownLeafIndex), bobGroup.myLeafEncryptionKey); err != nil {
		t.Fatalf("ProcessReceivedCommit: %v", err)
	}

	if len(bobGroup.pathNodePrivKeys) == 0 {
		t.Fatal("expected ProcessCommit to populate pathNodePrivKeys")
	}

	data, err := bobGroup.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState: %v", err)
	}

	restored, err := UnmarshalGroupState(data)
	if err != nil {
		t.Fatalf("UnmarshalGroupState: %v", err)
	}

	if len(restored.pathNodePrivKeys) != len(bobGroup.pathNodePrivKeys) {
		t.Fatalf("pathNodePrivKeys count mismatch after round trip: got %d, want %d",
			len(restored.pathNodePrivKeys), len(bobGroup.pathNodePrivKeys))
	}
	for nodeIdx, key := range bobGroup.pathNodePrivKeys {
		if !bytes.Equal(restored.pathNodePrivKeys[nodeIdx], key) {
			t.Errorf("pathNodePrivKeys[%d] not preserved across round trip", nodeIdx)
		}
	}
}

func TestStateSerialization_PreservesPendingUpdatePrivKey(t *testing.T) {
	aliceGroup, _, _, _ := setupTwoMemberGroup(t)

	want := []byte("pending-self-update-priv-key")
	aliceGroup.pendingUpdatePrivKey = append([]byte(nil), want...)

	data, err := aliceGroup.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState: %v", err)
	}

	restored, err := UnmarshalGroupState(data)
	if err != nil {
		t.Fatalf("UnmarshalGroupState: %v", err)
	}

	if !bytes.Equal(restored.pendingUpdatePrivKey, want) {
		t.Errorf("pendingUpdatePrivKey not preserved across round trip: got %x, want %x",
			restored.pendingUpdatePrivKey, want)
	}
}
