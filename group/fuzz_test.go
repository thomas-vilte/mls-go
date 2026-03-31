package group

import (
	"crypto/rand"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/treesync"
)

func createFuzzingGroup() (*Group, *ciphersuite.SignaturePrivateKey) {
	credWithKey, _, _ := credentials.GenerateCredentialWithKey([]byte("FuzzGroupCreator"))
	kp, kpPriv, _ := keypackages.Generate(credWithKey, keypackages.MLS128DHKEMP256)
	groupID, _ := NewGroupIDRandom()
	group, _ := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kp, kpPriv)
	return group, ciphersuite.NewSignaturePrivateKey(kpPriv.SignatureKey)
}

func FuzzProcessReceivedCommit(f *testing.F) {
	f.Add([]byte{0x01, 0x02, 0x03, 0x04})
	f.Add([]byte{})

	f.Fuzz(func(_ *testing.T, commitData []byte) {
		group, _ := createFuzzingGroup()

		ac, _ := framing.UnmarshalAuthenticatedContent(commitData)
		if ac == nil {
			return
		}

		var myPrivBytes []byte
		if group.members[0] != nil && group.members[0].KeyPackage != nil {
			myPrivBytes = make([]byte, 32)
			rand.Read(myPrivBytes)
		}

		// Must not panic regardless of input.
		_ = group.ProcessReceivedCommit(ac, treesync.LeafIndex(0), myPrivBytes)
	})
}

func FuzzJoinFromWelcome(f *testing.F) {
	f.Add([]byte{0x01, 0x02, 0x03, 0x04})
	f.Add([]byte{})

	f.Fuzz(func(_ *testing.T, welcomeData []byte) {
		welcome, err := UnmarshalWelcome(welcomeData)
		if err != nil || welcome == nil {
			return
		}

		credWithKey, _, _ := credentials.GenerateCredentialWithKey([]byte("FuzzJoiner"))
		kp, kpPriv, _ := keypackages.Generate(credWithKey, keypackages.MLS128DHKEMP256)

		// Must not panic regardless of input.
		_, _ = JoinFromWelcome(welcome, kp, kpPriv, nil)
	})
}

func FuzzUnmarshalGroupState(f *testing.F) {
	f.Add([]byte("{}"))
	f.Add([]byte{})

	f.Fuzz(func(_ *testing.T, data []byte) {
		g, err := UnmarshalGroupState(data)
		if err != nil || g == nil {
			return
		}
		roundTrip, err := g.MarshalState()
		if err != nil {
			return
		}
		_, _ = UnmarshalGroupState(roundTrip)
	})
}
