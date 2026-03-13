package group

import (
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/keypackages"
)

type passiveClientExternalPsk struct {
	PskID string `json:"psk_id"`
	Psk   string `json:"psk"`
}

type passiveClientWelcomeVector struct {
	CipherSuite               uint16                     `json:"cipher_suite"`
	ExternalPsks              []passiveClientExternalPsk `json:"external_psks"`
	KeyPackage                string                     `json:"key_package"`
	InitPriv                  string                     `json:"init_priv"`
	Welcome                   string                     `json:"welcome"`
	InitialEpochAuthenticator string                     `json:"initial_epoch_authenticator"`
}

func TestPassiveClientWelcomeVectors(t *testing.T) {
	data, err := os.ReadFile("../testdata/mls-interop-testvectors/test-vectors/passive-client-welcome.json")
	if err != nil {
		t.Skipf("passive-client-welcome.json not found: %v", err)
	}

	var vectors []passiveClientWelcomeVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse passive-client-welcome.json: %v", err)
	}

	for i, v := range vectors {
		cs := ciphersuite.CipherSuite(v.CipherSuite)
		if !cs.IsSupported() {
			continue
		}

		t.Run(fmt.Sprintf("vector-%d", i), func(t *testing.T) {
			kpData := mustDecodeHexBytes(t, v.KeyPackage)
			if len(kpData) < 4 {
				t.Fatalf("key_package MLSMessage too short: %d", len(kpData))
			}
			kp, err := keypackages.UnmarshalKeyPackage(kpData[4:])
			if err != nil {
				t.Fatalf("UnmarshalKeyPackage: %v", err)
			}

			initPrivBytes := mustDecodeHexBytes(t, v.InitPriv)
			var initPrivKey *ecdh.PrivateKey
			if cs == ciphersuite.MLS128DHKEMX25519 || cs == ciphersuite.MLS128DHKEMX25519ChaCha20 {
				initPrivKey, err = ecdh.X25519().NewPrivateKey(initPrivBytes)
			} else {
				initPrivKey, err = ecdh.P256().NewPrivateKey(initPrivBytes)
			}
			if err != nil {
				t.Fatalf("parse init_priv: %v", err)
			}
			privKeys := &keypackages.KeyPackagePrivateKeys{InitKey: initPrivKey}

			welcomeData := mustDecodeHexBytes(t, v.Welcome)
			if len(welcomeData) < 4 {
				t.Fatalf("welcome MLSMessage too short: %d", len(welcomeData))
			}
			welcome, err := UnmarshalWelcome(welcomeData[4:])
			if err != nil {
				t.Fatalf("UnmarshalWelcome: %v", err)
			}

			externalPsks := make(map[string][]byte, len(v.ExternalPsks))
			for _, psk := range v.ExternalPsks {
				pskID := mustDecodeHexBytes(t, psk.PskID)
				pskBytes := mustDecodeHexBytes(t, psk.Psk)
				externalPsks[string(pskID)] = pskBytes
			}

			group, err := JoinFromWelcome(welcome, kp, privKeys, externalPsks)
			if err != nil {
				t.Fatalf("JoinFromWelcome: %v", err)
			}
			if group == nil {
				t.Fatal("expected non-nil group")
			}

			wantAuth := mustDecodeHexBytes(t, v.InitialEpochAuthenticator)
			gotAuth := group.EpochAuthenticator()
			if !ciphersuite.EqualCT(gotAuth, wantAuth) {
				t.Fatalf("initial_epoch_authenticator sametch\n  got  %x\n  want %x", gotAuth, wantAuth)
			}
		})
	}
}
