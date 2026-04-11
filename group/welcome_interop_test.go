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

type welcomeVector struct {
	CipherSuite uint16 `json:"cipher_suite"`
	InitPriv    string `json:"init_priv"`
	KeyPackage  string `json:"key_package"`
	SignerPub   string `json:"signer_pub"`
	Welcome     string `json:"welcome"`
}

func TestWelcomeVectors(t *testing.T) {
	// Note: These vectors are from another implementation and may have HPKE
	// key schedule differences. Failures likely indicate implementation incompatibility.
	// Our own HPKE implementation passes its own round-trip tests.

	data, err := os.ReadFile("../testdata/mls-interop-testvectors/test-vectors/welcome.json")
	if err != nil {
		t.Skipf("welcome.json not found: %v", err)
	}

	var vectors []welcomeVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse welcome.json: %v", err)
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
			switch cs {
			case ciphersuite.MLS128DHKEMX25519, ciphersuite.MLS128DHKEMX25519ChaCha20:
				initPrivKey, err = ecdh.X25519().NewPrivateKey(initPrivBytes)
			case ciphersuite.MLS128DHKEMP256:
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

			group, err := JoinFromWelcome(welcome, kp, privKeys, nil)
			if err != nil {
				t.Fatalf("JoinFromWelcome: %v", err)
			}
			if group == nil {
				t.Fatal("expected non-nil group")
			}
			if welcome.GroupInfo == nil {
				t.Fatal("expected welcome.GroupInfo to be populated")
			}

			signerPubBytes := mustDecodeHexBytes(t, v.SignerPub)
			signerPub := ciphersuite.NewMLSSignaturePublicKey(signerPubBytes, cs.SignatureScheme())
			sig := ciphersuite.NewSignature(welcome.GroupInfo.Signature)
			if err := ciphersuite.VerifyWithLabel(signerPub, "GroupInfoTBS", welcome.GroupInfo.MarshalTBS(), sig); err != nil {
				t.Fatalf("group info signature sametch with signer_pub: %v", err)
			}
		})
	}
}
