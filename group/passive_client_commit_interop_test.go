package group

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/keypackages"
)

type passiveClientCommitVector struct {
	CipherSuite               int     `json:"cipher_suite"`
	KeyPackage                string  `json:"key_package"`
	SignaturePriv             string  `json:"signature_priv"`
	EncryptionPriv            string  `json:"encryption_priv"`
	InitPriv                  string  `json:"init_priv"`
	Welcome                   string  `json:"welcome"`
	RatchetTree               *string `json:"ratchet_tree"`
	InitialEpochAuthenticator string  `json:"initial_epoch_authenticator"`
	ExternalPsks              []struct {
		PskID string `json:"psk_id"`
		Psk   string `json:"psk"`
	} `json:"external_psks"`
	Epochs []struct {
		Proposals          []string `json:"proposals"`
		Commit             string   `json:"commit"`
		EpochAuthenticator string   `json:"epoch_authenticator"`
	} `json:"epochs"`
}

func TestPassiveClientHandlingCommitVectors(t *testing.T) {
	data, err := os.ReadFile("../testdata/mls-interop-testvectors/test-vectors/passive-client-handling-commit.json")
	if err != nil {
		t.Fatalf("reading test vectors: %v", err)
	}

	var vecs []passiveClientCommitVector
	if err := json.Unmarshal(data, &vecs); err != nil {
		t.Fatalf("unmarshaling test vectors: %v", err)
	}

	tested := 0
	for i, v := range vecs {
		cs := ciphersuite.CipherSuite(v.CipherSuite)
		if !cs.IsSupported() {
			continue
		}
		t.Run(fmt.Sprintf("vector-%d", i), func(t *testing.T) {
			runPassiveClientCommitVector(t, &v)
		})
		tested++
	}
	if tested == 0 {
		t.Fatal("no supported cipher suite vectors found")
	}
}

func runPassiveClientCommitVector(t *testing.T, v *passiveClientCommitVector) {
	t.Helper()

	// Parse key_package (MLSMessage-wrapped: skip 4-byte header)
	kpData := mustDecodeHex(t, v.KeyPackage)
	kp, err := keypackages.UnmarshalKeyPackage(kpData[4:])
	if err != nil {
		t.Fatalf("UnmarshalKeyPackage: %v", err)
	}

	// Build private keys
	cs := ciphersuite.CipherSuite(v.CipherSuite)
	var curve ecdh.Curve
	if cs == ciphersuite.MLS128DHKEMX25519 || cs == ciphersuite.MLS128DHKEMX25519ChaCha20 {
		curve = ecdh.X25519()
	} else {
		curve = ecdh.P256()
	}

	initPrivBytes := mustDecodeHex(t, v.InitPriv)
	initPrivKey, err := curve.NewPrivateKey(initPrivBytes)
	if err != nil {
		t.Fatalf("init_priv: %v", err)
	}

	encPrivBytes := mustDecodeHex(t, v.EncryptionPriv)
	encPrivKey, err := curve.NewPrivateKey(encPrivBytes)
	if err != nil {
		t.Fatalf("encryption_priv: %v", err)
	}

	privKeys := &keypackages.KeyPackagePrivateKeys{
		InitKey:       initPrivKey,
		EncryptionKey: encPrivKey,
	}

	// Build external PSK map
	psks := make(map[string][]byte)
	for _, p := range v.ExternalPsks {
		id := mustDecodeHex(t, p.PskID)
		psk := mustDecodeHex(t, p.Psk)
		psks[string(id)] = psk
	}

	// Parse welcome (MLSMessage-wrapped: skip 4-byte header)
	welcomeData := mustDecodeHex(t, v.Welcome)
	welcome, err := UnmarshalWelcome(welcomeData[4:])
	if err != nil {
		t.Fatalf("UnmarshalWelcome: %v", err)
	}

	// Join
	group, err := JoinFromWelcome(welcome, kp, privKeys, psks)
	if err != nil {
		t.Fatalf("JoinFromWelcome: %v", err)
	}

	// Verify initial epoch authenticator
	wantInitEA := mustDecodeHex(t, v.InitialEpochAuthenticator)
	if !bytes.Equal(group.EpochAuthenticator(), wantInitEA) {
		t.Fatalf("initial_epoch_authenticator sametch:\n  got  %x\n  want %x",
			group.EpochAuthenticator(), wantInitEA)
	}

	// Process each epoch
	for epochIdx, epoch := range v.Epochs {
		// Process proposals first
		for propIdx, propHex := range epoch.Proposals {
			propBytes := mustDecodeHex(t, propHex)
			msg, err := framing.UnmarshalMLSMessage(propBytes)
			if err != nil {
				t.Fatalf("epoch %d proposal %d: UnmarshalMLSMessage: %v", epochIdx, propIdx, err)
			}
			if pm, ok := msg.AsPublic(); ok {
				if err := group.ProcessPublicMessage(pm); err != nil {
					t.Fatalf("epoch %d proposal %d: ProcessPublicMessage: %v", epochIdx, propIdx, err)
				}
			}
			// Private proposals are skipped (can't decrypt without sender data key)
		}

		// Process commit
		commitBytes := mustDecodeHex(t, epoch.Commit)
		msg, err := framing.UnmarshalMLSMessage(commitBytes)
		if err != nil {
			t.Fatalf("epoch %d: UnmarshalMLSMessage(commit): %v", epochIdx, err)
		}

		if pm, ok := msg.AsPublic(); ok {
			if err := group.ProcessPublicMessage(pm); err != nil {
				t.Fatalf("epoch %d: ProcessPublicMessage(commit): %v", epochIdx, err)
			}
		} else {
			t.Fatalf("epoch %d: expected PublicMessage commit, got wire_format=%d", epochIdx, msg.WireFormat())
		}

		// Verify epoch authenticator
		wantEA := mustDecodeHex(t, epoch.EpochAuthenticator)
		if !bytes.Equal(group.EpochAuthenticator(), wantEA) {
			t.Fatalf("epoch %d: epoch_authenticator sametch:\n  got  %x\n  want %x",
				epochIdx, group.EpochAuthenticator(), wantEA)
		}
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}
