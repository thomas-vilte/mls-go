package schedule

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

type pskVectorPsk struct {
	PskID    string `json:"psk_id"`
	Psk      string `json:"psk"`
	PskNonce string `json:"psk_nonce"`
}

type pskVector struct {
	CipherSuite uint16         `json:"cipher_suite"`
	Psks        []pskVectorPsk `json:"psks"`
	PskSecret   string         `json:"psk_secret"`
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

func TestPskSecretVectors(t *testing.T) {
	data, err := os.ReadFile("../testdata/mls-interop-testvectors/test-vectors/psk_secret.json")
	if err != nil {
		t.Skipf("psk_secret.json not found: %v", err)
	}

	var vectors []pskVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse psk_secret.json: %v", err)
	}

	for i, v := range vectors {
		cs := ciphersuite.CipherSuite(v.CipherSuite)
		if !cs.IsSupported() {
			continue
		}

		t.Run(fmt.Sprintf("cs%d-v%d", v.CipherSuite, i), func(t *testing.T) {
			expectedSecret := mustDecodeHex(t, v.PskSecret)

			var psks []Psk
			for _, p := range v.Psks {
				psks = append(psks, Psk{
					PskType:  PskTypeExternal,
					PskID:    mustDecodeHex(t, p.PskID),
					PskNonce: mustDecodeHex(t, p.PskNonce),
					Psk:      mustDecodeHex(t, p.Psk),
				})
			}

			var got []byte
			if len(psks) == 0 {
				got = make([]byte, cs.HashLength())
			} else {
				got, err = ComputePskInput(psks, cs)
				if err != nil {
					t.Fatalf("ComputePskInput: %v", err)
				}
			}

			if !bytes.Equal(got, expectedSecret) {
				t.Errorf("psk_secret mismatch\n  got  %x\n  want %x", got, expectedSecret)
			}
		})
	}
}
