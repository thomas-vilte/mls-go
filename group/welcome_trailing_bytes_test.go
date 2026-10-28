package group

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/internal/tls"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// interopWelcomeBody returns the Welcome body (without the MLSMessage header) of the first interop vector
// whose cipher suite is implemented.
func interopWelcomeBody(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../testdata/mls-interop-testvectors/test-vectors/welcome.json")
	if err != nil {
		t.Fatalf("read welcome.json: %v", err)
	}
	var vectors []welcomeVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse welcome.json: %v", err)
	}
	for _, v := range vectors {
		if !ciphersuite.CipherSuite(v.CipherSuite).IsSupported() {
			continue
		}
		msg := mustDecodeHexBytes(t, v.Welcome)
		if len(msg) < 4 {
			t.Fatalf("welcome MLSMessage too short: %d", len(msg))
		}
		return msg[4:]
	}
	t.Fatal("welcome.json has no Welcome vector with an implemented cipher suite")
	return nil
}

// oneMemberGroupInfoBytes returns the serialized GroupInfo of a one-member group.
func oneMemberGroupInfoBytes(t *testing.T) []byte {
	t.Helper()
	cred, _, err := credentials.GenerateCredentialWithKey([]byte("parse-test"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey: %v", err)
	}
	kp, priv, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("keypackages.Generate: %v", err)
	}
	gid, err := NewGroupIDRandom()
	if err != nil {
		t.Fatalf("NewGroupIDRandom: %v", err)
	}
	g, err := NewGroup(gid, ciphersuite.MLS128DHKEMP256, kp, priv)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	gi, err := g.GetGroupInfo(ciphersuite.NewSignaturePrivateKey(priv.SignatureKey))
	if err != nil {
		t.Fatalf("GetGroupInfo: %v", err)
	}
	return gi.Marshal()
}

// TestWelcomeParsersRejectTrailingAndMalformedData checks that UnmarshalWelcome, UnmarshalGroupInfo and
// UnmarshalGroupSecrets refuse bytes after the structure, and that a malformed entry in the Welcome secrets
// vector is an error. Each mutated input follows a control that parses, so a failure comes from the mutation.
func TestWelcomeParsersRejectTrailingAndMalformedData(t *testing.T) {
	trailing := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	t.Run("Welcome/trailing_bytes", func(t *testing.T) {
		body := interopWelcomeBody(t)
		if _, err := UnmarshalWelcome(body); err != nil {
			t.Fatalf("control: valid Welcome rejected: %v", err)
		}
		mutated := append(append([]byte(nil), body...), trailing...)
		if _, err := UnmarshalWelcome(mutated); err == nil {
			t.Error("UnmarshalWelcome accepted 4 trailing bytes")
		}
	})

	t.Run("GroupInfo/trailing_bytes", func(t *testing.T) {
		data := oneMemberGroupInfoBytes(t)
		if _, err := UnmarshalGroupInfo(data); err != nil {
			t.Fatalf("control: valid GroupInfo rejected: %v", err)
		}
		mutated := append(append([]byte(nil), data...), trailing...)
		if _, err := UnmarshalGroupInfo(mutated); err == nil {
			t.Error("UnmarshalGroupInfo accepted 4 trailing bytes")
		}
	})

	t.Run("GroupSecrets/trailing_bytes", func(t *testing.T) {
		data := (&Secrets{JoinerSecret: ciphersuite.NewSecret(bytes.Repeat([]byte{0x42}, 32))}).Marshal()
		if _, err := UnmarshalGroupSecrets(data); err != nil {
			t.Fatalf("control: valid GroupSecrets rejected: %v", err)
		}
		mutated := append(append([]byte(nil), data...), trailing...)
		if _, err := UnmarshalGroupSecrets(mutated); err == nil {
			t.Error("UnmarshalGroupSecrets accepted 4 trailing bytes")
		}
	})

	t.Run("Welcome/truncated_secret_entry", func(t *testing.T) {
		body := interopWelcomeBody(t)
		if _, err := UnmarshalWelcome(body); err != nil {
			t.Fatalf("control: valid Welcome rejected: %v", err)
		}

		// Rebuild the Welcome with one malformed entry at the end of the secrets vector:
		// a length prefix of 63 with no data behind it.
		r := tls.NewReader(body)
		cs, err := r.ReadUint16()
		if err != nil {
			t.Fatal(err)
		}
		secrets, err := r.ReadVLBytes()
		if err != nil {
			t.Fatal(err)
		}
		egi, err := r.ReadVLBytes()
		if err != nil {
			t.Fatal(err)
		}
		w := tls.NewWriter()
		w.WriteUint16(cs)
		w.WriteVLBytes(append(append([]byte(nil), secrets...), 0x3F))
		w.WriteVLBytes(egi)

		if _, err := UnmarshalWelcome(w.Bytes()); err == nil {
			t.Error("UnmarshalWelcome dropped a truncated secrets entry without an error")
		}
	})
}
