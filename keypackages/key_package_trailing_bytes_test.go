package keypackages_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/internal/tls"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// interopWelcomeVector holds the fields of the interop Welcome vectors that this test reads.
type interopWelcomeVector struct {
	CipherSuite uint16 `json:"cipher_suite"`
	KeyPackage  string `json:"key_package"`
}

// interopKeyPackageBody returns the KeyPackage body (without the MLSMessage header) of the first interop
// vector whose cipher suite is implemented.
func interopKeyPackageBody(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../testdata/mls-interop-testvectors/test-vectors/welcome.json")
	if err != nil {
		t.Fatalf("read welcome.json: %v", err)
	}
	var vectors []interopWelcomeVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse welcome.json: %v", err)
	}
	for _, v := range vectors {
		if !ciphersuite.CipherSuite(v.CipherSuite).IsSupported() {
			continue
		}
		msg, err := hex.DecodeString(v.KeyPackage)
		if err != nil {
			t.Fatalf("hex decode key_package: %v", err)
		}
		if len(msg) < 4 {
			t.Fatalf("key_package MLSMessage too short: %d", len(msg))
		}
		return msg[4:]
	}
	t.Fatal("welcome.json has no vector with an implemented cipher suite")
	return nil
}

// TestUnmarshalKeyPackageRejectsTrailingBytes checks that UnmarshalKeyPackage refuses bytes after the
// structure, while UnmarshalKeyPackageFromReader still stops at the end of the KeyPackage, because Add
// proposals read it inline and more data follows.
func TestUnmarshalKeyPackageRejectsTrailingBytes(t *testing.T) {
	kp := interopKeyPackageBody(t)
	trailing := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	t.Run("KeyPackage/trailing_bytes", func(t *testing.T) {
		if _, err := keypackages.UnmarshalKeyPackage(kp); err != nil {
			t.Fatalf("control: valid KeyPackage rejected: %v", err)
		}
		mutated := append(append([]byte(nil), kp...), trailing...)
		if _, err := keypackages.UnmarshalKeyPackage(mutated); err == nil {
			t.Error("UnmarshalKeyPackage accepted 4 trailing bytes")
		}
	})

	t.Run("control/embedded_reader", func(t *testing.T) {
		mutated := append(append([]byte(nil), kp...), trailing...)
		r := tls.NewReader(mutated)
		if _, err := keypackages.UnmarshalKeyPackageFromReader(r); err != nil {
			t.Fatalf("UnmarshalKeyPackageFromReader: %v", err)
		}
		if r.Remaining() != len(trailing) {
			t.Errorf("Remaining() = %d, want %d", r.Remaining(), len(trailing))
		}
	})
}
