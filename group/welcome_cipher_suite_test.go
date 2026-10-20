package group

import (
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/internal/tls"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// unsupportedCipherSuites includes unregistered values and the unimplemented CS4.
var unsupportedCipherSuites = []uint16{0x0080, 0x0000, 0xFFFF, 0x0004}

// mustNotPanic runs fn and fails the test with the panic value if fn panics.
// Without it, a panic inside a subtest aborts the whole test binary.
func mustNotPanic(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", what, r)
		}
	}()
	fn()
}

// newCipherSuiteTestKeyPackage returns a valid CS1 KeyPackage and its private keys.
func newCipherSuiteTestKeyPackage(t *testing.T) (*keypackages.KeyPackage, *keypackages.KeyPackagePrivateKeys) {
	t.Helper()
	cred, _, err := credentials.GenerateCredentialWithKeyForCS([]byte("alice"), ciphersuite.MLS128DHKEMX25519)
	if err != nil {
		t.Fatalf("GenerateCredentialWithKeyForCS: %v", err)
	}
	kp, priv, err := keypackages.Generate(cred, keypackages.MLS128DHKEMX25519)
	if err != nil {
		t.Fatalf("keypackages.Generate: %v", err)
	}
	return kp, priv
}

// newCipherSuiteTestKeyPackageBytes returns a CS1 KeyPackage encoded with its cipher_suite
// (bytes 2-3, after protocol_version) replaced by cs. The signature no longer
// matches, which is irrelevant: the parser must reject the suite before that.
func newCipherSuiteTestKeyPackageBytes(t *testing.T, cs uint16) []byte {
	t.Helper()
	kp, _ := newCipherSuiteTestKeyPackage(t)
	data := kp.Marshal()
	data[2], data[3] = byte(cs>>8), byte(cs)
	return data
}

// TestWelcomeUnsupportedCipherSuite checks that Welcome, GroupInfo, and KeyPackage
// processing rejects unsupported cipher suites without panicking.
func TestWelcomeUnsupportedCipherSuite(t *testing.T) {
	t.Parallel()

	for _, cs := range unsupportedCipherSuites {
		t.Run(fmt.Sprintf("UnmarshalWelcome/cs=0x%04x", cs), func(t *testing.T) {
			// 4 bytes for 0x0080: suite, empty secrets<V>, empty encrypted_group_info<V>.
			data := (&Welcome{CipherSuite: ciphersuite.CipherSuite(cs), EncryptedGroupInfo: []byte{}}).Marshal()
			mustNotPanic(t, "UnmarshalWelcome", func() {
				if _, err := UnmarshalWelcome(data); !errors.Is(err, ErrUnsupportedCipherSuite) {
					t.Fatalf("UnmarshalWelcome err = %v, want ErrUnsupportedCipherSuite", err)
				}
			})
		})

		t.Run(fmt.Sprintf("JoinFromWelcome/cs=0x%04x", cs), func(t *testing.T) {
			kp, privKeys := newCipherSuiteTestKeyPackage(t)
			// Built by hand, so it never went through UnmarshalWelcome.
			welcome := &Welcome{
				CipherSuite:        ciphersuite.CipherSuite(cs),
				Secrets:            []EncryptedGroupSecrets{{NewMember: []byte{0x01, 0x02, 0x03}}},
				EncryptedGroupInfo: []byte{},
			}
			mustNotPanic(t, "JoinFromWelcome", func() {
				if _, err := JoinFromWelcome(welcome, kp, privKeys, nil); !errors.Is(err, ErrUnsupportedCipherSuite) {
					t.Fatalf("JoinFromWelcome err = %v, want ErrUnsupportedCipherSuite", err)
				}
			})
		})

		t.Run(fmt.Sprintf("UnmarshalGroupInfo/cs=0x%04x", cs), func(t *testing.T) {
			// Use 64-byte hashes so the fixture also accommodates CS4's hash length.
			data := (&Info{
				GroupContext: &GroupContext{
					Version:                 keypackages.MLS10,
					CipherSuite:             ciphersuite.CipherSuite(cs),
					GroupID:                 NewGroupID([]byte("alice")),
					Epoch:                   NewGroupEpoch(0),
					TreeHash:                make([]byte, 64),
					ConfirmedTranscriptHash: make([]byte, 64),
				},
				ConfirmationTag: make([]byte, 64),
			}).Marshal()
			mustNotPanic(t, "UnmarshalGroupInfo", func() {
				if _, err := UnmarshalGroupInfo(data); !errors.Is(err, ErrUnsupportedCipherSuite) {
					t.Fatalf("UnmarshalGroupInfo err = %v, want ErrUnsupportedCipherSuite", err)
				}
			})
		})

		t.Run(fmt.Sprintf("UnmarshalKeyPackage/cs=0x%04x", cs), func(t *testing.T) {
			data := newCipherSuiteTestKeyPackageBytes(t, cs)
			mustNotPanic(t, "UnmarshalKeyPackage", func() {
				if _, err := keypackages.UnmarshalKeyPackage(data); !errors.Is(err, ciphersuite.ErrUnsupportedSuite) {
					t.Fatalf("UnmarshalKeyPackage err = %v, want ciphersuite.ErrUnsupportedSuite", err)
				}
			})
		})

		t.Run(fmt.Sprintf("UnmarshalKeyPackageFromReader/cs=0x%04x", cs), func(t *testing.T) {
			data := newCipherSuiteTestKeyPackageBytes(t, cs)
			mustNotPanic(t, "UnmarshalKeyPackageFromReader", func() {
				if _, err := keypackages.UnmarshalKeyPackageFromReader(tls.NewReader(data)); !errors.Is(err, ciphersuite.ErrUnsupportedSuite) {
					t.Fatalf("UnmarshalKeyPackageFromReader err = %v, want ciphersuite.ErrUnsupportedSuite", err)
				}
			})
		})
	}

	// Control: the cipher_suite 1 vector of the interop Welcome set must still join.
	t.Run("control/welcome.json-cs1", func(t *testing.T) {
		data, err := os.ReadFile("../testdata/mls-interop-testvectors/test-vectors/welcome.json")
		if err != nil {
			t.Skipf("welcome.json not found: %v", err)
		}
		var vectors []welcomeVector
		if err := json.Unmarshal(data, &vectors); err != nil {
			t.Fatalf("parse welcome.json: %v", err)
		}
		idx := -1
		for i, v := range vectors {
			if v.CipherSuite == uint16(ciphersuite.MLS128DHKEMX25519) {
				idx = i
				break
			}
		}
		if idx < 0 {
			t.Skip("welcome.json has no cipher_suite 1 vector")
		}
		v := vectors[idx]

		kpData := mustDecodeHexBytes(t, v.KeyPackage)
		if len(kpData) < 4 {
			t.Fatalf("key_package MLSMessage too short: %d", len(kpData))
		}
		kp, err := keypackages.UnmarshalKeyPackage(kpData[4:])
		if err != nil {
			t.Fatalf("UnmarshalKeyPackage: %v", err)
		}
		initPriv, err := ecdh.X25519().NewPrivateKey(mustDecodeHexBytes(t, v.InitPriv))
		if err != nil {
			t.Fatalf("parse init_priv: %v", err)
		}
		welcomeData := mustDecodeHexBytes(t, v.Welcome)
		if len(welcomeData) < 4 {
			t.Fatalf("welcome MLSMessage too short: %d", len(welcomeData))
		}
		welcome, err := UnmarshalWelcome(welcomeData[4:])
		if err != nil {
			t.Fatalf("UnmarshalWelcome: %v", err)
		}
		privKeys := &keypackages.KeyPackagePrivateKeys{InitKey: initPriv}
		if _, err := JoinFromWelcome(welcome, kp, privKeys, nil); err != nil {
			t.Fatalf("JoinFromWelcome: %v", err)
		}
	})
}

// TestKeyPackageRefCipherSuiteValidation covers unsupported suites, supported suite
// reference lengths, and nil KeyPackages.
func TestKeyPackageRefCipherSuiteValidation(t *testing.T) {
	t.Parallel()
	kp, _ := newCipherSuiteTestKeyPackage(t)

	if _, err := keyPackageRef(kp, 0x0080); !errors.Is(err, ErrUnsupportedCipherSuite) {
		t.Fatalf("keyPackageRef(cs=0x0080) err = %v, want ErrUnsupportedCipherSuite", err)
	}
	ref, err := keyPackageRef(kp, ciphersuite.MLS128DHKEMX25519)
	if err != nil {
		t.Fatalf("keyPackageRef(cs=1) err = %v", err)
	}
	if len(ref) != 32 {
		t.Fatalf("keyPackageRef(cs=1) len = %d, want 32 (SHA-256)", len(ref))
	}
	if ref, err := keyPackageRef(nil, 0x0080); ref != nil || err != nil {
		t.Fatalf("keyPackageRef(nil) = %x, %v; want nil, nil", ref, err)
	}
}
