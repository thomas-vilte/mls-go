package secrettree

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// Structures for parsing test vector JSON.
type secretTreeSenderData struct {
	SenderDataSecret string `json:"sender_data_secret"`
	Ciphertext       string `json:"ciphertext"`
	Key              string `json:"key"`
	Nonce            string `json:"nonce"`
}

type secretTreeLeafGeneration struct {
	Generation       uint32 `json:"generation"`
	ApplicationKey   string `json:"application_key"`
	ApplicationNonce string `json:"application_nonce"`
	HandshakeKey     string `json:"handshake_key"`
	HandshakeNonce   string `json:"handshake_nonce"`
}

type secretTreeVector struct {
	CipherSuite      uint16                       `json:"cipher_suite"`
	EncryptionSecret string                       `json:"encryption_secret"`
	SenderData       secretTreeSenderData         `json:"sender_data"`
	Leaves           [][]secretTreeLeafGeneration `json:"leaves"`
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

// TestSecretTreeVectors runs Secret Tree interoperability test vectors
// according to RFC 9420 §9.
//
// The test vectors verify that:
//  1. Leaf secret derivation from encryption_secret is correct
//  2. Handshake and application ratchet root derivation is correct
//  3. Forward ratchet generates the expected keys/nonces for each generation
//
// Source: testdata/mls-interop-testvectors/test-vectors/secret-tree.json
func TestSecretTreeVectors(t *testing.T) {
	data, err := os.ReadFile("../testdata/mls-interop-testvectors/test-vectors/secret-tree.json")
	if err != nil {
		t.Skipf("secret-tree.json not found: %v", err)
	}

	var vectors []secretTreeVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse secret-tree.json: %v", err)
	}

	for i, v := range vectors {
		cs := ciphersuite.CipherSuite(v.CipherSuite)

		// Solo testear cipher suites soportados
		// CS=1: MLS_128_DHKEX255519_SHA256_Ed25519 (soportado, pero HPKE key schedule necesita fix)
		// CS=2: MLS_128_DHKEMP256_AES128GCM_SHA256_P256 (implementado) ✅
		// CS=3: MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 (soportado, pero HPKE key schedule necesita fix)
		if !cs.IsSupported() {
			continue
		}

		// All implemented cipher suites (CS1, CS2, CS3) are now fully supported
		// including proper HPKE key schedule and AEAD dispatch.

		t.Run(fmt.Sprintf("cs%d-v%d", v.CipherSuite, i), func(t *testing.T) {
			testSecretTreeVector(t, v, cs)
		})
	}
}

func testSecretTreeVector(t *testing.T, v secretTreeVector, cs ciphersuite.CipherSuite) {
	// Decodificar encryption_secret
	encryptionSecretBytes := mustDecodeHex(t, v.EncryptionSecret)

	// Crear Secret Tree
	leafCount := uint32(len(v.Leaves))

	// Verify each leaf
	for leafIndex, leafGens := range v.Leaves {
		t.Run(fmt.Sprintf("leaf%d", leafIndex), func(t *testing.T) {
			// For each leaf, we need a NEW tree because ratchet forward is destructive
			// (once you ratchet to gen 15, you can't go back to gen 0)
			leafTree, err := NewTree(ciphersuite.NewSecret(encryptionSecretBytes), leafCount, cs)
			if err != nil {
				t.Fatalf("NewTree failed: %v", err)
			}

			// Obtener leaf secret
			leaf, err := leafTree.LeafForIndex(uint32(leafIndex))
			if err != nil {
				t.Fatalf("LeafForIndex(%d) failed: %v", leafIndex, err)
			}

			// Verify each generation in the test vector
			// IMPORTANT: Test vectors assume sequential forward ratchet
			// You cannot skip to gen 15 without going through 0-14
			for _, expected := range leafGens {
				genName := fmt.Sprintf("gen%d", expected.Generation)
				t.Run(genName, func(t *testing.T) {
					// Ratchet forward to the expected generation (RFC 9420 §9.1)
					if err := leaf.ratchetTo(expected.Generation); err != nil {
						t.Fatalf("ratchetTo(%d): %v", expected.Generation, err)
					}

					// Derive key/nonce for the current generation
					appKey, err := leaf.ApplicationKey(expected.Generation)
					if err != nil {
						t.Fatalf("ApplicationKey(%s) failed: %v", genName, err)
					}

					appNonce, err := leaf.ApplicationNonce(expected.Generation)
					if err != nil {
						t.Fatalf("ApplicationNonce(%s) failed: %v", genName, err)
					}

					hsKey, err := leaf.HandshakeKey(expected.Generation)
					if err != nil {
						t.Fatalf("HandshakeKey(%s) failed: %v", genName, err)
					}

					hsNonce, err := leaf.HandshakeNonce(expected.Generation)
					if err != nil {
						t.Fatalf("HandshakeNonce(%s) failed: %v", genName, err)
					}

					// Compare with expected values
					expectedAppKey := mustDecodeHex(t, expected.ApplicationKey)
					expectedAppNonce := mustDecodeHex(t, expected.ApplicationNonce)
					expectedHsKey := mustDecodeHex(t, expected.HandshakeKey)
					expectedHsNonce := mustDecodeHex(t, expected.HandshakeNonce)

					if !bytes.Equal(appKey, expectedAppKey) {
						t.Errorf("application_key mismatch for %s\n  got  %x\n  want %x",
							genName, appKey, expectedAppKey)
					}

					if !bytes.Equal(appNonce, expectedAppNonce) {
						t.Errorf("application_nonce mismatch for %s\n  got  %x\n  want %x",
							genName, appNonce, expectedAppNonce)
					}

					if !bytes.Equal(hsKey, expectedHsKey) {
						t.Errorf("handshake_key mismatch for %s\n  got  %x\n  want %x",
							genName, hsKey, expectedHsKey)
					}

					if !bytes.Equal(hsNonce, expectedHsNonce) {
						t.Errorf("handshake_nonce mismatch for %s\n  got  %x\n  want %x",
							genName, hsNonce, expectedHsNonce)
					}
				})
			}
		})
	}
}

// TestSecretTreeDerivation verifies basic secret derivation
// according to RFC 9420 §9, Figure 25 and Figure 26.
func TestSecretTreeDerivation(t *testing.T) {
	// Simple test vector with CS=2
	encryptionSecretHex := "d69fcc35969e94680461974bd26c7cda7594cbf45985c4bf668c3b3118b765ab" //nolint:gosec // This is a test vector, not a credential
	encryptionSecretBytes := mustDecodeHex(t, encryptionSecretHex)
	encryptionSecret := ciphersuite.NewSecret(encryptionSecretBytes)

	// Create tree with 1 leaf
	tree, err := NewTree(encryptionSecret, 1, ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("NewTree failed: %v", err)
	}

	// Obtener leaf 0
	leaf, err := tree.LeafForIndex(0)
	if err != nil {
		t.Fatalf("LeafForIndex(0) failed: %v", err)
	}

	// Verify it can derive keys for generation 0
	appKey, err := leaf.ApplicationKey(0)
	if err != nil {
		t.Fatalf("ApplicationKey(0) failed: %v", err)
	}

	if len(appKey) != 16 {
		t.Errorf("application_key length should be 16, got %d", len(appKey))
	}

	appNonce, err := leaf.ApplicationNonce(0)
	if err != nil {
		t.Fatalf("ApplicationNonce(0) failed: %v", err)
	}

	if len(appNonce) != 12 {
		t.Errorf("application_nonce length should be 12, got %d", len(appNonce))
	}

	// Verify different generations give different keys
	appKey1, _ := leaf.ApplicationKey(1)
	if bytes.Equal(appKey, appKey1) {
		t.Error("application_key should be different for different generations")
	}
}

// TestSecretTreeBounds verifica que los límites del árbol se validan correctamente.
func TestSecretTreeBounds(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 4, ciphersuite.MLS128DHKEMP256)

	// Índice válido
	_, err := tree.LeafForIndex(0)
	if err != nil {
		t.Errorf("LeafForIndex(0) should succeed: %v", err)
	}

	_, err = tree.LeafForIndex(3)
	if err != nil {
		t.Errorf("LeafForIndex(3) should succeed: %v", err)
	}

	// Índice inválido
	_, err = tree.LeafForIndex(4)
	if err == nil {
		t.Error("LeafForIndex(4) should fail for out of bounds index")
	}

	// Índice negativo (uint32 wrap)
	_, err = tree.LeafForIndex(0xFFFFFFFF)
	if err == nil {
		t.Error("LeafForIndex(0xFFFFFFFF) should fail for out of bounds index")
	}
}

// TestSecretTreeGeneration verifica que las generaciones se derivan correctamente.
func TestSecretTreeGeneration(t *testing.T) {
	encSecret, _ := ciphersuite.NewSecretRandom(32)
	tree, _ := NewTree(encSecret, 1, ciphersuite.MLS128DHKEMP256)
	leaf, _ := tree.LeafForIndex(0)

	// Verify generations 0 and 15 give different results
	appKey0, _ := leaf.ApplicationKey(0)
	appKey15, _ := leaf.ApplicationKey(15)

	if bytes.Equal(appKey0, appKey15) {
		t.Error("application_key should be different for generations 0 and 15")
	}

	hsKey0, _ := leaf.HandshakeKey(0)
	hsKey15, _ := leaf.HandshakeKey(15)

	if bytes.Equal(hsKey0, hsKey15) {
		t.Error("handshake_key should be different for generations 0 and 15")
	}
}
