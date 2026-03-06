package ciphersuite

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/openmls/go/internal/tls"
)

// EncryptContext represents the context for HPKE encryption (RFC 9420 §5.1.3).
//
//	struct {
//	    opaque label<V>;
//	    opaque context<V>;
//	} EncryptContext;
type EncryptContext struct {
	Label   []byte
	Context []byte
}

// NewEncryptContext creates an encryption context with MLS prefix.
func NewEncryptContext(label string, context []byte) *EncryptContext {
	return &EncryptContext{
		Label:   []byte(LabelPrefix + label),
		Context: context,
	}
}

// Marshal serializes the context to TLS format.
func (ec *EncryptContext) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteVLBytes(ec.Label)
	w.WriteVLBytes(ec.Context)
	return w.Bytes()
}

// EncryptWithLabel encrypts to an HPKE public key with label (RFC 9420 §5.1.3).
//
// EncryptWithLabel(PublicKey, Label, Context, Plaintext) =
//
//	SealBase(PublicKey, EncryptContext, "", Plaintext)
func EncryptWithLabel(
	publicKey []byte,
	label string,
	context []byte,
	plaintext []byte,
	ciphersuite CipherSuite,
) (*HpkeCiphertext, error) {
	encContext := NewEncryptContext(label, context)
	return encryptWithLabelInternal(publicKey, encContext, plaintext, ciphersuite)
}

func encryptWithLabelInternal(
	publicKey []byte,
	encContext *EncryptContext,
	plaintext []byte,
	ciphersuite CipherSuite,
) (*HpkeCiphertext, error) {
	contextBytes := encContext.Marshal()

	// Generate ephemeral key pair
	privKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral key: %w", err)
	}

	// Parse recipient public key
	pubKey, err := ecdh.P256().NewPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	// DH key agreement
	sharedSecret, err := privKey.ECDH(pubKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	// Extract ephemeral public key
	kemOutput := privKey.PublicKey().Bytes()

	// Derive keys using HKDF
	suiteID := hpkeSuiteID(ciphersuite)
	info := append(suiteID, contextBytes...)

	// secret = Extract(dh_secret, psk)
	// For Base mode, psk is empty
	secret := hkdfExtract(sharedSecret, nil)

	// key = Expand(secret, "key", Nk)
	key, err := hkdfExpand(secret, labeledExpand(info, "key", suiteID), 16)
	if err != nil {
		return nil, fmt.Errorf("hkdf expand key: %w", err)
	}

	// base_nonce = Expand(secret, "base_nonce", Nn)
	baseNonce, err := hkdfExpand(secret, labeledExpand(info, "base_nonce", suiteID), 12)
	if err != nil {
		return nil, fmt.Errorf("hkdf expand nonce: %w", err)
	}

	// seq = 0
	seq := make([]byte, 12)

	// nonce = base_nonce XOR seq
	nonce := xorBytes(baseNonce, seq)

	// Encrypt using AES-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	return &HpkeCiphertext{
		KEMOutput:  kemOutput,
		Ciphertext: ciphertext,
	}, nil
}

// DecryptWithLabel decrypts with HPKE and label (RFC 9420 §5.1.3).
//
// DecryptWithLabel(PrivateKey, Label, Context, KEMOutput, Ciphertext) =
//
//	OpenBase(KEMOutput, PrivateKey, EncryptContext, "", Ciphertext)
func DecryptWithLabel(
	privateKey []byte,
	label string,
	context []byte,
	ciphertext *HpkeCiphertext,
	ciphersuite CipherSuite,
) ([]byte, error) {
	encContext := NewEncryptContext(label, context)
	return decryptWithLabelInternal(privateKey, encContext, ciphertext, ciphersuite)
}

func decryptWithLabelInternal(
	privateKey []byte,
	encContext *EncryptContext,
	ciphertext *HpkeCiphertext,
	ciphersuite CipherSuite,
) ([]byte, error) {
	contextBytes := encContext.Marshal()

	// Parse recipient private key
	privKey, err := ecdh.P256().NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	// Parse ephemeral public key
	pubKey, err := ecdh.P256().NewPublicKey(ciphertext.KEMOutput)
	if err != nil {
		return nil, fmt.Errorf("parsing ephemeral public key: %w", err)
	}

	// DH key agreement
	sharedSecret, err := privKey.ECDH(pubKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	// Derive keys using HKDF
	suiteID := hpkeSuiteID(ciphersuite)
	info := append(suiteID, contextBytes...)

	// secret = Extract(dh_secret, psk)
	secret := hkdfExtract(sharedSecret, nil)

	// key = Expand(secret, "key", Nk)
	key, err := hkdfExpand(secret, labeledExpand(info, "key", suiteID), 16)
	if err != nil {
		return nil, fmt.Errorf("hkdf expand key: %w", err)
	}

	// base_nonce = Expand(secret, "base_nonce", Nn)
	baseNonce, err := hkdfExpand(secret, labeledExpand(info, "base_nonce", suiteID), 12)
	if err != nil {
		return nil, fmt.Errorf("hkdf expand nonce: %w", err)
	}

	// seq = 0
	seq := make([]byte, 12)

	// nonce = base_nonce XOR seq
	nonce := xorBytes(baseNonce, seq)

	// Decrypt using AES-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: creating cipher: %v", ErrAeadDecryption, err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: creating GCM: %v", ErrAeadDecryption, err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAeadDecryption, err)
	}

	return plaintext, nil
}

// DeriveKeyPair derives an HPKE key pair from a secret (RFC 9180 §4.1).
func DeriveKeyPair(cs CipherSuite, ikm []byte) (*ecdh.PrivateKey, error) {
	// For DHKEM(P-256, HKDF-SHA256)
	// dkp_prk = Extract("", ikm)
	dkpPrk := hkdfExtract(ikm, nil)

	// info = labeledExpand("", "dkp_sk", suite_id)
	suiteID := hpkeSuiteID(cs)
	info := labeledExpand(nil, "dkp_sk", suiteID)

	// sk = Expand(dkp_prk, info, Nsk)
	// Nsk = 32 for P-256
	skBytes, err := hkdfExpand(dkpPrk, info, 32)
	if err != nil {
		return nil, err
	}

	return ecdh.P256().NewPrivateKey(skBytes)
}

func hpkeSuiteID(cs CipherSuite) []byte {
	// suite_id = "HPKE" || 0x00 || kem_id || kdf_id || aead_id
	config := cs.HPKEConfig()
	suiteID := make([]byte, 10)
	suiteID[0] = 'H'
	suiteID[1] = 'P'
	suiteID[2] = 'K'
	suiteID[3] = 'E'
	suiteID[4] = 0x00
	suiteID[5] = 0x00
	suiteID[6] = byte(config.KEM >> 8)
	suiteID[7] = byte(config.KEM)
	suiteID[8] = byte(config.KDF >> 8)
	suiteID[9] = byte(config.KDF)
	return suiteID
}

func labeledExpand(info []byte, label string, suiteID []byte) []byte {
	// labeled_info = "HPKE-v1" || suite_id || label || 0x00 || info
	labeledInfo := []byte("HPKE-v1")
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, []byte(label)...)
	labeledInfo = append(labeledInfo, 0x00)
	labeledInfo = append(labeledInfo, info...)
	return labeledInfo
}

func xorBytes(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}
