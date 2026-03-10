package ciphersuite

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

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

// EncapToBytes performs DHKEM encapsulation, returning (kem_output, shared_secret).
// shared_secret is the DHKEM ExtractAndExpand result (RFC 9180 §4.1).
func EncapToBytes(recipientPubKeyBytes []byte, cs CipherSuite) ([]byte, []byte, error) {
	sharedSecret, enc, err := dhkemEncap(recipientPubKeyBytes, cs)
	if err != nil {
		return nil, nil, err
	}
	return enc, sharedSecret, nil
}

// DecapToBytes performs DHKEM decapsulation, returning the shared_secret.
// shared_secret is the DHKEM ExtractAndExpand result (RFC 9180 §4.1).
func DecapToBytes(enc, privKeyBytes []byte, cs CipherSuite) ([]byte, error) {
	return dhkemDecap(enc, privKeyBytes, cs)
}

func encryptWithLabelInternal(
	publicKey []byte,
	encContext *EncryptContext,
	plaintext []byte,
	cs CipherSuite,
) (*HpkeCiphertext, error) {
	contextBytes := encContext.Marshal()

	sharedSecret, enc, err := dhkemEncap(publicKey, cs)
	if err != nil {
		return nil, fmt.Errorf("DHKEM encap: %w", err)
	}

	key, baseNonce, err := hpkeKeyScheduleBase(sharedSecret, contextBytes, cs)
	if err != nil {
		return nil, err
	}

	// seq = 0 → nonce = base_nonce XOR I2OSP(0, Nn) = base_nonce
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ct := aead.Seal(nil, baseNonce, plaintext, nil)
	return &HpkeCiphertext{KEMOutput: enc, Ciphertext: ct}, nil
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
	cs CipherSuite,
) ([]byte, error) {
	contextBytes := encContext.Marshal()

	sharedSecret, err := dhkemDecap(ciphertext.KEMOutput, privateKey, cs)
	if err != nil {
		return nil, fmt.Errorf("DHKEM decap: %w", err)
	}

	key, baseNonce, err := hpkeKeyScheduleBase(sharedSecret, contextBytes, cs)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: creating cipher: %v", ErrAeadDecryption, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: creating GCM: %v", ErrAeadDecryption, err)
	}

	plaintext, err := aead.Open(nil, baseNonce, ciphertext.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAeadDecryption, err)
	}
	return plaintext, nil
}

// DeriveKeyPair derives an HPKE key pair from IKM (RFC 9180 §4.1).
func DeriveKeyPair(cs CipherSuite, ikm []byte) (*ecdh.PrivateKey, error) {
	// DeriveKeyPair uses kem_suite_id (RFC 9180 §4.1)
	kemID := kemSuiteID(cs)
	dkpPrk := hpkeLabeledExtract(nil, "dkp_prk", ikm, kemID)
	order := elliptic.P256().Params().N

	for ctr := 0; ctr < 256; ctr++ {
		skBytes, err := hpkeLabeledExpand(dkpPrk, "candidate", []byte{byte(ctr)}, 32, kemID)
		if err != nil {
			return nil, err
		}

		skInt := new(big.Int).SetBytes(skBytes)
		if skInt.Sign() == 0 || skInt.Cmp(order) >= 0 {
			continue
		}

		priv, err := ecdh.P256().NewPrivateKey(skBytes)
		if err == nil {
			return priv, nil
		}
	}

	return nil, fmt.Errorf("derive key pair: no valid private key candidate")
}

// dhkemEncap performs DHKEM(P-256, HKDF-SHA256) encapsulation (RFC 9180 §4.1).
// Returns (shared_secret, kem_output).
func dhkemEncap(pkR []byte, cs CipherSuite) (sharedSecret, enc []byte, err error) {
	skE, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pkRKey, err := ecdh.P256().NewPublicKey(pkR)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing recipient public key: %w", err)
	}
	dh, err := skE.ECDH(pkRKey)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH: %w", err)
	}
	enc = skE.PublicKey().Bytes()
	kemCtx := append(enc, pkR...)
	sharedSecret, err = dhkemExtractAndExpand(dh, kemCtx, cs)
	if err == nil { fmt.Printf("[DEBUG encap] sharedSecret first4=%x kemCtx first4=%x\n", sharedSecret[:4], kemCtx[:4]) }
	return sharedSecret, enc, err
}

// dhkemDecap performs DHKEM(P-256, HKDF-SHA256) decapsulation (RFC 9180 §4.1).
func dhkemDecap(enc, skR []byte, cs CipherSuite) ([]byte, error) {
	privKey, err := ecdh.P256().NewPrivateKey(skR)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	pkE, err := ecdh.P256().NewPublicKey(enc)
	if err != nil {
		return nil, fmt.Errorf("parsing ephemeral public key: %w", err)
	}
	dh, err := privKey.ECDH(pkE)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	pkR := privKey.PublicKey().Bytes()
	kemCtx := append(enc, pkR...)
	ss, err := dhkemExtractAndExpand(dh, kemCtx, cs)
	if err == nil { fmt.Printf("[DEBUG decap] sharedSecret first4=%x kemCtx first4=%x pkR first4=%x\n", ss[:4], kemCtx[:4], pkR[:4]) }
	return ss, err
}

// dhkemExtractAndExpand implements ExtractAndExpand for DHKEM(P-256).
// Uses "eae_prk" label for extract (as in hpke-rs used by OpenMLS test vectors).
func dhkemExtractAndExpand(dh, kemCtx []byte, cs CipherSuite) ([]byte, error) {
	kemID := kemSuiteID(cs)
	prk := hpkeLabeledExtract(nil, "eae_prk", dh, kemID)
	return hpkeLabeledExpand(prk, "shared_secret", kemCtx, 32, kemID)
}

// hpkeKeyScheduleBase runs the HPKE KeySchedule for base mode (RFC 9180 §5.1).
// info is the serialized EncryptContext.
func hpkeKeyScheduleBase(sharedSecret, info []byte, cs CipherSuite) (key, baseNonce []byte, err error) {
	suiteID := hpkeSuiteID(cs)

	// ks_context = mode(0x00) || LabeledExtract("", "psk_id_hash", psk_id="") ||
	//                             LabeledExtract("", "info_hash", info)
	// RFC 9180 §5.1 — psk_id_hash and info_hash use LabeledExtract, NOT plain Hash()
	pskIDHash := hpkeLabeledExtract(nil, "psk_id_hash", nil, suiteID)
	infoHash := hpkeLabeledExtract(nil, "info_hash", info, suiteID)

	ksContext := []byte{0x00} // mode = base
	ksContext = append(ksContext, pskIDHash...)
	ksContext = append(ksContext, infoHash...)

	// secret = LabeledExtract(shared_secret, "secret", psk="")
	secret := hpkeLabeledExtract(sharedSecret, "secret", nil, suiteID)

	// key = LabeledExpand(secret, "key", ks_context, Nk)
	key, err = hpkeLabeledExpand(secret, "key", ksContext, 16, suiteID)
	if err != nil {
		return nil, nil, fmt.Errorf("expand key: %w", err)
	}

	// base_nonce = LabeledExpand(secret, "base_nonce", ks_context, Nn)
	baseNonce, err = hpkeLabeledExpand(secret, "base_nonce", ksContext, 12, suiteID)
	if err != nil {
		return nil, nil, fmt.Errorf("expand nonce: %w", err)
	}

	return key, baseNonce, nil
}

// hpkeSuiteID returns the full HPKE suite ID (RFC 9180 §5.1).
// suite_id = "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)
func hpkeSuiteID(cs CipherSuite) []byte {
	config := cs.HPKEConfig()
	return []byte{
		'H', 'P', 'K', 'E',
		byte(config.KEM >> 8), byte(config.KEM),
		byte(config.KDF >> 8), byte(config.KDF),
		byte(config.AEAD >> 8), byte(config.AEAD),
	}
}

// kemSuiteID returns the KEM-specific suite ID (RFC 9180 §4.1).
// kem_suite_id = "KEM" || I2OSP(kem_id, 2)
func kemSuiteID(cs CipherSuite) []byte {
	config := cs.HPKEConfig()
	return []byte{
		'K', 'E', 'M',
		byte(config.KEM >> 8), byte(config.KEM),
	}
}

// hpkeLabeledExtract computes HKDF-Extract with HPKE v1 labeling (RFC 9180 §4).
// LabeledExtract(salt, label, ikm) = HKDF-Extract(salt, "HPKE-v1" || suite_id || label || ikm)
func hpkeLabeledExtract(salt []byte, label string, ikm, suiteID []byte) []byte {
	labeled := []byte("HPKE-v1")
	labeled = append(labeled, suiteID...)
	labeled = append(labeled, []byte(label)...)
	labeled = append(labeled, ikm...)
	return hkdfExtract(salt, labeled)
}

// hpkeLabeledExpand computes HKDF-Expand with HPKE v1 labeling (RFC 9180 §4).
// LabeledExpand(prk, label, info, L) = HKDF-Expand(prk, I2OSP(L,2) || "HPKE-v1" || suite_id || label || info, L)
func hpkeLabeledExpand(prk []byte, label string, info []byte, length int, suiteID []byte) ([]byte, error) {
	labeled := []byte{byte(length >> 8), byte(length)} // I2OSP(L, 2)
	labeled = append(labeled, []byte("HPKE-v1")...)
	labeled = append(labeled, suiteID...)
	labeled = append(labeled, []byte(label)...)
	labeled = append(labeled, info...)
	return hkdfExpand(prk, labeled, length)
}
