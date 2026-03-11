// Package ciphersuite - Cipher Suite 1 (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
//
// Implementación nativa usando crypto/ecdh de Go 1.26.
package ciphersuite

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

// GenerateX25519KeyPair genera un X25519 key pair para CS1.
//
// Usa crypto/ecdh nativo de Go 1.26.
func GenerateX25519KeyPair() (publicKey, privateKey []byte, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pub := priv.PublicKey()
	return pub.Bytes(), priv.Bytes(), nil
}

// DeriveKeyPairX25519 deriva un X25519 key pair desde IKM usando HKDF (RFC 9180 §4.1).
//
// Implementa:
//   1. PRK = HKDF.Extract(salt="", ikm)
//   2. seed = HKDF.Expand(PRK, "DKEM X25519", 32)
//   3. sk = seed como private key X25519
//   4. pk = sk.PublicKey()
func DeriveKeyPairX25519(ikm []byte) ([]byte, []byte, error) {
	hkdf := NewHKDF()
	prk := hkdf.Extract(nil, ikm)

	// Expand para obtener seed de 32 bytes para X25519
	seed, err := hkdf.Expand(prk, []byte("DKEM X25519"), 32)
	if err != nil {
		return nil, nil, fmt.Errorf("HKDF expand: %w", err)
	}

	priv, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return nil, nil, err
	}

	pub := priv.PublicKey()
	return pub.Bytes(), priv.Bytes(), nil
}

// EncapToBytes hace DHKEM encapsulation, retorna (kem_output, shared_secret).
//
// Implementa RFC 9180 §4.1 para las cipher suites que usan X25519 y P256.
func EncapToBytes(recipientPubKeyBytes []byte, cs CipherSuite) ([]byte, []byte, error) {
	switch cs {
	case MLS128DHKEMX25519, MLS256DHKEMX25519ChaCha20:
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}

		pub, err := ecdh.X25519().NewPublicKey(recipientPubKeyBytes)
		if err != nil {
			return nil, nil, err
		}

		sharedSecret, err := priv.ECDH(pub)
		if err != nil {
			return nil, nil, err
		}

		return priv.PublicKey().Bytes(), sharedSecret, nil

	case MLS128DHKEMP256:
		priv, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}

		pub, err := ecdh.P256().NewPublicKey(recipientPubKeyBytes)
		if err != nil {
			return nil, nil, err
		}

		sharedSecret, err := priv.ECDH(pub)
		if err != nil {
			return nil, nil, err
		}

		return priv.PublicKey().Bytes(), sharedSecret, nil

	default:
		return nil, nil, fmt.Errorf("unsupported cipher suite: %d", cs)
	}
}

// DecapToBytes hace DHKEM decapsulation, retorna shared_secret.
//
// Implementa RFC 9180 §4.1 para las cipher suites que usan X25519 y P256.
func DecapToBytes(enc, privKeyBytes []byte, cs CipherSuite) ([]byte, error) {
	switch cs {
	case MLS128DHKEMX25519, MLS256DHKEMX25519ChaCha20:
		priv, err := ecdh.X25519().NewPrivateKey(privKeyBytes)
		if err != nil {
			return nil, err
		}

		pub, err := ecdh.X25519().NewPublicKey(enc)
		if err != nil {
			return nil, err
		}

		sharedSecret, err := priv.ECDH(pub)
		return sharedSecret, err

	case MLS128DHKEMP256:
		priv, err := ecdh.P256().NewPrivateKey(privKeyBytes)
		if err != nil {
			return nil, err
		}

		pub, err := ecdh.P256().NewPublicKey(enc)
		if err != nil {
			return nil, err
		}

		sharedSecret, err := priv.ECDH(pub)
		return sharedSecret, err

	default:
		return nil, fmt.Errorf("unsupported cipher suite: %d", cs)
	}
}
