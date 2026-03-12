// Package ciphersuite - Cipher Suite 2 (MLS_128_DHKEMP256_AES128GCM_SHA256_P256)
package ciphersuite

import (
	"crypto/ecdh"
	"fmt"
)

// DeriveKeyPairP256 derives a P256 key pair from IKM using HKDF (RFC 9180 §4.1).
//
// Implements:
//  1. PRK = HKDF.Extract(salt="", ikm)
//  2. okm = HKDF.Expand(PRK, "DKEM P256", 32)
//  3. sk = okm as P256 private key
//  4. pk = sk.PublicKey()
func DeriveKeyPairP256(ikm []byte) ([]byte, []byte, error) {
	hkdf := NewHKDF()
	prk := hkdf.Extract(nil, ikm)

	info := SerializeKdfLabel("DKEM P256", []byte{}, 32)
	okm, err := hkdf.Expand(prk, info, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("HKDF expand: %w", err)
	}

	privKey, err := ecdh.P256().NewPrivateKey(okm)
	if err != nil {
		return nil, nil, err
	}

	pubKey := privKey.PublicKey()
	return pubKey.Bytes(), privKey.Bytes(), nil
}
