// Package ciphersuite - Cipher Suite 2 (MLS_128_DHKEMP256_AES128GCM_SHA256_P256)
package ciphersuite

import (
	"crypto/ecdh"
	"fmt"
)

// DeriveKeyPairP256 derives a P-256 key pair deterministically from IKM (RFC 9180 §4.1).
//
//  1. PRK = HKDF.Extract(salt="", ikm)
//  2. sk  = HKDF.Expand(PRK, "DKEM P256", 32)
//  3. pk  = sk.PublicKey()
//
// The info string "DKEM P256" is used as a plain byte slice (no KDF label wrapping),
// consistent with DeriveKeyPairX25519 and the RFC 9180 §4.1 spec.
func DeriveKeyPairP256(ikm []byte) (pubKey, privKey []byte, err error) {
	hkdf := NewHKDF()
	prk := hkdf.Extract(nil, ikm)

	okm, err := hkdf.Expand(prk, []byte("DKEM P256"), 32)
	if err != nil {
		return nil, nil, fmt.Errorf("HKDF expand: %w", err)
	}

	privKeyECDH, err := ecdh.P256().NewPrivateKey(okm)
	if err != nil {
		return nil, nil, err
	}

	pubKeyECDH := privKeyECDH.PublicKey()
	return pubKeyECDH.Bytes(), privKeyECDH.Bytes(), nil
}
