//nolint:unused
package ciphersuite

import (
	"crypto/sha256"
	"hash"
)

// hkdfExtract implements HKDF-Extract using HMAC-SHA256 (RFC 5869).
func hkdfExtract(salt, ikm []byte) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	return hmacSha256(salt, ikm)
}

// hkdfExpand implements HKDF-Expand using HMAC-SHA256 (RFC 5869).
func hkdfExpand(prk, info []byte, length int) []byte {
	n := (length + sha256.Size - 1) / sha256.Size
	if n > 255 {
		return nil
	}

	var okm []byte
	var t []byte
	for i := 1; i <= n; i++ {
		data := append(t, info...)
		data = append(data, byte(i))
		t = hmacSha256(prk, data)
		okm = append(okm, t...)
	}

	return okm[:length]
}

// hmacSha256 computes HMAC-SHA256.
func hmacSha256(key, message []byte) []byte {
	blockSize := 64 // SHA-256 block size

	if len(key) > blockSize {
		h := sha256.Sum256(key)
		key = h[:]
	}
	if len(key) < blockSize {
		padding := make([]byte, blockSize-len(key))
		key = append(key, padding...)
	}

	oKeyPad := make([]byte, blockSize)
	iKeyPad := make([]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		oKeyPad[i] = key[i] ^ 0x5c
		iKeyPad[i] = key[i] ^ 0x36
	}

	ihash := sha256.New()
	ihash.Write(iKeyPad)
	ihash.Write(message)
	inner := ihash.Sum(nil)

	ohash := sha256.New()
	ohash.Write(oKeyPad)
	ohash.Write(inner)
	return ohash.Sum(nil)
}

// hmacHash is an HMAC hash implementation for use with HKDF.
type hmacHash struct {
	hash  hash.Hash
	block []byte
}

func newHMAC(h func() hash.Hash, key []byte) hash.Hash {
	hm := &hmacHash{
		hash: h(),
	}

	blockSize := 64 // SHA-256 block size
	if len(key) > blockSize {
		hash := sha256.Sum256(key)
		key = hash[:]
	}
	if len(key) < blockSize {
		padding := make([]byte, blockSize-len(key))
		key = append(key, padding...)
	}

	hm.block = key
	return hm
}

func (h *hmacHash) Write(p []byte) (n int, err error) {
	return h.hash.Write(p)
}

func (h *hmacHash) Sum(b []byte) []byte {
	temp := h.hash.Sum(nil)
	h.hash.Reset()

	oKeyPad := make([]byte, 64)
	for i := range oKeyPad {
		oKeyPad[i] = h.block[i] ^ 0x5c
	}
	h.hash.Write(oKeyPad)
	h.hash.Write(temp)
	return h.hash.Sum(b)
}

func (h *hmacHash) Reset() {
	h.hash.Reset()
	iKeyPad := make([]byte, 64)
	for i := range iKeyPad {
		iKeyPad[i] = h.block[i] ^ 0x36
	}
	h.hash.Write(iKeyPad)
}

func (h *hmacHash) Size() int {
	return h.hash.Size()
}

func (h *hmacHash) BlockSize() int {
	return h.hash.BlockSize()
}
