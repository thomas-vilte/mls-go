package schedule

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/openmls/go/ciphersuite"
)

// PskType identifies the type of Pre-Shared Key.
type PskType uint8

const (
	PskTypeExternal   PskType = 0x00
	PskTypeResumption PskType = 0x01
	PskTypeBranch     PskType = 0x02
)

// Psk represents a Pre-Shared Key.
type Psk struct {
	PskType PskType
	PskId   []byte
	Psk     []byte
}

// ComputePskInput computes the PSK input for the key schedule.
func ComputePskInput(psks []Psk, cs ciphersuite.CipherSuite) ([]byte, error) {
	if len(psks) == 0 {
		return nil, fmt.Errorf("no PSKs provided")
	}

	if len(psks) == 1 {
		return psks[0].Psk, nil
	}

	// Combine multiple PSKs using HMAC
	pskInput := psks[0].Psk
	for i := 1; i < len(psks); i++ {
		h := hmac.New(sha256.New, pskInput)
		h.Write(psks[i].Psk)
		pskInput = h.Sum(nil)
	}

	return pskInput, nil
}
