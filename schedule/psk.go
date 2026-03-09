package schedule

import (
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

	out := make([]byte, cs.HashLength())
	for _, psk := range psks {
		if len(psk.Psk) == 0 {
			return nil, fmt.Errorf("empty PSK")
		}

		secret := ciphersuite.NewSecret(psk.Psk)
		derived, err := secret.HKDFExpand([]byte("derived psk"), cs.HashLength())
		if err != nil {
			return nil, fmt.Errorf("deriving psk input: %w", err)
		}

		derivedBytes := derived.AsSlice()
		for i := range out {
			out[i] ^= derivedBytes[i]
		}
	}

	return out, nil
}
