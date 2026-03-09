package schedule

import (
	"fmt"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/internal/tls"
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

// ComputePskInput computes psk_secret according to RFC 9420 §8.4.
func ComputePskInput(psks []Psk, cs ciphersuite.CipherSuite) ([]byte, error) {
	if len(psks) == 0 {
		return nil, fmt.Errorf("no PSKs provided")
	}
	out := make([]byte, cs.HashLength())
	count := uint16(len(psks))
	for i, psk := range psks {
		if len(psk.Psk) == 0 {
			return nil, fmt.Errorf("empty PSK at index %d", i)
		}
		zeroSalt := ciphersuite.ZeroSecret(cs.HashLength())
		pskSecret := ciphersuite.NewSecret(psk.Psk)
		extracted, err := zeroSalt.HKDFExtract(pskSecret)
		if err != nil {
			return nil, fmt.Errorf("extracting PSK %d: %w", i, err)
		}
		label := PSKLabel{
			PskType: psk.PskType,
			PskID:   psk.PskId,
			Index:   uint16(i),
			Count:   count,
		}
		pskLabel, err := extracted.KdfExpandLabel("derived psk", label.Marshal(), cs.HashLength())
		if err != nil {
			return nil, fmt.Errorf("expanding PSK label %d: %w", i, err)
		}
		labelBytes := pskLabel.AsSlice()
		for j := range out {
			out[j] ^= labelBytes[j]
		}
	}
	return out, nil
}

// PSKLabel according to RFC 9420 §8.4
type PSKLabel struct {
	PskType PskType
	PskID   []byte
	Index   uint16
	Count   uint16
}

func (l PSKLabel) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteUint8(uint8(l.PskType))
	w.WriteVLBytes(l.PskID)
	w.WriteUint16(l.Index)
	w.WriteUint16(l.Count)
	return w.Bytes()
}
