package schedule

import (
	"fmt"

	"github.com/mls-go/ciphersuite"
	"github.com/mls-go/internal/tls"
)

// PskType identifies the type of Pre-Shared Key (RFC 9420 §8.4).
type PskType uint8

const (
	PskTypeExternal   PskType = 0x01 // matches OpenMLS / interop test vectors
	PskTypeResumption PskType = 0x02
	PskTypeBranch     PskType = 0x03
)

// Psk represents a Pre-Shared Key.
type Psk struct {
	PskType  PskType
	PskId    []byte // external PSK: psk_id
	PskNonce []byte
	Psk      []byte
	// Resumption PSK fields (PskType == PskTypeResumption)
	Usage      uint8
	PskGroupID []byte
	PskEpoch   uint64
}

// ComputePskInput computes psk_secret according to RFC 9420 §8.4 / OpenMLS draft-19:
//
//	psk_secret_0   = 0^Nh
//	psk_extracted  = HKDF-Extract(0^Nh, psk[i])
//	psk_input      = ExpandWithLabel(psk_extracted, "derived psk", PSKLabel[i], Nh)
//	psk_secret_i   = HKDF-Extract(psk_input[i], psk_secret_{i-1})
//	psk_secret     = psk_secret_n
func ComputePskInput(psks []Psk, cs ciphersuite.CipherSuite) ([]byte, error) {
	if len(psks) == 0 {
		return nil, fmt.Errorf("no PSKs provided")
	}
	pskSecret := ciphersuite.ZeroSecret(cs.HashLength())
	count := uint16(len(psks))
	for i, psk := range psks {
		if len(psk.Psk) == 0 {
			return nil, fmt.Errorf("empty PSK at index %d", i)
		}
		zeroSalt := ciphersuite.ZeroSecret(cs.HashLength())
		extracted, err := zeroSalt.HKDFExtract(ciphersuite.NewSecret(psk.Psk))
		if err != nil {
			return nil, fmt.Errorf("extracting PSK %d: %w", i, err)
		}
		label := PSKLabel{
			PskType:    psk.PskType,
			PskID:      psk.PskId,
			PskNonce:   psk.PskNonce,
			Index:      uint16(i),
			Count:      count,
			Usage:      psk.Usage,
			PskGroupID: psk.PskGroupID,
			PskEpoch:   psk.PskEpoch,
		}
		pskInput, err := extracted.KdfExpandLabel("derived psk", label.Marshal(), cs.HashLength())
		if err != nil {
			return nil, fmt.Errorf("expanding PSK label %d: %w", i, err)
		}
		// psk_secret_i = HKDF-Extract(psk_input_i, psk_secret_{i-1})
		pskSecret, err = pskInput.HKDFExtract(pskSecret)
		if err != nil {
			return nil, fmt.Errorf("chaining PSK secret %d: %w", i, err)
		}
	}
	return pskSecret.AsSlice(), nil
}

// PSKLabel according to RFC 9420 §8.4
//
//	struct {
//	    PreSharedKeyID id;
//	    uint16 index;
//	    uint16 count;
//	} PSKLabel;
type PSKLabel struct {
	PskType  PskType
	PskID    []byte // external: psk_id
	PskNonce []byte
	Index    uint16
	Count    uint16
	// Resumption fields (PskType == PskTypeResumption)
	Usage      uint8
	PskGroupID []byte
	PskEpoch   uint64
}

func (l PSKLabel) Marshal() []byte {
	w := tls.NewWriter()
	// PreSharedKeyID inline encoding per RFC 9420 §8.4
	w.WriteUint8(uint8(l.PskType))
	if l.PskType == PskTypeResumption {
		w.WriteUint8(l.Usage)
		w.WriteVLBytes(l.PskGroupID)
		w.WriteUint64(l.PskEpoch)
	} else {
		w.WriteVLBytes(l.PskID)
	}
	w.WriteVLBytes(l.PskNonce)
	// PSKLabel outer fields
	w.WriteUint16(l.Index)
	w.WriteUint16(l.Count)
	return w.Bytes()
}
