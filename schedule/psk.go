// Package schedule implements Pre-Shared Key (PSK) handling for the MLS key schedule.
//
// PSKs provide additional entropy and authentication in the key schedule per RFC 9420 §8.4.
// They are used for:
//   - External PSKs: Application-defined pre-shared keys
//   - Resumption PSKs: Prove membership in a previous epoch (RFC §8.6)
//   - Branch PSKs: Link a new group to an existing one
//
// Multiple PSKs are combined using iterated HKDF-Extract:
//
//	psk_secret_0 = 0^Nh
//	psk_secret_i = HKDF-Extract(psk_input[i], psk_secret_{i-1})
//	psk_secret   = psk_secret_n
package schedule

import (
	"errors"
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/internal/tls"
)

// PskType identifies the type of Pre-Shared Key as defined in RFC 9420 §8.4.
//
// The PSK type determines how the PSK is used and what fields are present:
//   - External: Application-defined pre-shared key
//   - Resumption: Prove membership in a previous epoch
//   - Branch: Link a new group to an existing one
//
// RFC 9420 §8.4:
//
//	enum {
//	    external(1),
//	    resumption(2),
//	    branch(3),
//	    (255)
//	} PreSharedKeyType;
type PskType uint8

const (
	// PskTypeExternal represents an externally provided PSK.
	PskTypeExternal PskType = 0x01 // matches other implementation / interop test vectors
	// PskTypeResumption represents a resumption PSK from a previous epoch.
	PskTypeResumption PskType = 0x02
	// PskTypeBranch represents a branch PSK linking a new group to an existing one (RFC 9420 §8.4).
	PskTypeBranch PskType = 0x03
)

// ResumptionPSKUsage identifies the context in which a Resumption PSK is used (RFC 9420 §11.2).
//
//	enum {
//	    application(1),
//	    reinit(2),
//	    branch(3),
//	    (255)
//	} ResumptionPSKUsage;
type ResumptionPSKUsage uint8

const (
	// ResumptionUsageApplication is used in normal epoch advancement.
	ResumptionUsageApplication ResumptionPSKUsage = 0x01
	// ResumptionUsageReinit is used when restarting a group (ReInit).
	// MUST only appear alongside a ReInit proposal in the same commit.
	ResumptionUsageReinit ResumptionPSKUsage = 0x02
	// ResumptionUsageBranch is used when branching a sub-group.
	// MUST only appear in a branching context (not in normal commits).
	ResumptionUsageBranch ResumptionPSKUsage = 0x03
)

// Psk represents a Pre-Shared Key as defined in RFC 9420 §8.4.
//
// PSKs can be:
//   - External: Application-defined pre-shared keys with psk_id and psk
//   - Resumption: Prove membership in a previous epoch (usage, group_id, epoch)
//   - Branch: Link a new group to an existing one
//
// RFC 9420 §8.4:
//
//	struct {
//	    PreSharedKeyType ktype;
//	    select (ktype) {
//	        case external:
//	            opaque psk_id<V>;
//	        case resumption:
//	            uint8 usage;
//	            opaque group_id<V>;
//	            uint64 epoch;
//	        case branch:
//	            // Same as external
//	            opaque psk_id<V>;
//	    };
//	    opaque psk_nonce<V>;
//	    opaque psk<V>;
//	} Psk;
type Psk struct {
	PskType  PskType
	PskID    []byte // external PSK: psk_id
	PskNonce []byte
	Psk      []byte
	// Resumption PSK fields (PskType == PskTypeResumption)
	Usage      uint8
	PskGroupID []byte
	PskEpoch   uint64
}

// Validate checks that the Psk fields satisfy RFC 9420 §8.4 requirements.
//
// The psk_nonce MUST be a fresh random value of length KDF.Nh (RFC §8.4).
// The psk value itself MUST be non-empty.
func (p *Psk) Validate(cs ciphersuite.CipherSuite) error {
	if len(p.Psk) == 0 {
		return errors.New("psk: psk value is empty")
	}
	if nh := cs.HashLength(); len(p.PskNonce) != nh {
		return fmt.Errorf("psk: psk_nonce must be %d bytes (KDF.Nh), got %d (RFC §8.4)", nh, len(p.PskNonce))
	}
	return nil
}

// ComputePskInput computes psk_secret according to RFC 9420 §8.4.
//
// Multiple PSKs are combined using iterated HKDF-Extract:
//
//	psk_secret_0 = 0^Nh
//	psk_extracted = HKDF-Extract(0^Nh, psk[i])
//	psk_input = ExpandWithLabel(psk_extracted, "derived psk", PSKLabel[i], Nh)
//	psk_secret_i = HKDF-Extract(psk_input[i], psk_secret_{i-1})
//	psk_secret = psk_secret_n
//
// Parameters:
//   - psks: List of PSKs to combine
//   - cs: Cipher suite for HKDF operations
//
// Returns the combined psk_secret, or an error if no PSKs are provided or any
// PSK is empty.
//
// RFC 9420 §8.4:
//
//	psk_secret = HKDF-Extract(psk_input_n, ... HKDF-Extract(psk_input_1, 0^Nh)...)
func ComputePskInput(psks []Psk, cs ciphersuite.CipherSuite) ([]byte, error) {
	if len(psks) == 0 {
		return nil, fmt.Errorf("no PSKs provided")
	}
	pskSecret := ciphersuite.ZeroSecretCS(cs)
	count := uint16(len(psks))
	for i, psk := range psks {
		if err := psk.Validate(cs); err != nil {
			return nil, fmt.Errorf("PSK at index %d: %w", i, err)
		}
		zeroSalt := ciphersuite.ZeroSecretCS(cs)
		extracted, err := zeroSalt.HKDFExtract(ciphersuite.NewSecretForCS(cs, psk.Psk))
		if err != nil {
			return nil, fmt.Errorf("extracting PSK %d: %w", i, err)
		}
		label := PSKLabel{
			PskType:    psk.PskType,
			PskID:      psk.PskID,
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
		// Chain PSK secrets per RFC 9420 §8.4:
		// psk_secret_i = HKDF-Extract(psk_input_i, psk_secret_{i-1})
		pskSecret, err = pskInput.HKDFExtract(pskSecret)
		if err != nil {
			return nil, fmt.Errorf("chaining PSK secret %d: %w", i, err)
		}
	}
	return pskSecret.AsSlice(), nil
}

// PSKLabel represents the PSKLabel structure for PSK derivation per RFC 9420 §8.4.
//
// The PSKLabel is used in ExpandWithLabel to derive psk_input from each PSK:
//
//	psk_input = ExpandWithLabel(psk_extracted, "derived psk", PSKLabel, Nh)
//
// RFC 9420 §8.4:
//
//	struct {
//	    PreSharedKeyID id;
//	    uint16 index;
//	    uint16 count;
//	} PSKLabel;
//
// where PreSharedKeyID is:
//
//	select (ktype) {
//	    case external:
//	        opaque psk_id<V>;
//	    case resumption:
//	        uint8 usage;
//	        opaque group_id<V>;
//	        uint64 epoch;
//	    case branch:
//	        opaque psk_id<V>;
//	};
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

// Marshal serializes the PSKLabel to TLS presentation language format.
//
// The serialization includes:
//   - psk_type: Type of PSK (external, resumption, branch)
//   - PSK identifier: psk_id for external/branch, or usage+group_id+epoch for resumption
//   - psk_nonce: Nonce for this PSK
//   - index: Position of this PSK in the list
//   - count: Total number of PSKs
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
