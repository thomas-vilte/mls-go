package group

import (
	"fmt"

	"github.com/thomas-vilte/mls-go/schedule"
)

// PSKStore is an interface for resolving Pre-Shared Keys per RFC 9420 §8.4.
// Applications implement this interface to provide external PSKs.
type PSKStore interface {
	// GetPSK returns the PSK for the given ID.
	// Must return an error if the PSK does not exist or cannot be accessed.
	GetPSK(pskID []byte) ([]byte, error)
}

// PSKResolver implements PSK resolution logic from proposals.
type PSKResolver struct {
	store PSKStore
}

// NewPSKResolver creates a new resolver with the given store.
func NewPSKResolver(store PSKStore) *PSKResolver {
	return &PSKResolver{store: store}
}

// ResolvePSK resolves a PSK from a PskID.
// Supports External PSKs (type 1) and Resumption PSKs (type 2).
func (r *PSKResolver) ResolvePSK(pskID *PskID) ([]byte, error) {
	if pskID == nil {
		return nil, fmt.Errorf("psk_id is nil")
	}

	switch schedule.PskType(pskID.PskType) {
	case schedule.PskTypeExternal:
		return r.store.GetPSK(pskID.ID)
	case schedule.PskTypeResumption:
		resumptionKey := make([]byte, len(pskID.PskGroupID)+8)
		copy(resumptionKey, pskID.PskGroupID)
		for i := 0; i < 8; i++ {
			resumptionKey[len(pskID.PskGroupID)+i] = byte(pskID.PskEpoch >> (8 * (7 - i)))
		}
		return r.store.GetPSK(resumptionKey)
	case schedule.PskTypeBranch:
		return r.store.GetPSK(pskID.ID)
	default:
		return nil, fmt.Errorf("unsupported PSK type: %d", pskID.PskType)
	}
}
