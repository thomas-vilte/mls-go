package group

import "fmt"

// PSKStore es una interfaz para resolver Pre-Shared Keys (RFC 9420 §8.4).
// Las aplicaciones implementan esta interfaz para proveer PSKs externos.
type PSKStore interface {
	// GetPSK retorna el PSK para el ID dado
	// Debe retornar error si el PSK no existe o no puede ser accedido
	GetPSK(pskID []byte) ([]byte, error)
}

// PSKResolver implementa la lógica de resolución de PSKs desde proposals.
type PSKResolver struct {
	store PSKStore
}

// NewPSKResolver crea un nuevo resolver con el store dado.
func NewPSKResolver(store PSKStore) *PSKResolver {
	return &PSKResolver{store: store}
}

// ResolvePSK resuelve un PSK desde un PskID.
// Soporta External PSKs (tipo 1) y Resumption PSKs (tipo 2).
func (r *PSKResolver) ResolvePSK(pskID *PskID) ([]byte, error) {
	if pskID == nil {
		return nil, fmt.Errorf("psk_id is nil")
	}

	switch pskID.PskType {
	case 1: // External PSK
		return r.store.GetPSK(pskID.ID)
	case 2: // Resumption PSK - usar compound key (group_id, epoch)
		resumptionKey := append(pskID.PskGroupID, make([]byte, 8)...)
		// Convertir epoch a bytes big-endian
		for i := 7; i >= 0; i-- {
			resumptionKey[len(resumptionKey)-8+i] = byte(pskID.PskEpoch >> (8 * (7 - i)))
		}
		return r.store.GetPSK(resumptionKey)
	case 3: // Branch PSK
		return r.store.GetPSK(pskID.ID)
	default:
		return nil, fmt.Errorf("unsupported PSK type: %d", pskID.PskType)
	}
}
