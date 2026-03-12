package framing

import (
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/internal/tls"
)

// marshalAuthenticatedContentTBM serializes AuthenticatedContentTBM for membership_tag (RFC §6.2).
//
// Structure:
//
//	struct {
//	    FramedContentTBS content_tbs;     // = MarshalTBS()
//	    FramedContentAuthData auth;
//	} AuthenticatedContentTBM;
func marshalAuthenticatedContentTBM(ac *AuthenticatedContent) []byte {
	w := tls.NewWriter()
	w.WriteRaw(ac.MarshalTBS()) // RFC §6.2: TBM contains FramedContentTBS, not just wire_format+content
	w.WriteRaw(ac.Auth.Marshal(ac.Content.ContentType()))
	return w.Bytes()
}

// MarshalSender serializes a Sender according to RFC §6.
func MarshalSender(s *Sender, w *tls.Writer) {
	w.WriteUint8(uint8(s.Type))
	switch s.Type {
	case SenderTypeMember:
		w.WriteUint32(s.LeafIndex)
	case SenderTypeExternal:
		w.WriteUint32(s.SenderIndex)
	}
}

// UnmarshalSender parses a Sender from a TLS reader.
func UnmarshalSender(r *tls.Reader) (*Sender, error) {
	st, err := r.ReadUint8()
	if err != nil {
		return nil, err
	}
	s := &Sender{Type: SenderType(st)}
	switch SenderType(st) {
	case SenderTypeMember:
		idx, err := r.ReadUint32()
		if err != nil {
			return nil, err
		}
		s.LeafIndex = idx
	case SenderTypeExternal:
		idx, err := r.ReadUint32()
		if err != nil {
			return nil, err
		}
		s.SenderIndex = idx
	case SenderTypeNewMemberProposal, SenderTypeNewMemberCommit:
		// No additional fields
	default:
		return nil, fmt.Errorf("%w: %d", ErrInvalidSenderType, st)
	}
	return s, nil
}

// UnmarshalSenderData parses bytes into an MLSSenderData.
func UnmarshalSenderData(data []byte) (*MLSSenderData, error) {
	r := tls.NewReader(data)
	leafIndex, err := r.ReadUint32()
	if err != nil {
		return nil, fmt.Errorf("framing: reading leaf_index: %w", err)
	}
	generation, err := r.ReadUint32()
	if err != nil {
		return nil, fmt.Errorf("framing: reading generation: %w", err)
	}
	guard, err := r.ReadBytes(ciphersuite.ReuseGuardBytes)
	if err != nil {
		return nil, fmt.Errorf("framing: reading reuse_guard: %w", err)
	}
	sd := &MLSSenderData{LeafIndex: leafIndex, Generation: generation}
	copy(sd.ReuseGuard[:], guard)
	return sd, nil
}
