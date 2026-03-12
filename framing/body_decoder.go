package framing

import (
	"fmt"

	"github.com/thomas-vilte/mls-go/internal/tls"
)

type rawBodyDecoder func(data []byte) (consumed int, err error)

var (
	proposalBodyDecoder rawBodyDecoder
	commitBodyDecoder   rawBodyDecoder
)

// RegisterRawBodyDecoders registers decoders for raw handshake bodies.
func RegisterRawBodyDecoders(proposalDecoder, commitDecoder rawBodyDecoder) {
	proposalBodyDecoder = proposalDecoder
	commitBodyDecoder = commitDecoder
}

func readFramedContentBody(r *tls.Reader, ct ContentType, hasMembershipTag, expectsTrailingAuth bool) (FramedContentBody, error) {
	switch ct {
	case ContentTypeApplication:
		bodyData, err := r.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("framing: reading body: %w", err)
		}
		return ApplicationData{Data: bodyData}, nil
	case ContentTypeProposal:
		bodyData, err := readRawBody(r, proposalBodyDecoder, ct, hasMembershipTag, expectsTrailingAuth)
		if err != nil {
			return nil, fmt.Errorf("framing: reading proposal body: %w", err)
		}
		return ProposalBody{Data: bodyData}, nil
	case ContentTypeCommit:
		bodyData, err := readRawBody(r, commitBodyDecoder, ct, hasMembershipTag, expectsTrailingAuth)
		if err != nil {
			return nil, fmt.Errorf("framing: reading commit body: %w", err)
		}
		return CommitBody{Data: bodyData}, nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrInvalidContentType, ct)
	}
}

func readRawBody(r *tls.Reader, decoder rawBodyDecoder, ct ContentType, hasMembershipTag, expectsTrailingAuth bool) ([]byte, error) {
	remaining := r.BytesAfterPosition()
	if len(remaining) == 0 {
		return nil, fmt.Errorf("empty raw body")
	}
	if !expectsTrailingAuth {
		bodyData := make([]byte, len(remaining))
		copy(bodyData, remaining)
		r.Skip(len(remaining))
		return bodyData, nil
	}

	// Try deterministic decoder on the full remaining bytes first.
	// The byte-by-byte scanner below passes truncated slices to the decoder,
	// which can fail for complex bodies (e.g., commits with UpdatePath) that
	// need to see the full data to parse correctly.
	if decoder != nil {
		consumed, err := decoder(remaining)
		if err == nil && consumed > 0 && consumed <= len(remaining) {
			if validAuthTail(remaining[consumed:], ct, hasMembershipTag) {
				bodyData := make([]byte, consumed)
				copy(bodyData, remaining[:consumed])
				r.Skip(consumed)
				return bodyData, nil
			}
		}
	}

	// Fall back to byte-by-byte scanner for cases without a deterministic decoder.
	for i := 1; i <= len(remaining); i++ {
		candidate := remaining[:i]
		if decoder != nil {
			consumed, err := decoder(candidate)
			if err != nil || consumed != len(candidate) {
				continue
			}
		}
		if !validAuthTail(remaining[i:], ct, hasMembershipTag) {
			continue
		}

		bodyData := make([]byte, i)
		copy(bodyData, candidate)
		r.Skip(i)
		return bodyData, nil
	}

	return nil, fmt.Errorf("unable to locate raw handshake body")
}

func validAuthTail(tail []byte, ct ContentType, hasMembershipTag bool) bool {
	base := tls.NewReader(tail)
	if _, err := base.ReadVLBytes(); err != nil {
		return false
	}

	if ct != ContentTypeCommit {
		if hasMembershipTag {
			if _, err := base.ReadVLBytes(); err != nil {
				return false
			}
		}
		return base.Remaining() == 0
	}

	// Commit auth tail can be either:
	//   signature || confirmation_tag || [membership_tag]
	// or
	//   signature || [membership_tag]
	// Try both layouts.
	tryWithConfirmation := func() bool {
		r := tls.NewReader(tail)
		if _, err := r.ReadVLBytes(); err != nil {
			return false
		}
		if _, err := r.ReadVLBytes(); err != nil {
			return false
		}
		if hasMembershipTag {
			if _, err := r.ReadVLBytes(); err != nil {
				return false
			}
		}
		return r.Remaining() == 0
	}

	tryWithoutConfirmation := func() bool {
		r := tls.NewReader(tail)
		if _, err := r.ReadVLBytes(); err != nil {
			return false
		}
		if hasMembershipTag {
			if _, err := r.ReadVLBytes(); err != nil {
				return false
			}
		}
		return r.Remaining() == 0
	}

	return tryWithConfirmation() || tryWithoutConfirmation()
}
