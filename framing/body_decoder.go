package framing

import (
	"fmt"

	"github.com/openmls/go/internal/tls"
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

func readFramedContentBody(r *tls.Reader, ct ContentType, hasMembershipTag bool, expectsTrailingAuth bool) (FramedContentBody, error) {
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

func readRawBody(
	r *tls.Reader,
	decoder rawBodyDecoder,
	ct ContentType,
	hasMembershipTag bool,
	expectsTrailingAuth bool,
) ([]byte, error) {
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
	r := tls.NewReader(tail)
	if _, err := r.ReadVLBytes(); err != nil {
		return false
	}
	if ct == ContentTypeCommit && r.Remaining() > 0 {
		if _, err := r.ReadVLBytes(); err != nil {
			return false
		}
	}
	if hasMembershipTag {
		if _, err := r.ReadVLBytes(); err != nil {
			return false
		}
	}
	return r.Remaining() == 0
}
