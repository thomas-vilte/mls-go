package group

import (
	"github.com/mls-go/framing"
	"github.com/mls-go/internal/tls"
)

func init() {
	framing.RegisterRawBodyDecoders(decodeProposalBodyLength, decodeCommitBodyLength)
}

func decodeProposalBodyLength(data []byte) (int, error) {
	r := tls.NewReader(data)
	if err := unmarshalProposalFromReader(r); err != nil {
		return 0, err
	}
	return r.Position(), nil
}

// decodeCommitBodyLength returns the exact number of bytes in data that form
// a valid Commit body (proposals<V> + optional inline UpdatePath).
// This is O(body_length) deterministic — no byte-by-byte scanning needed.
func decodeCommitBodyLength(data []byte) (int, error) {
	r := tls.NewReader(data)
	_, err := unmarshalCommitFromReader(r)
	if err != nil {
		return 0, err
	}
	return r.Position(), nil
}
