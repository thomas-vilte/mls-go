package group

import (
	"bytes"
	"fmt"

	"github.com/openmls/go/framing"
	"github.com/openmls/go/internal/tls"
)

func init() {
	framing.RegisterRawBodyDecoders(decodeProposalBodyLength, decodeCommitBodyLength)
}

func decodeProposalBodyLength(data []byte) (int, error) {
	return decodeRawBodyLength(data, unmarshalProposalRoundTrip)
}

func decodeCommitBodyLength(data []byte) (int, error) {
	return decodeRawBodyLength(data, unmarshalCommitRoundTrip)
}

func decodeRawBodyLength(data []byte, validate func([]byte) error) (int, error) {
	for i := 1; i <= len(data); i++ {
		candidate := data[:i]
		if err := validate(candidate); err == nil {
			r := tls.NewReader(data[i:])
			if _, err := r.ReadVLBytes(); err == nil {
				return i, nil
			}
		}
	}
	return 0, fmt.Errorf("unable to locate raw handshake body")
}

func unmarshalProposalRoundTrip(data []byte) error {
	p, err := UnmarshalProposal(data)
	if err != nil {
		return err
	}
	if !bytes.Equal(ProposalMarshal(p), data) {
		return fmt.Errorf("proposal roundtrip mismatch")
	}
	return nil
}

func unmarshalCommitRoundTrip(data []byte) error {
	c, err := UnmarshalCommit(data)
	if err != nil {
		return err
	}
	if !bytes.Equal(c.Marshal(), data) {
		return fmt.Errorf("commit roundtrip mismatch")
	}
	return nil
}
