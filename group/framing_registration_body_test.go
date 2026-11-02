package group

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/internal/tls"
)

// TestRegisteredDecodersFindBodyBoundary checks the body boundary of unauthenticated messages through the
// decoders that this package registers in framing_registration.go.
func TestRegisteredDecodersFindBodyBoundary(t *testing.T) {
	t.Cleanup(func() {
		framing.RegisterRawBodyDecoders(decodeProposalBodyLength, decodeCommitBodyLength)
	})

	t.Run("InvalidCommitBodyBoundedCalls", func(t *testing.T) {
		for _, n := range []int{256, 1024, 4096} {
			calls, decoded := 0, 0
			framing.RegisterRawBodyDecoders(
				countingBodyDecoder(decodeProposalBodyLength, &calls, &decoded),
				countingBodyDecoder(decodeCommitBodyLength, &calls, &decoded),
			)
			junk := bytes.Repeat([]byte{0xFF}, n) // 0xFF is an invalid MLS varint prefix
			if _, err := framing.UnmarshalPublicMessage(commitPublicMessageWithoutTail(junk)); err == nil {
				t.Fatalf("n=%d: expected an error for an invalid commit body", n)
			}
			if calls > 2 || decoded > 2*n {
				t.Errorf("n=%d: decoder calls=%d bytes=%d, want at most 2 calls and %d bytes", n, calls, decoded, 2*n)
			}
		}
	})

	t.Run("ValidCommitVectorsDecodeOnce", func(t *testing.T) {
		// Control: every valid message of the passive-client commit vectors must
		// still decode with a single decoder call and a body that re-parses exactly.
		data, err := os.ReadFile("../testdata/mls-interop-testvectors/test-vectors/passive-client-handling-commit.json")
		if err != nil {
			t.Fatalf("reading vectors: %v", err)
		}
		var vecs []passiveClientCommitVector
		if err := json.Unmarshal(data, &vecs); err != nil {
			t.Fatalf("parsing vectors: %v", err)
		}

		calls, decoded := 0, 0
		framing.RegisterRawBodyDecoders(
			countingBodyDecoder(decodeProposalBodyLength, &calls, &decoded),
			countingBodyDecoder(decodeCommitBodyLength, &calls, &decoded),
		)

		checked := 0
		for vi := range vecs {
			// Same filter as TestPassiveClientHandlingCommitVectors: unsupported
			// cipher suites are not exercised by this implementation.
			if !ciphersuite.CipherSuite(vecs[vi].CipherSuite).IsSupported() {
				continue
			}
			for _, epoch := range vecs[vi].Epochs {
				messages := append(append([]string{}, epoch.Proposals...), epoch.Commit)
				for _, h := range messages {
					raw := mustDecodeHex(t, h)
					calls = 0
					msg, err := framing.UnmarshalMLSMessage(raw)
					if err != nil {
						t.Fatalf("vector %d: UnmarshalMLSMessage: %v", vi, err)
					}
					if calls != 1 {
						t.Fatalf("vector %d: valid message decoded with %d decoder calls, want 1", vi, calls)
					}
					if msg.PublicMessage == nil {
						t.Fatalf("vector %d: expected a PublicMessage, got wire_format=%d", vi, msg.WireFormat())
					}
					switch body := msg.PublicMessage.Content.Body.(type) {
					case framing.CommitBody:
						if _, err := UnmarshalCommit(body.Data); err != nil {
							t.Fatalf("vector %d: commit body does not re-parse exactly: %v", vi, err)
						}
					case framing.ProposalBody:
						if _, err := UnmarshalProposal(body.Data); err != nil {
							t.Fatalf("vector %d: proposal body does not re-parse: %v", vi, err)
						}
					default:
						t.Fatalf("vector %d: unexpected body type %T", vi, body)
					}
					checked++
				}
			}
		}
		if checked == 0 {
			t.Fatal("no vector messages were checked")
		}
	})
}

// countingBodyDecoder wraps a raw body decoder and records its calls and input bytes.
func countingBodyDecoder(next func([]byte) (int, error), calls, decoded *int) func([]byte) (int, error) {
	return func(data []byte) (int, error) {
		*calls++
		*decoded += len(data)
		return next(data)
	}
}

// commitPublicMessageWithoutTail wraps body in a PublicMessage header for a commit sent by
// member leaf 0. No auth tail follows body, so the body boundary has to be found
// from the bytes after the header alone.
func commitPublicMessageWithoutTail(body []byte) []byte {
	w := tls.NewWriter()
	w.WriteUint16(uint16(framing.WireFormatPublicMessage))
	w.WriteVLBytes([]byte("boundary-group")) // group_id
	w.WriteUint64(1)                         // epoch
	w.WriteUint8(uint8(framing.SenderTypeMember))
	w.WriteUint32(0)    // leaf_index
	w.WriteVLBytes(nil) // authenticated_data
	w.WriteUint8(uint8(framing.ContentTypeCommit))
	w.WriteRaw(body)
	return w.Bytes()
}
