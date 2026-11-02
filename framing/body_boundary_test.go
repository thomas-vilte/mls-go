package framing

import (
	"bytes"
	"errors"
	"runtime"
	"testing"

	"github.com/thomas-vilte/mls-go/internal/tls"
)

// TestReadRawBodyWorkIsLinear checks that locating a raw handshake body before its auth tail is checked costs
// linear work. With a decoder registered, invalid bytes cost one decoder call instead of one per prefix, and
// without a decoder the tail check does not copy every VL field it visits.
func TestReadRawBodyWorkIsLinear(t *testing.T) {
	t.Run("InvalidBodyDecoderCallsLinear", func(t *testing.T) {
		for _, n := range []int{256, 1024, 4096} {
			calls, decoded := 0, 0
			rejectAll := func(data []byte) (int, error) {
				calls++
				decoded += len(data)
				return 0, errors.New("test: invalid body")
			}
			// 0xFF is an invalid MLS varint prefix, so no prefix is a valid body.
			input := bytes.Repeat([]byte{0xFF}, n)
			if _, err := readRawBody(tls.NewReader(input), rejectAll, ContentTypeCommit, true, true); err == nil {
				t.Fatalf("n=%d: expected an error for an invalid body", n)
			}
			if calls > 2 {
				t.Errorf("n=%d: decoder called %d times, want at most 2 (prefixes must not be re-decoded)", n, calls)
			}
			if decoded > 2*n {
				t.Errorf("n=%d: decoder was given %d bytes, want at most %d (linear in input size)", n, decoded, 2*n)
			}
		}
	})

	t.Run("ValidBodyDecodedWithOneCall", func(t *testing.T) {
		// Control: a valid body followed by a valid signature-only tail.
		bodyWriter := tls.NewWriter()
		bodyWriter.WriteVLBytes([]byte("commit-body"))
		body := bodyWriter.Bytes()

		tailWriter := tls.NewWriter()
		tailWriter.WriteVLBytes([]byte{0x01, 0x02}) // signature
		tail := tailWriter.Bytes()

		input := append(append([]byte{}, body...), tail...)

		calls := 0
		vlDecoder := func(data []byte) (int, error) {
			calls++
			r := tls.NewReader(data)
			if _, err := r.ReadVLBytes(); err != nil {
				return 0, err
			}
			return r.Position(), nil
		}

		r := tls.NewReader(input)
		got, err := readRawBody(r, vlDecoder, ContentTypeCommit, false, true)
		if err != nil {
			t.Fatalf("readRawBody(valid body): %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Errorf("body = %x, want %x", got, body)
		}
		if calls != 1 {
			t.Errorf("decoder called %d times for a valid body, want 1", calls)
		}
		if r.Remaining() != len(tail) {
			t.Errorf("reader left %d bytes, want %d (the auth tail)", r.Remaining(), len(tail))
		}
	})

	t.Run("NoDecoderTailScanIsLinear", func(t *testing.T) {
		// Without a decoder, the tail check runs at every offset. Linear work
		// roughly doubles the allocations when the input doubles; the copying
		// tail check that the fix replaces grows much faster.
		small := tailScanAllocs(t, 20000)
		large := tailScanAllocs(t, 40000)
		if large > 3*small {
			t.Errorf("tail scan allocated %d bytes for 40000 input bytes and %d for 20000: growth is not linear", large, small)
		}
	})
}

// tailScanAllocs returns the bytes allocated by readRawBody without a decoder
// on the crafted n-byte input, which must not contain a valid body boundary.
func tailScanAllocs(t *testing.T, n int) uint64 {
	t.Helper()
	input := tailScanInput(n)

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := readRawBody(tls.NewReader(input), nil, ContentTypeCommit, true, true)
	runtime.ReadMemStats(&after)

	if err == nil {
		t.Fatalf("n=%d: expected no body boundary in the crafted input", n)
	}
	return after.TotalAlloc - before.TotalAlloc
}

// tailScanInput returns n bytes in which every 4-byte aligned offset far
// enough from the end holds a 4-byte MLS varint header (>= 16384) declaring a
// VL field that covers almost the rest of the input. Each header is a candidate
// boundary whose tail check copies the declared field. The final byte is left
// as 0xFF, so no candidate completes a valid auth tail.
func tailScanInput(n int) []byte {
	buf := bytes.Repeat([]byte{0xFF}, n)
	for p := 0; p+16389 <= n; p += 4 {
		v := n - p - 5 // minimal 4-byte varint that leaves only the final 0xFF unread
		buf[p] = 0x80 | byte(v>>24)
		buf[p+1] = byte(v >> 16)
		buf[p+2] = byte(v >> 8)
		buf[p+3] = byte(v)
	}
	return buf
}
