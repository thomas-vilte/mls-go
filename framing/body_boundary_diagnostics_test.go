//go:build diagnostics

package framing

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/thomas-vilte/mls-go/internal/tls"
)

// Additional diagnostics for the body boundary of unauthenticated messages.

// TestDecoderCalledOnceOnGarbageBody checks that, with a decoder registered, a garbage body of N bytes causes
// a single decoder call with the whole remainder.
func TestDecoderCalledOnceOnGarbageBody(t *testing.T) {
	calls, total := 0, 0
	dec := func(data []byte) (int, error) {
		calls++
		total += len(data)
		return 0, errors.New("test: no body")
	}
	data := bytes.Repeat([]byte{0x01}, 4096)
	r := tls.NewReader(data)
	if _, err := readRawBody(r, dec, ContentTypeCommit, false, true); err == nil {
		t.Fatalf("readRawBody accepted garbage")
	}
	if calls != 1 || total != len(data) {
		t.Errorf("decoder calls=%d bytes=%d, want 1 call over %d bytes", calls, total, len(data))
	}
}

// TestDecoderBodyFollowedByValidatedTail checks that the body is what the decoder consumes and that the rest
// must validate as an auth tail. An invalid tail fails without looking for another boundary.
func TestDecoderBodyFollowedByValidatedTail(t *testing.T) {
	dec := func(data []byte) (int, error) {
		if len(data) < 3 {
			return 0, errors.New("short")
		}
		return 3, nil
	}
	good := []byte{0xA0, 0xA1, 0xA2, 0x01, 0x55}
	body, err := readRawBody(tls.NewReader(good), dec, ContentTypeProposal, false, true)
	if err != nil || !bytes.Equal(body, good[:3]) {
		t.Fatalf("valid tail: body=%x err=%v, want the first 3 bytes", body, err)
	}
	bad := []byte{0xA0, 0xA1, 0xA2, 0x01, 0x55, 0x00}
	if _, err := readRawBody(tls.NewReader(bad), dec, ContentTypeProposal, false, true); err == nil {
		t.Errorf("readRawBody accepted a body whose auth tail has one extra byte")
	}
}

// TestSkipVLBytesMatchesReadVLBytes checks that skipVLBytes fails and advances exactly like ReadVLBytes,
// including non-minimal varints, an invalid prefix, lengths larger than the buffer and empty buffers.
func TestSkipVLBytesMatchesReadVLBytes(t *testing.T) {
	inputs := [][]byte{
		{},
		{0x00},
		{0x01, 0x55},
		{0x01},
		{0x40, 0x3F},             // 63 codificado con 2 bytes: no minimo
		{0x40, 0x40, 0x00},       // 64 con 2 bytes, pero sin datos
		{0x80, 0x00, 0x00, 0x40}, // 64 con 4 bytes: no minimo
		{0xC0, 0x00, 0x00, 0x00}, // prefijo 3 invalido
		{0x7F},                   // 63 pero sin datos
	}
	for _, in := range inputs {
		r1 := tls.NewReader(in)
		_, e1 := r1.ReadVLBytes()
		r2 := tls.NewReader(in)
		e2 := skipVLBytes(r2)
		if (e1 == nil) != (e2 == nil) {
			t.Errorf("input %x: ReadVLBytes err=%v, skipVLBytes err=%v", in, e1, e2)
			continue
		}
		if e1 == nil && r1.Position() != r2.Position() {
			t.Errorf("input %x: positions differ: ReadVLBytes=%d skipVLBytes=%d", in, r1.Position(), r2.Position())
		}
	}
}

// TestLargeBodyWithoutDecoderCompletes checks that, without a decoder, the boundary search over a 1 MiB garbage
// body ends in linear time. The bound is generous: it detects quadratic regressions, it does not measure
// performance.
func TestLargeBodyWithoutDecoderCompletes(t *testing.T) {
	data := bytes.Repeat([]byte{0x00}, 1<<20)
	start := time.Now()
	_, err := readRawBody(tls.NewReader(data), nil, ContentTypeProposal, false, true)
	elapsed := time.Since(start)
	t.Logf("1 MiB zeros without decoder: err=%v elapsed=%v", err, elapsed)
	if elapsed > 10*time.Second {
		t.Errorf("scan of 1 MiB took %v", elapsed)
	}
}
