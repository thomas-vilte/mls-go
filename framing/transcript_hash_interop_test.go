package framing_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/mls-go/ciphersuite"
	"github.com/mls-go/framing"
)

type transcriptHashVector struct {
	CipherSuite                  uint16 `json:"cipher_suite"`
	ConfirmationKey              string `json:"confirmation_key"`
	AuthenticatedContent         string `json:"authenticated_content"`
	InterimTranscriptHashBefore  string `json:"interim_transcript_hash_before"`
	ConfirmedTranscriptHashAfter string `json:"confirmed_transcript_hash_after"`
	InterimTranscriptHashAfter   string `json:"interim_transcript_hash_after"`
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

// parseConfirmedTHInput splits a raw AuthenticatedContent wire encoding into:
//   - cthInput: the ConfirmedTranscriptHashInput bytes (WireFormat + FramedContent + signature)
//   - confirmationTag: the confirmation_tag bytes (or nil if not present)
//
// RFC 9420 §6.1 wire format (PublicMessage):
//
//	WireFormat(2) | FramedContent(variable, inline Commit body) | signature<V> | confirmation_tag<V>?
func parseConfirmedTHInput(ac []byte) (cthInput, confirmationTag []byte, err error) {
	pos := 0
	rd := func(n int) []byte {
		if pos+n > len(ac) {
			panic("short read")
		}
		b := ac[pos : pos+n]
		pos += n
		return b
	}
	readVLLen := func() int {
		b := ac[pos]
		if b&0xC0 == 0 {
			pos++
			return int(b)
		} else if b&0xC0 == 0x40 {
			n := (int(b&0x3F) << 8) | int(ac[pos+1])
			pos += 2
			return n
		}
		panic("unsupported 4-byte varint")
	}
	readVL := func() []byte {
		n := readVLLen()
		return rd(n)
	}

	// WireFormat
	rd(2)

	// FramedContent: group_id<V> | epoch(8) | sender | auth_data<V> | content_type | body
	readVL() // group_id
	rd(8)    // epoch
	st := ac[pos]
	pos++ // sender_type
	if st == 1 || st == 2 {
		rd(4) // leaf_index / sender_index
	}
	readVL() // authenticated_data

	ct := ac[pos]
	pos++ // content_type

	// body: RFC §6.1 — inline (raw) for Commit/Proposal, VL-wrapped for Application
	switch ct {
	case 1: // application
		readVL()
	case 2: // proposal (inline Proposal struct — VL group of bytes starting with type)
		// read Proposal type (uint16) + variable data; safest: read all VL-wrapped content
		// In the test vectors, proposal body is raw so we skip by reading the remaining content
		// For simplicity in the vector format, read until the signature VLBytes
		// Actually proposal body is inline: just read 2 bytes (type) + body depends on type
		// Simplification: find sig by brute-force is unreliable; use VL as in vector
		readVL()
	case 3: // commit: inline Commit = proposals<V> + path?
		readVL() // proposals vector (VL-encoded inner vector)
		pathPresent := ac[pos]
		pos++
		if pathPresent == 1 {
			readVL() // path
		}
	}

	frCEnd := pos

	// signature<V>
	sigStart := pos
	readVL()
	sigEnd := pos

	cthInput = ac[0:sigEnd]
	_ = frCEnd
	_ = sigStart

	// confirmation_tag<V> (only for commit)
	if ct == 3 && pos < len(ac) {
		confirmationTag = readVL()
	}

	return cthInput, confirmationTag, nil
}

func TestTranscriptHashVectors(t *testing.T) {
	data, err := os.ReadFile("../testdata/mls-interop-testvectors/test-vectors/transcript-hashes.json")
	if err != nil {
		t.Skipf("transcript-hashes.json not found: %v", err)
	}

	var vectors []transcriptHashVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse transcript-hashes.json: %v", err)
	}

	for i, v := range vectors {
		cs := ciphersuite.CipherSuite(v.CipherSuite)
		if !cs.IsSupported() {
			continue
		}

		t.Run(fmt.Sprintf("cs%d-v%d", v.CipherSuite, i), func(t *testing.T) {
			acBytes := mustHexDecode(t, v.AuthenticatedContent)
			interimBefore := mustHexDecode(t, v.InterimTranscriptHashBefore)
			expectedConfirmed := mustHexDecode(t, v.ConfirmedTranscriptHashAfter)
			expectedInterimAfter := mustHexDecode(t, v.InterimTranscriptHashAfter)

			cthInput, confirmationTag, err := parseConfirmedTHInput(acBytes)
			if err != nil {
				t.Fatalf("parseConfirmedTHInput: %v", err)
			}

			// confirmed_transcript_hash_after = Hash(interim_before || ConfirmedTranscriptHashInput)
			cthi := &framing.ConfirmedTranscriptHashInput{
				RawInput: cthInput,
			}
			confirmed := cthi.ComputeRaw(cs, interimBefore)
			if !bytes.Equal(confirmed, expectedConfirmed) {
				t.Errorf("confirmed_transcript_hash_after mismatch\n  got  %x\n  want %x", confirmed, expectedConfirmed)
			}

			// interim_transcript_hash_after = Hash(confirmed || VL(confirmation_tag))
			ithi := &framing.InterimTranscriptHashInput{ConfirmationTag: confirmationTag}
			interimAfter := ithi.Compute(cs, confirmed)
			if !bytes.Equal(interimAfter, expectedInterimAfter) {
				t.Errorf("interim_transcript_hash_after mismatch\n  got  %x\n  want %x", interimAfter, expectedInterimAfter)
			}
		})
	}
}
