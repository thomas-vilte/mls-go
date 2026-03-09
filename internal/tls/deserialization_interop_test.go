package tls

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

type deserializationVector struct {
	VLBytesHeader string `json:"vlbytes_header"`
	Length        uint32 `json:"length"`
}

func TestDeserializationVectors(t *testing.T) {
	data, err := os.ReadFile("../../testdata/mls-interop-testvectors/test-vectors/deserialization.json")
	if err != nil {
		t.Skipf("deserialization.json not found: %v", err)
	}

	var vectors []deserializationVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse deserialization.json: %v", err)
	}

	for _, v := range vectors {
		v := v
		t.Run(fmt.Sprintf("len_%d_header_%s", v.Length, v.VLBytesHeader), func(t *testing.T) {
			header, err := hex.DecodeString(v.VLBytesHeader)
			if err != nil {
				t.Fatalf("decode header hex: %v", err)
			}

			r := NewReader(header)
			gotLen, err := r.ReadMLSVarint()
			if err != nil {
				t.Fatalf("ReadMLSVarint: %v", err)
			}
			if gotLen != v.Length {
				t.Fatalf("ReadMLSVarint length = %d, want %d", gotLen, v.Length)
			}
			if r.Remaining() != 0 {
				t.Fatalf("ReadMLSVarint remaining = %d, want 0", r.Remaining())
			}

			w := NewWriter()
			w.WriteMLSVarint(v.Length)
			if !bytes.Equal(w.Bytes(), header) {
				t.Fatalf("WriteMLSVarint header = %x, want %x", w.Bytes(), header)
			}

			const maxInlinePayload = 16383

			if v.Length <= maxInlinePayload {
				payload := bytes.Repeat([]byte{0xA5}, int(v.Length))
				wire := make([]byte, 0, len(header)+len(payload))
				wire = append(wire, header...)
				wire = append(wire, payload...)

				r2 := NewReader(wire)
				got, err := r2.ReadVLBytes()
				if err != nil {
					t.Fatalf("ReadVLBytes: %v", err)
				}
				if uint32(len(got)) != v.Length {
					t.Fatalf("ReadVLBytes length = %d, want %d", len(got), v.Length)
				}
				if !bytes.Equal(got, payload) {
					t.Fatal("ReadVLBytes payload mismatch")
				}
				if r2.Remaining() != 0 {
					t.Fatalf("ReadVLBytes remaining = %d, want 0", r2.Remaining())
				}
				return
			}

			r2 := NewReader(header)
			_, err = r2.ReadVLBytes()
			if err == nil {
				t.Fatalf("ReadVLBytes expected buffer underrun for len=%d", v.Length)
			}
			if !strings.Contains(err.Error(), "buffer underrun") {
				t.Fatalf("ReadVLBytes error = %q, want buffer underrun", err.Error())
			}
		})
	}
}
