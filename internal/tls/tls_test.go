// Package tls - Tests exhaustivos para encoding/decoding TLS
//
// Objetivo: Encontrar TODOS los bugs en parsing/serialización
// Cobertura: 80%+ del paquete internal/tls
package tls

import (
	"bytes"
	"fmt"
	"math"
	"testing"
)

// ============================================================================
// Writer Tests
// ============================================================================

func TestWriter_WriteUint8(t *testing.T) {
	tests := []struct {
		name   string
		input  uint8
		expect []byte
	}{
		{"zero", 0, []byte{0x00}},
		{"max", 255, []byte{0xFF}},
		{"typical", 42, []byte{0x2A}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewWriter()
			w.WriteUint8(tt.input)
			if !bytes.Equal(w.Bytes(), tt.expect) {
				t.Errorf("WriteUint8(%d) = %x, want %x", tt.input, w.Bytes(), tt.expect)
			}
		})
	}
}

func TestWriter_WriteUint16(t *testing.T) {
	tests := []struct {
		name   string
		input  uint16
		expect []byte
	}{
		{"zero", 0, []byte{0x00, 0x00}},
		{"max", 65535, []byte{0xFF, 0xFF}},
		{"typical", 0x1234, []byte{0x12, 0x34}},
		{"boundary_64", 64, []byte{0x00, 0x40}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewWriter()
			w.WriteUint16(tt.input)
			if !bytes.Equal(w.Bytes(), tt.expect) {
				t.Errorf("WriteUint16(%d) = %x, want %x", tt.input, w.Bytes(), tt.expect)
			}
		})
	}
}

func TestWriter_WriteUint32(t *testing.T) {
	tests := []struct {
		name   string
		input  uint32
		expect []byte
	}{
		{"zero", 0, []byte{0x00, 0x00, 0x00, 0x00}},
		{"max", 4294967295, []byte{0xFF, 0xFF, 0xFF, 0xFF}},
		{"typical", 0x12345678, []byte{0x12, 0x34, 0x56, 0x78}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewWriter()
			w.WriteUint32(tt.input)
			if !bytes.Equal(w.Bytes(), tt.expect) {
				t.Errorf("WriteUint32(%d) = %x, want %x", tt.input, w.Bytes(), tt.expect)
			}
		})
	}
}

func TestWriter_WriteUint64(t *testing.T) {
	tests := []struct {
		name   string
		input  uint64
		expect []byte
	}{
		{"zero", 0, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"max", math.MaxUint64, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		{"typical", 0x123456789ABCDEF0, []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewWriter()
			w.WriteUint64(tt.input)
			if !bytes.Equal(w.Bytes(), tt.expect) {
				t.Errorf("WriteUint64(%d) = %x, want %x", tt.input, w.Bytes(), tt.expect)
			}
		})
	}
}

// ============================================================================
// MLS Varint Tests - CRÍTICO
// ============================================================================

func TestWriter_WriteMLSVarint(t *testing.T) {
	tests := []struct {
		name   string
		input  uint32
		expect []byte
	}{
		// 1-byte encoding (0-63)
		{"1byte_zero", 0, []byte{0x00}},
		{"1byte_one", 1, []byte{0x01}},
		{"1byte_63", 63, []byte{0x3F}},

		// 2-byte encoding (64-16383)
		{"2byte_64", 64, []byte{0x40, 0x40}},
		{"2byte_65", 65, []byte{0x40, 0x41}},
		{"2byte_16383", 16383, []byte{0x7F, 0xFF}},

		// 4-byte encoding (16384-1073741823)
		{"4byte_16384", 16384, []byte{0x80, 0x00, 0x40, 0x00}},
		{"4byte_16385", 16385, []byte{0x80, 0x00, 0x40, 0x01}},
		{"4byte_max", 1073741823, []byte{0xBF, 0xFF, 0xFF, 0xFF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewWriter()
			w.WriteMLSVarint(tt.input)
			if !bytes.Equal(w.Bytes(), tt.expect) {
				t.Errorf("WriteMLSVarint(%d) = %x, want %x", tt.input, w.Bytes(), tt.expect)
			}
		})
	}
}

func TestReader_ReadMLSVarint(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect uint32
		err    bool
	}{
		// 1-byte encoding
		{"1byte_zero", []byte{0x00}, 0, false},
		{"1byte_63", []byte{0x3F}, 63, false},

		// 2-byte encoding
		{"2byte_64", []byte{0x40, 0x40}, 64, false},
		{"2byte_16383", []byte{0x7F, 0xFF}, 16383, false},

		// 4-byte encoding
		{"4byte_16384", []byte{0x80, 0x00, 0x40, 0x00}, 16384, false},
		{"4byte_max", []byte{0xBF, 0xFF, 0xFF, 0xFF}, 1073741823, false},

		// Invalid prefix (11 = 3)
		{"invalid_prefix", []byte{0xC0, 0x00, 0x00, 0x00}, 0, true},

		// Buffer underrun
		{"underrun_2byte", []byte{0x40}, 0, true},
		{"underrun_4byte", []byte{0x80, 0x00}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReader(tt.input)
			got, err := r.ReadMLSVarint()
			if (err != nil) != tt.err {
				t.Fatalf("ReadMLSVarint() err = %v, want err = %v", err, tt.err)
			}
			if got != tt.expect {
				t.Errorf("ReadMLSVarint() = %d, want %d", got, tt.expect)
			}
		})
	}
}

func TestMLSVarint_Roundtrip(t *testing.T) {
	// Test TODOS los valores en los boundaries
	testValues := []uint32{
		0, 1, 63, 64, 65, 16383, 16384, 16385,
		100000, 1000000, 10000000, 1073741823,
	}

	for _, v := range testValues {
		t.Run(fmtUint32(v), func(t *testing.T) {
			w := NewWriter()
			w.WriteMLSVarint(v)

			r := NewReader(w.Bytes())
			got, err := r.ReadMLSVarint()
			if err != nil {
				t.Fatalf("Roundtrip failed: %v", err)
			}
			if got != v {
				t.Errorf("Roundtrip failed: wrote %d, read %d", v, got)
			}
		})
	}
}

func TestMLSVarint_InvalidPrefix(t *testing.T) {
	// El prefix 0b11 (3) es INVÁLIDO según RFC 9420 §3.5
	invalid := []byte{0xC0, 0x00, 0x00, 0x00} // prefix = 3
	r := NewReader(invalid)
	_, err := r.ReadMLSVarint()
	if err == nil {
		t.Fatal("Expected error for invalid prefix 0b11, got nil")
	}
}

// ============================================================================
// Variable-Length Bytes Tests
// ============================================================================

func TestWriter_ReadVLBytes(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect []byte
		err    bool
	}{
		{"empty", []byte{0x00}, []byte{}, false},
		{"1_byte", []byte{0x01, 0x42}, []byte{0x42}, false},
		{"typical", []byte{0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F}, []byte("Hello"), false},

		// Buffer underrun
		{"underrun", []byte{0x05, 0x48, 0x65}, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReader(tt.input)
			got, err := r.ReadVLBytes()
			if (err != nil) != tt.err {
				t.Fatalf("ReadVLBytes() err = %v, want err = %v", err, tt.err)
			}
			if !bytes.Equal(got, tt.expect) {
				t.Errorf("ReadVLBytes() = %x, want %x", got, tt.expect)
			}
		})
	}
}

func TestVLBytes_Roundtrip(t *testing.T) {
	testData := [][]byte{
		{},
		{0x00},
		{0x42},
		[]byte("Hello, MLS!"),
		bytes.Repeat([]byte{0xFF}, 63),    // 1-byte length
		bytes.Repeat([]byte{0xFF}, 64),    // 2-byte length
		bytes.Repeat([]byte{0xFF}, 16383), // 2-byte length max
	}

	for _, data := range testData {
		name := fmt.Sprintf("len_%d", len(data))
		t.Run(name, func(t *testing.T) {
			w := NewWriter()
			w.WriteVLBytes(data)

			r := NewReader(w.Bytes())
			got, err := r.ReadVLBytes()
			if err != nil {
				t.Fatalf("Roundtrip failed: %v", err)
			}
			if !bytes.Equal(got, data) {
				t.Errorf("Roundtrip failed: length %d", len(data))
			}
		})
	}
}

// ============================================================================
// Reader Tests
// ============================================================================

func TestReader_Basic(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}
	r := NewReader(data)

	// Test Remaining
	if r.Remaining() != 4 {
		t.Errorf("Remaining() = %d, want 4", r.Remaining())
	}

	// Test Position
	if r.Position() != 0 {
		t.Errorf("Position() = %d, want 0", r.Position())
	}

	// Read one byte
	_, err := r.ReadUint8()
	if err != nil {
		t.Fatalf("ReadUint8() failed: %v", err)
	}

	if r.Position() != 1 {
		t.Errorf("Position() = %d, want 1", r.Position())
	}

	if r.Remaining() != 3 {
		t.Errorf("Remaining() = %d, want 3", r.Remaining())
	}
}

func TestReader_SetPosition(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}
	r := NewReader(data)

	r.SetPosition(2)
	if r.Position() != 2 {
		t.Errorf("SetPosition(2) failed: position = %d, want 2", r.Position())
	}

	if r.Remaining() != 2 {
		t.Errorf("SetPosition(2) failed: remaining = %d, want 2", r.Remaining())
	}
}

func TestReader_Skip(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}
	r := NewReader(data)

	r.Skip(2)
	if r.Position() != 2 {
		t.Errorf("Skip(2) failed: position = %d, want 2", r.Position())
	}
}

func TestReader_BytesAfterPosition(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}
	r := NewReader(data)

	// Initially, should return all bytes
	got := r.BytesAfterPosition()
	if !bytes.Equal(got, data) {
		t.Errorf("BytesAfterPosition() = %x, want %x", got, data)
	}

	// After reading 2 bytes
	//nolint:errcheck,gosec // Test code, errors intentionally ignored
	r.ReadUint8()
	//nolint:errcheck,gosec // Test code, errors intentionally ignored
	r.ReadUint8()
	got = r.BytesAfterPosition()
	if !bytes.Equal(got, []byte{0x03, 0x04}) {
		t.Errorf("BytesAfterPosition() = %x, want %x", got, []byte{0x03, 0x04})
	}
}

func TestReader_ReadBytes(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}
	r := NewReader(data)

	got, err := r.ReadBytes(2)
	if err != nil {
		t.Fatalf("ReadBytes(2) failed: %v", err)
	}
	if !bytes.Equal(got, []byte{0x01, 0x02}) {
		t.Errorf("ReadBytes(2) = %x, want %x", got, []byte{0x01, 0x02})
	}
}

func TestReader_BufferUnderrun(t *testing.T) {
	data := []byte{0x01}
	r := NewReader(data)

	// Try to read more than available
	_, err := r.ReadUint16()
	if err == nil {
		t.Fatal("Expected buffer underrun error, got nil")
	}
}

// ============================================================================
// Edge Cases y Security Tests
// ============================================================================

func TestWriter_EmptyWrites(t *testing.T) {
	w := NewWriter()

	// Multiple empty writes should work
	w.WriteUint8(0)
	w.WriteUint16(0)
	w.WriteUint32(0)
	w.WriteUint64(0)

	if len(w.Bytes()) != 15 {
		t.Errorf("Expected 15 bytes, got %d", len(w.Bytes()))
	}
}

func TestWriter_ChainedWrites(t *testing.T) {
	w := NewWriter()
	w.WriteUint8(0x01)
	w.WriteUint16(0x0203)
	w.WriteUint32(0x04050607)
	w.WriteUint64(0x08090A0B0C0D0E0F)

	expected := []byte{
		0x01,
		0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	}

	if !bytes.Equal(w.Bytes(), expected) {
		t.Errorf("ChainedWrites() = %x, want %x", w.Bytes(), expected)
	}
}

func TestReader_BoundaryValues(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		fn     func(*Reader) (interface{}, error)
		expect interface{}
	}{
		{
			name: "uint8_max",
			data: []byte{0xFF},
			fn: func(r *Reader) (interface{}, error) {
				return r.ReadUint8()
			},
			expect: uint8(0xFF),
		},
		{
			name: "uint16_max",
			data: []byte{0xFF, 0xFF},
			fn: func(r *Reader) (interface{}, error) {
				return r.ReadUint16()
			},
			expect: uint16(0xFFFF),
		},
		{
			name: "uint32_max",
			data: []byte{0xFF, 0xFF, 0xFF, 0xFF},
			fn: func(r *Reader) (interface{}, error) {
				return r.ReadUint32()
			},
			expect: uint32(0xFFFFFFFF),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReader(tt.data)
			got, err := tt.fn(r)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if got != tt.expect {
				t.Errorf("Got %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestWriter_BigEndian(t *testing.T) {
	// Verify que usamos big-endian correctamente
	w := NewWriter()
	w.WriteUint16(0x1234)

	expected := []byte{0x12, 0x34}
	if !bytes.Equal(w.Bytes(), expected) {
		t.Errorf("WriteUint16 not big-endian: got %x, want %x", w.Bytes(), expected)
	}

	// Verify con binary.BigEndian
	r := NewReader(w.Bytes())
	got, _ := r.ReadUint16()
	if got != 0x1234 {
		t.Errorf("ReadUint16 failed: got %d, want %d", got, 0x1234)
	}
}

func TestMLSVarint_MaxValues(t *testing.T) {
	// Test max value for each encoding
	max1Byte := uint32(63)
	max2Byte := uint32(16383)
	max4Byte := uint32(1073741823)

	w := NewWriter()
	w.WriteMLSVarint(max1Byte)
	if len(w.Bytes()) != 1 {
		t.Errorf("Max 1-byte value encoded as %d bytes, want 1", len(w.Bytes()))
	}

	w = NewWriter()
	w.WriteMLSVarint(max2Byte)
	if len(w.Bytes()) != 2 {
		t.Errorf("Max 2-byte value encoded as %d bytes, want 2", len(w.Bytes()))
	}

	w = NewWriter()
	w.WriteMLSVarint(max4Byte)
	if len(w.Bytes()) != 4 {
		t.Errorf("Max 4-byte value encoded as %d bytes, want 4", len(w.Bytes()))
	}
}

func TestReader_ReadVLBytes_MaxLength(t *testing.T) {
	// Test VLBytes con length máximo que podemos manejar
	maxInline := 16383
	data := bytes.Repeat([]byte{0x42}, maxInline)

	w := NewWriter()
	w.WriteVLBytes(data)

	r := NewReader(w.Bytes())
	got, err := r.ReadVLBytes()
	if err != nil {
		t.Fatalf("ReadVLBytes failed: %v", err)
	}
	if len(got) != maxInline {
		t.Errorf("ReadVLBytes length = %d, want %d", len(got), maxInline)
	}
}

func TestWriter_Reset(t *testing.T) {
	// Test que NewWriter siempre crea writer limpio
	w1 := NewWriter()
	w1.WriteUint8(0x42)

	w2 := NewWriter()
	if len(w2.Bytes()) != 0 {
		t.Errorf("NewWriter should be empty, got %d bytes", len(w2.Bytes()))
	}
}

func TestReader_EmptyBuffer(t *testing.T) {
	r := NewReader([]byte{})

	// ReadUint8 should fail
	_, err := r.ReadUint8()
	if err == nil {
		t.Fatal("Expected error on empty buffer, got nil")
	}

	// ReadMLSVarint should fail
	_, err = r.ReadMLSVarint()
	if err == nil {
		t.Fatal("Expected error on empty buffer, got nil")
	}

	// ReadVLBytes should fail
	_, err = r.ReadVLBytes()
	if err == nil {
		t.Fatal("Expected error on empty buffer, got nil")
	}
}

// ============================================================================
// Fuzzing-like Tests
// ============================================================================

func TestMLSVarint_AllBoundaries(t *testing.T) {
	// Test TODOS los valores en los boundaries
	boundaries := []uint32{
		0, 1, 2, 62, 63, 64, 65,
		16382, 16383, 16384, 16385,
		1073741822, 1073741823,
	}

	for _, v := range boundaries {
		w := NewWriter()
		w.WriteMLSVarint(v)

		r := NewReader(w.Bytes())
		got, err := r.ReadMLSVarint()
		if err != nil {
			t.Fatalf("Failed for value %d: %v", v, err)
		}
		if got != v {
			t.Errorf("Failed for value %d: got %d", v, got)
		}
	}
}

func TestWriterVLBytes_EmptyAndSingle(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"single_zero", []byte{0x00}},
		{"single_ff", []byte{0xFF}},
		{"two_bytes", []byte{0x00, 0xFF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewWriter()
			w.WriteVLBytes(tt.data)

			r := NewReader(w.Bytes())
			got, err := r.ReadVLBytes()
			if err != nil {
				t.Fatalf("Failed: %v", err)
			}
			if !bytes.Equal(got, tt.data) {
				t.Errorf("Got %x, want %x", got, tt.data)
			}
		})
	}
}

// ============================================================================
// WriteRaw and ReadUint64 Tests (previously uncovered)
// ============================================================================

func TestWriter_WriteRaw(t *testing.T) {
	w := NewWriter()
	w.WriteRaw([]byte{0x01, 0x02, 0x03})
	if !bytes.Equal(w.Bytes(), []byte{0x01, 0x02, 0x03}) {
		t.Errorf("WriteRaw = %x, want 010203", w.Bytes())
	}

	// WriteRaw followed by WriteUint8 — ensures no corruption
	w2 := NewWriter()
	w2.WriteRaw([]byte{0xAA, 0xBB})
	w2.WriteUint8(0xCC)
	if !bytes.Equal(w2.Bytes(), []byte{0xAA, 0xBB, 0xCC}) {
		t.Errorf("WriteRaw+WriteUint8 = %x, want aabbcc", w2.Bytes())
	}

	// Empty WriteRaw is a no-op
	w3 := NewWriter()
	w3.WriteRaw([]byte{})
	if len(w3.Bytes()) != 0 {
		t.Errorf("WriteRaw(empty) produced %d bytes, want 0", len(w3.Bytes()))
	}
}

func TestReader_ReadUint64(t *testing.T) {
	tests := []struct {
		name  string
		input uint64
	}{
		{"zero", 0},
		{"one", 1},
		{"max_uint32", math.MaxUint32},
		{"above_uint32", uint64(math.MaxUint32) + 1},
		{"max_uint64", math.MaxUint64},
		{"typical", 0x0102030405060708},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewWriter()
			w.WriteUint64(tt.input)
			r := NewReader(w.Bytes())
			got, err := r.ReadUint64()
			if err != nil {
				t.Fatalf("ReadUint64() error: %v", err)
			}
			if got != tt.input {
				t.Errorf("ReadUint64() = %d, want %d", got, tt.input)
			}
		})
	}

	// Error: underrun
	r := NewReader([]byte{0x00, 0x01, 0x02}) // only 3 bytes
	if _, err := r.ReadUint64(); err == nil {
		t.Error("ReadUint64() with 3 bytes should error")
	}
}

func TestReader_ReadUint32_Underrun(t *testing.T) {
	r := NewReader([]byte{0x00, 0x01}) // only 2 bytes
	if _, err := r.ReadUint32(); err == nil {
		t.Error("ReadUint32() with 2 bytes should error")
	}
}

func TestReader_ReadBytes_Underrun(t *testing.T) {
	r := NewReader([]byte{0x01, 0x02})
	if _, err := r.ReadBytes(5); err == nil {
		t.Error("ReadBytes(5) with 2 bytes should error")
	}
}

// Helper para formatear uint32 en nombres de test
func fmtUint32(v uint32) string {
	if v < 1000 {
		return fmt.Sprintf("%d", v)
	}
	return "large"
}
