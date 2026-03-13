// Package tls implements TLS presentation language encoding/decoding.
//
// This is a minimal implementation of RFC 8446 §3 for MLS message encoding.
// It's based on the tls_codec Go crate used by other implementation.
package tls

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrBufferUnderrun is returned when a read exceeds the available buffer data.
var ErrBufferUnderrun = errors.New("buffer underrun")

// Writer writes TLS presentation language format.
type Writer struct {
	buf []byte
}

// NewWriter creates a new TLS writer.
func NewWriter() *Writer {
	return &Writer{
		buf: make([]byte, 0, 256),
	}
}

// Bytes returns the written bytes.
func (w *Writer) Bytes() []byte {
	return w.buf
}

// WriteUint8 writes an 8-bit unsigned integer.
func (w *Writer) WriteUint8(v uint8) {
	w.buf = append(w.buf, v)
}

// WriteUint16 writes a 16-bit unsigned integer in big-endian.
func (w *Writer) WriteUint16(v uint16) {
	w.buf = append(w.buf, byte(v>>8), byte(v))
}

// WriteUint32 writes a 32-bit unsigned integer in big-endian.
func (w *Writer) WriteUint32(v uint32) {
	w.buf = append(w.buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// WriteUint64 writes a 64-bit unsigned integer in big-endian.
func (w *Writer) WriteUint64(v uint64) {
	w.buf = append(w.buf,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v),
	)
}

// WriteVLBytes writes a variable-length byte vector.
//
// Format: length<V> || data
// where length is encoded as MLS varint (RFC 9420 §3.5)
func (w *Writer) WriteVLBytes(data []byte) {
	w.WriteMLSVarint(uint32(len(data)))
	w.buf = append(w.buf, data...)
}

// WriteRaw writes raw bytes without encoding.
func (w *Writer) WriteRaw(data []byte) {
	w.buf = append(w.buf, data...)
}

// WriteMLSVarint writes an unsigned integer in MLS variable-length encoding (RFC 9420 §3.5).
//
// Encoding:
//   - 0–63: 1 byte (high 2 bits = 00)
//   - 64–16383: 2 bytes (high 2 bits = 01)
//   - 16384–1073741823: 4 bytes (high 2 bits = 10)
func (w *Writer) WriteMLSVarint(v uint32) {
	switch {
	case v < 64:
		w.buf = append(w.buf, byte(v))
	case v < 16384:
		w.buf = append(w.buf, byte(0x40|(v>>8)), byte(v&0xFF))
	default:
		w.buf = append(w.buf, byte(0x80|(v>>24)), byte((v>>16)&0xFF), byte((v>>8)&0xFF), byte(v&0xFF))
	}
}

// Reader reads TLS presentation language format.
type Reader struct {
	buf []byte
	pos int
}

// NewReader creates a new TLS reader.
func NewReader(data []byte) *Reader {
	return &Reader{
		buf: data,
		pos: 0,
	}
}

// Remaining returns the number of unread bytes.
func (r *Reader) Remaining() int {
	return len(r.buf) - r.pos
}

// Position returns the current read position.
func (r *Reader) Position() int {
	return r.pos
}

// SetPosition sets the read position.
func (r *Reader) SetPosition(pos int) {
	r.pos = pos
}

// Skip advances the position by n bytes.
func (r *Reader) Skip(n int) {
	r.pos += n
}

// BytesAfterPosition returns bytes from current position to end.
func (r *Reader) BytesAfterPosition() []byte {
	return r.buf[r.pos:]
}

// ReadUint8 reads an 8-bit unsigned integer.
func (r *Reader) ReadUint8() (uint8, error) {
	if r.pos >= len(r.buf) {
		return 0, ErrBufferUnderrun
	}
	v := r.buf[r.pos]
	r.pos++
	return v, nil
}

// ReadUint16 reads a 16-bit unsigned integer in big-endian.
func (r *Reader) ReadUint16() (uint16, error) {
	if r.pos+2 > len(r.buf) {
		return 0, ErrBufferUnderrun
	}
	v := binary.BigEndian.Uint16(r.buf[r.pos:])
	r.pos += 2
	return v, nil
}

// ReadUint32 reads a 32-bit unsigned integer in big-endian.
func (r *Reader) ReadUint32() (uint32, error) {
	if r.pos+4 > len(r.buf) {
		return 0, ErrBufferUnderrun
	}
	v := binary.BigEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v, nil
}

// ReadUint64 reads a 64-bit unsigned integer in big-endian.
func (r *Reader) ReadUint64() (uint64, error) {
	if r.pos+8 > len(r.buf) {
		return 0, ErrBufferUnderrun
	}
	v := binary.BigEndian.Uint64(r.buf[r.pos:])
	r.pos += 8
	return v, nil
}

// ReadVLBytes reads a variable-length byte vector.
func (r *Reader) ReadVLBytes() ([]byte, error) {
	length, err := r.ReadMLSVarint()
	if err != nil {
		return nil, err
	}

	if r.pos+int(length) > len(r.buf) {
		return nil, fmt.Errorf("buffer underrun: need %d bytes, have %d", length, r.Remaining())
	}

	data := make([]byte, length)
	copy(data, r.buf[r.pos:r.pos+int(length)])
	r.pos += int(length)

	return data, nil
}

// ReadMLSVarint reads an unsigned integer in MLS variable-length encoding (RFC 9420 §3.5).
func (r *Reader) ReadMLSVarint() (uint32, error) {
	if r.pos >= len(r.buf) {
		return 0, ErrBufferUnderrun
	}

	b0 := r.buf[r.pos]
	prefix := b0 >> 6

	switch prefix {
	case 0: // 1-byte: 0–63
		r.pos++
		return uint32(b0 & 0x3F), nil
	case 1: // 2-byte: 64–16383
		if r.pos+2 > len(r.buf) {
			return 0, ErrBufferUnderrun
		}
		v := uint32(b0&0x3F)<<8 | uint32(r.buf[r.pos+1])
		r.pos += 2
		return v, nil
	case 2: // 4-byte: 16384–1073741823
		if r.pos+4 > len(r.buf) {
			return 0, ErrBufferUnderrun
		}
		v := uint32(b0&0x3F)<<24 | uint32(r.buf[r.pos+1])<<16 | uint32(r.buf[r.pos+2])<<8 | uint32(r.buf[r.pos+3])
		r.pos += 4
		return v, nil
	default:
		return 0, fmt.Errorf("invalid MLS varint prefix 0x%02x", b0)
	}
}

// ReadBytes reads n bytes.
func (r *Reader) ReadBytes(n int) ([]byte, error) {
	if r.pos+n > len(r.buf) {
		return nil, ErrBufferUnderrun
	}

	data := make([]byte, n)
	copy(data, r.buf[r.pos:r.pos+n])
	r.pos += n

	return data, nil
}
