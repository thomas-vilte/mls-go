// Package tls implements TLS presentation language encoding/decoding.
//
// This is a minimal implementation of RFC 8446 §3 for MLS message encoding.
// It's based on the tls_codec Rust crate used by OpenMLS.
package tls

import (
	"encoding/binary"
	"errors"
	"fmt"
)

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
// where length is encoded as ULEB128
func (w *Writer) WriteVLBytes(data []byte) {
	w.WriteULEB128(uint32(len(data)))
	w.buf = append(w.buf, data...)
}

// WriteRaw writes raw bytes without encoding.
func (w *Writer) WriteRaw(data []byte) {
	w.buf = append(w.buf, data...)
}

// WriteULEB128 writes an unsigned integer in ULEB128 format.
func (w *Writer) WriteULEB128(v uint32) {
	for v >= 0x80 {
		w.buf = append(w.buf, byte(v)|0x80)
		v >>= 7
	}
	w.buf = append(w.buf, byte(v))
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
		return 0, errors.New("buffer underrun")
	}
	v := r.buf[r.pos]
	r.pos++
	return v, nil
}

// ReadUint16 reads a 16-bit unsigned integer in big-endian.
func (r *Reader) ReadUint16() (uint16, error) {
	if r.pos+2 > len(r.buf) {
		return 0, errors.New("buffer underrun")
	}
	v := binary.BigEndian.Uint16(r.buf[r.pos:])
	r.pos += 2
	return v, nil
}

// ReadUint32 reads a 32-bit unsigned integer in big-endian.
func (r *Reader) ReadUint32() (uint32, error) {
	if r.pos+4 > len(r.buf) {
		return 0, errors.New("buffer underrun")
	}
	v := binary.BigEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v, nil
}

// ReadUint64 reads a 64-bit unsigned integer in big-endian.
func (r *Reader) ReadUint64() (uint64, error) {
	if r.pos+8 > len(r.buf) {
		return 0, errors.New("buffer underrun")
	}
	v := binary.BigEndian.Uint64(r.buf[r.pos:])
	r.pos += 8
	return v, nil
}

// ReadVLBytes reads a variable-length byte vector.
func (r *Reader) ReadVLBytes() ([]byte, error) {
	length, err := r.ReadULEB128()
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

// ReadULEB128 reads an unsigned integer in ULEB128 format.
func (r *Reader) ReadULEB128() (uint32, error) {
	var result uint32
	var shift uint

	for {
		if r.pos >= len(r.buf) {
			return 0, errors.New("buffer underrun")
		}

		b := r.buf[r.pos]
		r.pos++

		result |= uint32(b&0x7F) << shift
		if b&0x80 == 0 {
			break
		}

		shift += 7
		if shift >= 32 {
			return 0, errors.New("ULEB128 overflow")
		}
	}

	return result, nil
}

// ReadBytes reads n bytes.
func (r *Reader) ReadBytes(n int) ([]byte, error) {
	if r.pos+n > len(r.buf) {
		return nil, errors.New("buffer underrun")
	}

	data := make([]byte, n)
	copy(data, r.buf[r.pos:r.pos+n])
	r.pos += n

	return data, nil
}
