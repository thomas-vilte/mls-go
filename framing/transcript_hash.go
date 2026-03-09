package framing

import (
	"crypto/sha256"
	"fmt"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/internal/tls"
)

// ConfirmedTranscriptHashInput serializa el input para calcular el confirmed_transcript_hash
// de una época (RFC 9420 §6.2).
//
//	struct {
//	    WireFormat wire_format;
//	    FramedContent content; /* content_type == commit */
//	    opaque signature<V>;
//	} ConfirmedTranscriptHashInput;
//
// Hash: confirmed_transcript_hash[n] = Hash(interim_transcript_hash[n-1] || serialize(input))
type ConfirmedTranscriptHashInput struct {
	WireFormat WireFormat
	Content    FramedContent // debe ser ContentTypeCommit
	Signature  []byte
	RawInput   []byte // alternative: raw wire bytes (WireFormat+FramedContent+signature) for interop use
}

// NewConfirmedTranscriptHashInput construye el input a partir de un AuthenticatedContent de commit.
func NewConfirmedTranscriptHashInput(ac *AuthenticatedContent) (*ConfirmedTranscriptHashInput, error) {
	if ac.Content.ContentType() != ContentTypeCommit {
		return nil, fmt.Errorf("%w: ConfirmedTranscriptHashInput requiere un commit", ErrInvalidContentType)
	}
	var sig []byte
	if ac.Auth.Signature != nil {
		sig = ac.Auth.Signature.AsSlice()
	}
	return &ConfirmedTranscriptHashInput{
		WireFormat: ac.WireFormat,
		Content:    ac.Content,
		Signature:  sig,
	}, nil
}

// Marshal serializa el input para el hash.
func (i *ConfirmedTranscriptHashInput) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteUint16(uint16(i.WireFormat))
	w.WriteRaw(i.Content.Marshal())
	w.WriteVLBytes(i.Signature)
	return w.Bytes()
}

// Compute calcula confirmed_transcript_hash[n] = Hash(interimHash || serialize(i)).
func (i *ConfirmedTranscriptHashInput) Compute(cs ciphersuite.CipherSuite, interimHash []byte) ([]byte, error) {
	if i.Content.ContentType() != ContentTypeCommit {
		return nil, fmt.Errorf("%w: ConfirmedTranscriptHashInput requiere un commit", ErrInvalidContentType)
	}
	data := append(interimHash, i.Marshal()...)
	return hashByCipherSuite(cs, data), nil
}

// ComputeRaw calcula confirmed_transcript_hash[n] = Hash(interimHash || RawInput)
// usando los bytes crudos del wire en lugar de re-serializar desde structs.
func (i *ConfirmedTranscriptHashInput) ComputeRaw(cs ciphersuite.CipherSuite, interimHash []byte) []byte {
	data := append(interimHash, i.RawInput...)
	return hashByCipherSuite(cs, data)
}

// InterimTranscriptHashInput serializa el input para calcular el interim_transcript_hash
// de una época (RFC 9420 §6.2).
//
//	struct {
//	    MAC confirmation_tag;
//	} InterimTranscriptHashInput;
//
// Hash: interim_transcript_hash[n] = Hash(confirmed_transcript_hash[n] || serialize(input))
type InterimTranscriptHashInput struct {
	ConfirmationTag []byte
}

// Marshal serializa el input para el hash.
func (i *InterimTranscriptHashInput) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteVLBytes(i.ConfirmationTag)
	return w.Bytes()
}

// Compute calcula interim_transcript_hash[n] = Hash(confirmedHash || serialize(i)).
func (i *InterimTranscriptHashInput) Compute(cs ciphersuite.CipherSuite, confirmedHash []byte) []byte {
	data := append(confirmedHash, i.Marshal()...)
	return hashByCipherSuite(cs, data)
}

// hashByCipherSuite aplica el hash del cipher suite al input.
// Actualmente solo soporta SHA-256 (MLS_128_DHKEMP256_AES128GCM_SHA256_P256).
func hashByCipherSuite(_ ciphersuite.CipherSuite, data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
