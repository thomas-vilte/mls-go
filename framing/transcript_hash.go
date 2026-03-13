package framing

import (
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/internal/tls"
)

// ConfirmedTranscriptHashInput serializes the input for computing confirmed_transcript_hash
// for an epoch (RFC 9420 §6.2).
//
// Structure:
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
	Content    FramedContent // Must be ContentTypeCommit
	Signature  []byte
	RawInput   []byte // Alternative: raw wire bytes for interop use
}

// NewConfirmedTranscriptHashInput builds the input from an AuthenticatedContent of type commit.
func NewConfirmedTranscriptHashInput(ac *AuthenticatedContent) (*ConfirmedTranscriptHashInput, error) {
	if ac.Content.ContentType() != ContentTypeCommit {
		return nil, fmt.Errorf("%w: ConfirmedTranscriptHashInput requires a commit", ErrInvalidContentType)
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

// Marshal serializes the input for hashing.
func (i *ConfirmedTranscriptHashInput) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteUint16(uint16(i.WireFormat))
	w.WriteRaw(i.Content.Marshal())
	w.WriteVLBytes(i.Signature)
	return w.Bytes()
}

// Compute calculates confirmed_transcript_hash[n] = Hash(interimHash || serialize(i)).
func (i *ConfirmedTranscriptHashInput) Compute(cs ciphersuite.CipherSuite, interimHash []byte) ([]byte, error) {
	if i.Content.ContentType() != ContentTypeCommit {
		return nil, fmt.Errorf("%w: ConfirmedTranscriptHashInput requires a commit", ErrInvalidContentType)
	}
	data := make([]byte, 0, len(interimHash)+len(i.Marshal()))
	data = append(data, interimHash...)
	data = append(data, i.Marshal()...)
	return hashByCipherSuite(cs, data), nil
}

// ComputeRaw calculates confirmed_transcript_hash[n] = Hash(interimHash || RawInput)
// using raw wire bytes instead of re-serializing from structs.
func (i *ConfirmedTranscriptHashInput) ComputeRaw(cs ciphersuite.CipherSuite, interimHash []byte) []byte {
	data := make([]byte, 0, len(interimHash)+len(i.RawInput))
	data = append(data, interimHash...)
	data = append(data, i.RawInput...)
	return hashByCipherSuite(cs, data)
}

// InterimTranscriptHashInput serializes the input for computing interim_transcript_hash
// for an epoch (RFC 9420 §6.2).
//
// Structure:
//
//	struct {
//	    MAC confirmation_tag;
//	} InterimTranscriptHashInput;
//
// Hash: interim_transcript_hash[n] = Hash(confirmed_transcript_hash[n] || serialize(input))
type InterimTranscriptHashInput struct {
	ConfirmationTag []byte
}

// Marshal serializes the input for hashing.
func (i *InterimTranscriptHashInput) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteVLBytes(i.ConfirmationTag)
	return w.Bytes()
}

// Compute calculates interim_transcript_hash[n] = Hash(confirmedHash || serialize(i)).
func (i *InterimTranscriptHashInput) Compute(cs ciphersuite.CipherSuite, confirmedHash []byte) []byte {
	data := make([]byte, 0, len(confirmedHash)+len(i.Marshal()))
	data = append(data, confirmedHash...)
	data = append(data, i.Marshal()...)
	return hashByCipherSuite(cs, data)
}

// hashByCipherSuite applies the cipher suite's hash function to the input.
func hashByCipherSuite(cs ciphersuite.CipherSuite, data []byte) []byte {
	h := cs.HashFunction()()
	h.Write(data)
	return h.Sum(nil)
}
