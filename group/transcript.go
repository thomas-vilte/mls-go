package group

import (
	"crypto/sha256"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/internal/tls"
)

// hashData computa el hash SHA-256 de los datos
func hashData(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// ConfirmedTranscriptHashInput
// confirmed_transcript_hash_[epoch] = Hash(interim_transcript_hash_[epoch-1] || ConfirmedTranscriptHashInput)
// RFC 9420 §8.2
type ConfirmedTranscriptHashInput struct {
	WireFormat uint16
	Content    []byte // Serialized FramedContent with content_type == commit
	Signature  []byte
}

// Calculate computa el confirmed transcript hash
func (cthi *ConfirmedTranscriptHashInput) Calculate(
	cs ciphersuite.CipherSuite,
	interimTranscriptHash []byte,
) ([]byte, error) {
	w := tls.NewWriter()
	w.WriteUint16(cthi.WireFormat)
	w.WriteVLBytes(cthi.Content)
	w.WriteVLBytes(cthi.Signature)

	input := append(interimTranscriptHash, w.Bytes()...)
	return hashData(input), nil
}

// InterimTranscriptHashInput
// interim_transcript_hash_[epoch] = Hash(confirmed_transcript_hash_[epoch] || InterimTranscriptHashInput)
// RFC 9420 §8.2
type InterimTranscriptHashInput struct {
	ConfirmationTag []byte
}

// Calculate computa el interim transcript hash
func (ithi *InterimTranscriptHashInput) Calculate(
	cs ciphersuite.CipherSuite,
	confirmedTranscriptHash []byte,
) ([]byte, error) {
	w := tls.NewWriter()
	w.WriteVLBytes(ithi.ConfirmationTag)

	input := append(confirmedTranscriptHash, w.Bytes()...)
	return hashData(input), nil
}
