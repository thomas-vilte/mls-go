package ciphersuite

import (
	"fmt"
	"hash"

	"github.com/openmls/go/internal/tls"
)

// KeyPackageRefLabel is the label for KeyPackage references (RFC 9420 §5.2).
var KeyPackageRefLabel = []byte("MLS 1.0 KeyPackage Reference")

// ProposalRefLabel is the label for Proposal references (RFC 9420 §5.2).
var ProposalRefLabel = []byte("MLS 1.0 Proposal Reference")

// HashReference represents a hash-based reference to an MLS object (RFC 9420 §5.2).
type HashReference struct {
	Value []byte
}

// NewHashReference creates a new hash reference.
func NewHashReference(value []byte) *HashReference {
	return &HashReference{Value: value}
}

// AsSlice returns the reference value.
func (hr *HashReference) AsSlice() []byte {
	return hr.Value
}

// String returns a string representation.
func (hr *HashReference) String() string {
	s := "HashReference: "
	for _, b := range hr.Value {
		s += fmt.Sprintf("%02X", b)
	}
	return s
}

// KeyPackageRef is a reference to a KeyPackage.
type KeyPackageRef HashReference

// MakeKeyPackageRef computes a KeyPackage reference.
// MakeKeyPackageRef(value) = RefHash("MLS 1.0 KeyPackage Reference", value)
func MakeKeyPackageRef(value []byte, hashFn func() hash.Hash) *KeyPackageRef {
	ref := makeHashReference(value, KeyPackageRefLabel, hashFn)
	return (*KeyPackageRef)(ref)
}

// AsSlice returns the reference value.
func (kpr *KeyPackageRef) AsSlice() []byte {
	return (*HashReference)(kpr).AsSlice()
}

// ProposalRef is a reference to a Proposal.
type ProposalRef HashReference

// MakeProposalRef computes a Proposal reference.
// MakeProposalRef(value) = RefHash("MLS 1.0 Proposal Reference", value)
func MakeProposalRef(value []byte, hashFn func() hash.Hash) *ProposalRef {
	ref := makeHashReference(value, ProposalRefLabel, hashFn)
	return (*ProposalRef)(ref)
}

// AsSlice returns the reference value.
func (pr *ProposalRef) AsSlice() []byte {
	return (*HashReference)(pr).AsSlice()
}

// hashReferenceInput is the input structure for computing references.
type hashReferenceInput struct {
	Label []byte
	Value []byte
}

// Marshal serializes the input.
func (hri *hashReferenceInput) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteVLBytes(hri.Label)
	w.WriteVLBytes(hri.Value)
	return w.Bytes()
}

// makeHashReference computes a hash reference.
// RefHash(label, value) = Hash(RefHashInput)
// where RefHashInput is:
//
//	struct {
//	    opaque label<V> = label;
//	    opaque value<V> = value;
//	} RefHashInput;
func makeHashReference(value, label []byte, hashFn func() hash.Hash) *HashReference {
	input := &hashReferenceInput{
		Label: label,
		Value: value,
	}
	payload := input.Marshal()
	h := hashFn()
	h.Write(payload)
	return NewHashReference(h.Sum(nil))
}
