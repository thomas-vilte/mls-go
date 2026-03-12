// Package ciphersuite implements hash reference operations per RFC 9420 §5.2.
package ciphersuite

import (
	"fmt"
	"hash"

	"github.com/thomas-vilte/mls-go/internal/tls"
)

// KeyPackageRefLabel is the label for KeyPackage references as defined in RFC 9420 §5.2.
var KeyPackageRefLabel = []byte("MLS 1.0 KeyPackage Reference")

// ProposalRefLabel is the label for Proposal references as defined in RFC 9420 §5.2.
var ProposalRefLabel = []byte("MLS 1.0 Proposal Reference")

// HashReference represents a hash-based reference to an MLS object as defined in RFC 9420 §5.2.
//
// Hash references are used to uniquely identify MLS objects without revealing their content:
//   - KeyPackageRef: identifies a KeyPackage in a group (RFC 9420 §5.2)
//   - ProposalRef: identifies a Proposal in a Commit (RFC 9420 §5.2)
//
// The reference is computed as:
//
//	RefHash(label, value) = Hash(VL(label) || VL(value))
//
// where VL() is a variable-length integer encoding.
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

// KeyPackageRef is a reference to a KeyPackage as defined in RFC 9420 §5.2.
type KeyPackageRef HashReference

// MakeKeyPackageRef computes a KeyPackage reference per RFC 9420 §5.2.
//
// Implements:
//
//	MakeKeyPackageRef(value) = RefHash("MLS 1.0 KeyPackage Reference", value)
//
// This reference is used to identify a KeyPackage in a group without
// revealing the KeyPackage content.
func MakeKeyPackageRef(value []byte, hashFn func() hash.Hash) *KeyPackageRef {
	ref := makeHashReference(value, KeyPackageRefLabel, hashFn)
	return (*KeyPackageRef)(ref)
}

// AsSlice returns the reference value.
func (kpr *KeyPackageRef) AsSlice() []byte {
	return (*HashReference)(kpr).AsSlice()
}

// ProposalRef is a reference to a Proposal as defined in RFC 9420 §5.2.
type ProposalRef HashReference

// MakeProposalRef computes a Proposal reference per RFC 9420 §5.2.
//
// Implements:
//
//	MakeProposalRef(value) = RefHash("MLS 1.0 Proposal Reference", value)
//
// This reference is used to identify a Proposal in a Commit's references list.
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

// makeHashReference computes a hash reference per RFC 9420 §5.2.
//
// Implements:
//
//	RefHash(label, value) = Hash(RefHashInput)
//
// where RefHashInput is:
//
//	struct {
//	    opaque label<V> = label;
//	    opaque value<V> = value;
//	} RefHashInput;
//
// The variable-length encoding (VL) ensures the hash input is unambiguous.
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
