package ciphersuite

// No imports needed

// SignatureError represents signature errors.
type SignatureError string

const (
	// ErrVerificationError is returned when signature verification fails.
	ErrVerificationError SignatureError = "signature verification failed"
	// ErrSigningError is returned when signature generation fails.
	ErrSigningError SignatureError = "signature generation failed"
)

func (e SignatureError) Error() string {
	return string(e)
}

// SignedStruct represents a struct that contains a signature.
// This is the type-safe pattern used in OpenMLS Rust.
type SignedStruct interface {
	FromPayload(payload interface{}, signature *Signature, serializedPayload []byte) interface{}
}

// Signable represents a struct that can be signed.
type Signable interface {
	// UnsignedPayload returns the serialized payload that should be signed.
	UnsignedPayload() ([]byte, error)
	// Label returns the string label used for labeled signing.
	Label() string
}

// Sign signs a Signable object.
// Returns the signature and the serialized payload.
func Sign(s Signable, signer *SignaturePrivateKey) (*Signature, []byte, error) {
	payload, err := s.UnsignedPayload()
	if err != nil {
		return nil, nil, ErrSigningError
	}

	// Create SignContent with MLS prefix
	signContent := NewSignContent(s.Label(), payload)
	signContentBytes := signContent.Marshal()

	// Sign
	sig, err := signer.Sign(signContentBytes)
	if err != nil {
		return nil, nil, ErrSigningError
	}

	return sig, payload, nil
}

// Verifiable represents a struct that can be verified.
type Verifiable interface {
	// UnsignedPayload returns the serialized payload that should be verified.
	UnsignedPayload() ([]byte, error)
	// Signature returns the signature to be verified.
	Signature() *Signature
	// Label returns the string label used for labeled verification.
	Label() string
}

// VerifiedStruct represents a verified struct (marker interface).
type VerifiedStruct interface{}

// Verify verifies a Verifiable object.
func Verify(v Verifiable, pk *OpenMlsSignaturePublicKey) error {
	payload, err := v.UnsignedPayload()
	if err != nil {
		return ErrVerificationError
	}

	// Create SignContent with MLS prefix
	signContent := NewSignContent(v.Label(), payload)
	signContentBytes := signContent.Marshal()

	// Verify
	if err := pk.Verify(signContentBytes, v.Signature()); err != nil {
		return ErrVerificationError
	}

	return nil
}

// VerifyWithLabel verifies a signature with a specific label.
func VerifyWithLabel(pk *OpenMlsSignaturePublicKey, label string, payload []byte, sig *Signature) error {
	signContent := NewSignContent(label, payload)
	signContentBytes := signContent.Marshal()
	return pk.Verify(signContentBytes, sig)
}

// SignWithLabel signs data with a specific label.
func SignWithLabel(signer *SignaturePrivateKey, label string, payload []byte) (*Signature, error) {
	signContent := NewSignContent(label, payload)
	signContentBytes := signContent.Marshal()
	return signer.Sign(signContentBytes)
}
