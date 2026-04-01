package schedule

import (
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// ExporterLabel represents a label for MLS exporter derivation.
//
// Exporter labels are used to derive application-specific secrets from the
// exporter_secret while maintaining cryptographic binding to the group state.
type ExporterLabel string

const (
	// ExporterLabelAuthenticationKey derives an authentication key.
	ExporterLabelAuthenticationKey ExporterLabel = "authentication_key"
)

// Exporter derives an external secret using the MLS-Exporter construction per RFC 9420 §8.5.
//
// The MLS-Exporter allows applications to derive their own secrets from the MLS
// key schedule while maintaining cryptographic binding to the group state:
//
//	MLS-Exporter(Label, Context, Length) =
//	    ExpandWithLabel(
//	        DeriveSecret(exporter_secret, Label),
//	        "exporter", Hash(Context), Length)
//
// Parameters:
//   - exporterSecret: The exporter_secret from epoch secrets
//   - cs: Cipher suite for HKDF and hashing
//   - label: Application-specific label for domain separation
//   - context: Application context to bind the exported secret to
//   - length: Desired output length in bytes
//
// Returns the exported secret, or an error if exporter_secret is nil or derivation fails.
//
// RFC 9420 §8.5:
//
//	exported_secret = ExpandWithLabel(
//	    DeriveSecret(exporter_secret, Label),
//	    "exporter",
//	    Hash(Context),
//	    Length
//	)
func Exporter(exporterSecret *ciphersuite.Secret, cs ciphersuite.CipherSuite, label ExporterLabel, context []byte, length int) ([]byte, error) {
	if exporterSecret == nil {
		return nil, fmt.Errorf("exporter_secret is nil")
	}

	// DeriveSecret(exporter_secret, Label) = ExpandWithLabel(es, label, [], Nh)
	step1, err := exporterSecret.DeriveSecret(cs, string(label))
	if err != nil {
		return nil, fmt.Errorf("MLS-Exporter step1: %w", err)
	}

	// Hash(Context)
	contextHash, err := ciphersuite.Hash(cs, context)
	if err != nil {
		return nil, fmt.Errorf("MLS-Exporter hashing context: %w", err)
	}

	result, err := step1.KdfExpandLabel("exporter", contextHash, length)
	if err != nil {
		return nil, fmt.Errorf("MLS-Exporter step2: %w", err)
	}

	return result.AsSlice(), nil
}

// DeriveAuthenticationKey derives an authentication key from authentication_secret.
//
// This function uses HKDF-Expand to derive a fixed-length authentication key:
//
//	authentication_key = HKDF-Expand(authentication_secret, "authentication_key", 32)
//
// Parameters:
//   - authenticationSecret: The authentication_secret from epoch secrets
//
// Returns the 32-byte authentication key, or an error if authentication_secret is nil.
func DeriveAuthenticationKey(authenticationSecret *ciphersuite.Secret) ([]byte, error) {
	if authenticationSecret == nil {
		return nil, fmt.Errorf("authentication_secret is nil")
	}

	authKey, err := authenticationSecret.HKDFExpand([]byte("authentication_key"), 32)
	if err != nil {
		return nil, fmt.Errorf("HKDF expand failed: %w", err)
	}

	return authKey.AsSlice(), nil
}
