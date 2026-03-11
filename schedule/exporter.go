package schedule

import (
	"fmt"

	"github.com/openmls/go/ciphersuite"
)

// ExporterLabel represents an exporter label.
type ExporterLabel string

const (
	ExporterLabelAuthenticationKey ExporterLabel = "authentication_key"
	ExporterLabelExporterSecret    ExporterLabel = "exporter_secret"
	ExporterLabelResumptionPsk     ExporterLabel = "resumption_psk"
)

// Exporter derives an external secret using the MLS-Exporter construction (RFC 9420 §8.5).
//
//	MLS-Exporter(Label, Context, Length) =
//	    ExpandWithLabel(
//	        DeriveSecret(exporter_secret, Label),
//	        "exporter", Hash(Context), Length)
func Exporter(exporterSecret *ciphersuite.Secret, cs ciphersuite.CipherSuite, label ExporterLabel, context []byte, length int) ([]byte, error) {
	if exporterSecret == nil {
		return nil, fmt.Errorf("exporter_secret is nil")
	}

	// Step 1: DeriveSecret(exporter_secret, Label) = ExpandWithLabel(es, label, [], Nh)
	step1, err := exporterSecret.DeriveSecret(cs, string(label))
	if err != nil {
		return nil, fmt.Errorf("MLS-Exporter step1: %w", err)
	}

	// Step 2: Hash(Context)
	contextHash, err := ciphersuite.Hash(cs, context)
	if err != nil {
		return nil, fmt.Errorf("MLS-Exporter hashing context: %w", err)
	}

	// Step 3: ExpandWithLabel(step1, "exporter", Hash(Context), Length)
	result, err := step1.KdfExpandLabel("exporter", contextHash, length)
	if err != nil {
		return nil, fmt.Errorf("MLS-Exporter step2: %w", err)
	}

	return result.AsSlice(), nil
}

// DeriveAuthenticationKey derives an authentication key.
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
