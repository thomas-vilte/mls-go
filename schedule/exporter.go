package schedule

import (
	"crypto/sha256"
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

// Exporter derives an external secret from the exporter_secret.
func Exporter(exporterSecret *ciphersuite.Secret, label ExporterLabel, context []byte, length int) ([]byte, error) {
	if exporterSecret == nil {
		return nil, fmt.Errorf("exporter_secret is nil")
	}

	fullLabel := append([]byte("mls10 "), []byte(label)...)

	exportedValue, err := exporterSecret.HKDFExpand(append(fullLabel, context...), length)
	if err != nil {
		return nil, fmt.Errorf("HKDF expand failed: %w", err)
	}

	return exportedValue.AsSlice(), nil
}

// DeriveAuthenticationKey derives an authentication key.
func DeriveAuthenticationKey(authenticationSecret *ciphersuite.Secret) ([]byte, error) {
	if authenticationSecret == nil {
		return nil, fmt.Errorf("authentication_secret is nil")
	}

	authKey, err := authenticationSecret.HKDFExpand([]byte("authentication_key"), sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("HKDF expand failed: %w", err)
	}

	return authKey.AsSlice(), nil
}
