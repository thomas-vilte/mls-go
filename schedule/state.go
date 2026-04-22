// Package schedule implements MLS Key Schedule state persistence.
//
// This file provides serialization/deserialization for EpochSecrets,
// enabling group state persistence and recovery.
//
// SECURITY WARNING: EpochSecrets contain all cryptographic secrets for an MLS
// epoch. They MUST be encrypted at rest and transmitted only over secure channels.
package schedule

// EpochSecretsData is a serializable representation of EpochSecrets.
//
// This struct is designed for JSON serialization with base64-encoded byte fields.
// All secrets are copied to prevent accidental mutation of the original EpochSecrets.
//
// SECURITY WARNING: Contains sensitive cryptographic material:
//   - encryption_secret: Derives all message encryption keys
//   - confirmation_key: Verifies group state agreement
//   - membership_key: Authenticates group membership
//   - init_secret: Seeds the next epoch's key schedule
//
// This data MUST be encrypted before persistence or transmission.
type EpochSecretsData struct {
	SenderDataSecret     []byte `json:"sender_data_secret"`
	EncryptionSecret     []byte `json:"encryption_secret"`
	ExporterSecret       []byte `json:"exporter_secret"`
	AuthenticationSecret []byte `json:"authentication_secret"`
	ConfirmationKey      []byte `json:"confirmation_key"`
	MembershipKey        []byte `json:"membership_key"`
	ExternalSecret       []byte `json:"external_secret"`
	ResumptionSecret     []byte `json:"resumption_secret"`
	InitSecret           []byte `json:"init_secret"`
}

// MarshalData converts EpochSecrets to a serializable struct, deep-copying all secret bytes.
//
// Security:
//   - All secrets are copied using append([]byte(nil), ...) to ensure independence
//   - The original EpochSecrets remain unchanged
//   - Caller is responsible for encrypting the returned data
//
// Usage:
//
//	data := epochSecrets.MarshalData()
//	jsonData, err := json.Marshal(data)
//	if err != nil {
//	    return err
//	}
//	// Encrypt jsonData before storing
func (e *EpochSecrets) MarshalData() *EpochSecretsData {
	if e == nil {
		return nil
	}

	data := &EpochSecretsData{}

	if e.SenderDataSecret != nil {
		data.SenderDataSecret = append([]byte(nil), e.SenderDataSecret.AsSlice()...)
	}
	if e.EncryptionSecret != nil {
		data.EncryptionSecret = append([]byte(nil), e.EncryptionSecret.AsSlice()...)
	}
	if e.ExporterSecret != nil {
		data.ExporterSecret = append([]byte(nil), e.ExporterSecret.AsSlice()...)
	}
	if e.AuthenticationSecret != nil {
		data.AuthenticationSecret = append([]byte(nil), e.AuthenticationSecret.AsSlice()...)
	}
	if e.ConfirmationKey != nil {
		data.ConfirmationKey = append([]byte(nil), e.ConfirmationKey.AsSlice()...)
	}
	if e.MembershipKey != nil {
		data.MembershipKey = append([]byte(nil), e.MembershipKey.AsSlice()...)
	}
	if e.ExternalSecret != nil {
		data.ExternalSecret = append([]byte(nil), e.ExternalSecret.AsSlice()...)
	}
	if e.ResumptionSecret != nil {
		data.ResumptionSecret = append([]byte(nil), e.ResumptionSecret.AsSlice()...)
	}
	if e.InitSecret != nil {
		data.InitSecret = append([]byte(nil), e.InitSecret.AsSlice()...)
	}

	return data
}
