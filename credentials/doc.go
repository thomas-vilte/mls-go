// Package credentials implements MLS credentials per RFC 9420 §5.2.
//
// Credentials bind an identity to a signing key and are stored in LeafNodes.
// They are used to authenticate group members and attribute messages to senders.
//
// # Credential Types
//
// The package supports the two credential types defined in RFC 9420:
//
//   - BasicCredential: identity blob with optional extension data
//   - X509Credential: X.509 certificate chain (ECDSA P-256 only for MLS signatures)
//
// # Usage
//
// ## Basic Credential
//
// For simple applications using plaintext identities:
//
//	cred, priv, err := credentials.GenerateCredentialWithKey([]byte("alice@example.com"))
//
// ## X.509 Credential
//
// For applications using certificate-based identity:
//
//	// Load certificate and private key from files or HSM
//	certDER := loadCertificateDER()
//	privKey := loadECDSAPrivateKey()
//
//	cred, err := credentials.GenerateX509CredentialWithKey(certDER, privKey)
//
// ## Credential Validation
//
// The library includes a default validator that checks credential structure.
// For application-specific policies (e.g., certificate chain validation,
// allowlist enforcement), implement the CredentialValidator interface:
//
//	type validatingCreditor struct{}
//
//	func (validatingCreditor) ValidateCredential(ctx context.Context, cred *Credential) error {
//	    // Custom validation logic
//	    if bytes.HasPrefix(cred.Identity, []byte("admin:")) {
//	        return nil // allow
//	    }
//	    return fmt.Errorf("only admin: users allowed")
//	}
//
// Install via ClientOption:
//
//	client, err := mls.NewClient(identity, cs,
//	    mls.WithCredentialValidator(validatingCreditor{}),
//	)
//
// # Credential Selection
//
// MLS cipher suites dictate signature schemes:
//
//   - MLS10_DHKEMX25519_AES128GCM_SHA256_Ed25519: Ed25519
//   - MLS10_DHKEMP256_AES128GCM_SHA256_P256: ECDSA P-256
//   - MLS10_DHKEMX448_AES256GCM_SHA512_Ed448: Ed448
//   - MLS10_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448: Ed448
//
// The signature scheme is automatically selected based on the cipher suite.
// Using an incompatible credential (e.g., Ed25519 with a P-256 cipher suite)
// will result in an error during key package generation.
//
// # Wire Format
//
// Credentials are serialized as part of KeyPackage and LeafNode payloads.
// The format is determined by the CredentialType field:
//
//   - 0x0001: BasicCredential
//   - 0x0002: X509Credential
package credentials
