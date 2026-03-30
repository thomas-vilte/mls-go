// Package mls is the module root for github.com/thomas-vilte/mls-go.
//
// The implementation is organized into subpackages:
//
//   - ciphersuite: HPKE, HKDF, AEAD, signatures, and hash references
//   - credentials: MLS credentials
//   - extensions: MLS extension types and helpers
//   - framing: MLSMessage, PublicMessage, and PrivateMessage framing
//   - group: group lifecycle, proposals, commits, and Welcome handling
//   - keypackages: KeyPackage generation and validation
//   - schedule: MLS key schedule and exporter support
//   - secrettree: per-sender secret tree ratchets
//   - treesync: ratchet tree and TreeKEM helpers
//
// The main entry point for applications is usually the group package.
//
// A minimal flow looks like this:
//
//	groupID, err := group.NewGroupIDRandom()
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	aliceCred, aliceSigPriv, err := credentials.GenerateCredentialWithKeyForCS([]byte("alice"), ciphersuite.MLS128DHKEMP256)
//	if err != nil {
//		log.Fatal(err)
//	}
//	aliceKP, alicePriv, err := keypackages.Generate(aliceCred, ciphersuite.MLS128DHKEMP256)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	aliceGroup, err := group.NewGroup(groupID, ciphersuite.MLS128DHKEMP256, aliceKP, alicePriv)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	bobCred, _, err := credentials.GenerateCredentialWithKeyForCS([]byte("bob"), ciphersuite.MLS128DHKEMP256)
//	if err != nil {
//		log.Fatal(err)
//	}
//	bobKP, bobPriv, err := keypackages.Generate(bobCred, ciphersuite.MLS128DHKEMP256)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	if _, err := aliceGroup.AddMember(bobKP); err != nil {
//		log.Fatal(err)
//	}
//
//	if _, err := aliceGroup.Commit(aliceSigPriv, aliceSigPriv.PublicKey(), nil); err != nil {
//		log.Fatal(err)
//	}
//
// The integration tests under group/ are the best source of up-to-date usage examples.
//
// References:
//
//   - RFC 9420: https://www.rfc-editor.org/rfc/rfc9420
//   - RFC 9180: https://www.rfc-editor.org/rfc/rfc9180
package mls
