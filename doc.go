// Package openmls implements the Messaging Layer Security (MLS) protocol.
//
// MLS is an end-to-end encryption protocol for group messaging, specified in RFC 9420.
// This implementation is based on the OpenMLS Rust implementation.
//
// # Getting Started
//
// To create a new MLS group:
//
//	cs := ciphersuite.MLS128DHKEMP256
//	cred := credentials.NewBasicCredential("Alice")
//	kp, privKeys, err := keypackages.Generate(cred, cs)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	group, err := group.New(cs, kp, privKeys)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Adding Members
//
// To add a member to the group:
//
//	welcome, err := group.AddMember("Bob")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Processing Welcome
//
// To join a group from a Welcome message:
//
//	joinerGroup, err := group.ProcessWelcome(welcome, kp, privKeys)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Encryption and Decryption
//
// To encrypt a message:
//
//	ciphertext, err := group.Encrypt([]byte("Hello, MLS!"))
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// To decrypt:
//
//	plaintext, err := group.Decrypt(ciphertext)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # References
//
//   - RFC 9420: https://datatracker.ietf.org/doc/html/rfc9420
//   - OpenMLS (Rust): https://github.com/openmls/openmls
package openmls

// Version of the library
const Version = "0.1.0-dev"
