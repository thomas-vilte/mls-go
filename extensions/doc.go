// Package extensions implements MLS extensions per RFC 9420 §13.
//
// Extensions add optional information to MLS objects and are used in:
//   - KeyPackages: client capabilities and features
//   - GroupInfo: group parameters for new members joining via Welcome
//   - GroupContext: shared state ensuring all members have same view
//   - LeafNodes: per-member configuration (e.g., application-specific IDs)
//
// # Implemented Extension Types
//
// The package provides concrete implementations for all required MLS extensions:
//
// | Extension Type          | ID     | Location     | RFC Section | Description                    |
// |-------------------------|--------|--------------|-------------|----------------------------------|
// | ApplicationID          | 0x0001 | LeafNode     | §5.3.3      | Application-specific identifier |
// | RatchetTree            | 0x0002 | GroupInfo   | §12.4.3.3   | Full tree for new members        |
// | RequiredCapabilities   | 0x0003 | GroupContext | §11.1       | Required features for group      |
// | ExternalPub            | 0x0004 | GroupInfo   | §12.4.3.2   | HPKE key for External Commit    |
// | ExternalSenders        | 0x0005 | GroupContext | §12.1.8.1  | Allowed external senders         |
// | LastResort              | 0x000A | KeyPackage  | §16.8       | Backup KeyPackage               |
//
// # Usage
//
// ## Creating Extensions
//
// Use the typed extension constructors:
//
//	appID := NewApplicationIDExtension([]byte("my-app-id"))
//	ext, err := appID.ToExtension()
//
// ## Adding to KeyPackage
//
//	kp, priv, err := keypackages.Generate(cred, cs,
//	    keypackages.WithExtensions([]extensions.Extension{*ext}),
//	)
//
// ## Adding to GroupInfo
//
//	groupInfo, err := g.GetGroupInfo(sigKey,
//	    group.WithRatchetTree(true),     // Include ratchet tree (default)
//	    group.WithExternalPub(false), // Omit external pub key
//	)
//
// # Custom Extension Handlers
//
// For custom extensions not defined in this package, use the generic
// Extension type directly:
//
//	ext := Extension{
//	    Type: ExtensionType(0xFF01), // Custom type ID
//	    Data: []byte("custom data"),
//	}
//
// Applications may inspect and validate custom extensions but must not
// modify them unless they are the sender.
//
// # Serialization
//
// Extensions are serialized in ascending order by type ID (RFC 9420 §13.4).
//
// # Errors
//
// Operations return typed errors for programmatic handling:
//
//   - ErrInvalidExtension: when extension data is malformed
//   - Extension type not supported: returns error on unmarshal
package extensions
