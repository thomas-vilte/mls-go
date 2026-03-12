// Package framing implements Message Layer Security (MLS) message framing.
//
// This package provides the core message framing layer for MLS as defined in
// RFC 9420 §6. It handles the packaging of MLS content (application data,
// proposals, commits) into messages that can be transmitted over the wire.
//
// The framing layer provides:
//   - Sender authentication (signatures)
//   - Membership verification (membership_tag)
//   - Encryption for privacy (PrivateMessage)
//   - Uniform structure for all messages
//
// # MLS Message Types
//
// MLS defines several wire formats (RFC 9420 §6):
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                    MLS Message Hierarchy                        │
//	├─────────────────────────────────────────────────────────────────┤
//	│  MLSMessage (wrapper)                                           │
//	│  ├─ PublicMessage  (§6.2)  → Cleartext, signed                  │
//	│  ├─ PrivateMessage (§6.3)  → Encrypted                          │
//	│  ├─ Welcome        (§11.2) → Welcome messages                   │
//	│  └─ GroupInfo      (§11.5) → Group information                  │
//	└─────────────────────────────────────────────────────────────────┘
//
// # PublicMessage Structure (RFC 9420 §6.2)
//
// Public messages are transmitted in cleartext with signatures:
//
//	struct {
//	    FramedContent content;           // Framed content
//	    FramedContentAuthData auth;      // Signature + confirmation
//	    select (sender.sender_type) {    // Conditional tag
//	        case member:  MAC membership_tag;
//	        case external:
//	        case new_member_commit:
//	        case new_member_proposal:  struct{};
//	    };
//	} PublicMessage;
//
// Wire format: [wire_format][content][auth][membership_tag?]
//
// # PrivateMessage Structure (RFC 9420 §6.3)
//
// Private messages encrypt their content:
//
//	struct {
//	    opaque group_id<V>;              // IN CLEAR
//	    uint64 epoch;                    // IN CLEAR
//	    ContentType content_type;        // IN CLEAR
//	    opaque authenticated_data<V>;    // IN CLEAR
//	    opaque encrypted_sender_data<V>; // ENCRYPTED
//	    opaque ciphertext<V>;            // ENCRYPTED
//	} PrivateMessage;
//
// Wire format: [group_id][epoch][type][auth_data][enc_sd][ct]
//
//	←─── IN CLEAR ───→←──── ENCRYPTED ────→
//
// # SenderData Structure (RFC 9420 §6.3.2)
//
// Encrypted sender information:
//
//	struct {
//	    uint32 leaf_index;       // Leaf index in ratchet tree
//	    uint32 generation;       // Sequence number for ratchet
//	    opaque reuse_guard[4];   // Nonce reuse protection
//	} MLSSenderData;
//
// Encrypted with sender_data_secret to form encrypted_sender_data
//
// # FramedContent Structure (RFC 9420 §6.1)
//
// The core content structure common to all message types:
//
//	struct {
//	    opaque group_id<V>;            // Group identifier
//	    uint64 epoch;                  // Current epoch
//	    Sender sender;                 // Message sender
//	    opaque authenticated_data<V>;  // Additional authenticated data
//	    ContentType content_type;      // Content type
//	    select (content_type) {
//	        case application:  opaque application_data<V>;
//	        case proposal:     Proposal proposal;
//	        case commit:       Commit commit;
//	    };
//	} FramedContent;
//
// # Encryption Flow (RFC 9420 §6.3.1)
//
//  1. Sign FramedContent → AuthenticatedContent
//  2. Generate random ReuseGuard (4 bytes)
//  3. Derive key/nonce from SecretTree
//     └─ XOR nonce[:4] with ReuseGuard
//  4. Construct MLSSenderData
//     └─ Encrypt with sender_data_secret
//  5. Build complete AAD
//     [group_id][epoch][content_type][auth_data][enc_sender]
//  6. Encrypt AuthenticatedContent
//     └─ key/nonce from SecretTree + AAD
//  7. Return PrivateMessage
//     [group_id][epoch][type][auth_data][enc_sd][ciphertext]
//
// # Membership Tag (RFC 9420 §6.2)
//
//	membership_tag = MAC(membership_key, AuthenticatedContentTBM)
//
// Where:
//   - membership_key: Derived from key schedule
//   - TBM = "ToBeMAC'd": Serialized content for MAC
//   - Only for sender_type == member
//
// # Confirmation Tag (RFC 9420 §6.1)
//
//	confirmation_tag = MAC(confirmation_key, confirmed_transcript)
//
// Where:
//   - confirmation_key: Derived from key schedule
//   - confirmed_transcript: Hash of confirmed transcript
//   - Only for ContentType == commit
//
// # Usage Example
//
//	// Create FramedContent
//	content := framing.FramedContent{
//	    GroupID:           []byte("my-group"),
//	    Epoch:             1,
//	    Sender:            framing.Sender{Type: framing.SenderTypeMember, LeafIndex: 0},
//	    AuthenticatedData: []byte("optional-data"),
//	    Body:              framing.ApplicationData{Data: []byte("Hello, MLS!")},
//	}
//
//	// Create PublicMessage (cleartext, signed)
//	pubMsg, err := framing.NewPublicMessage(content, sigKey, gc, membershipKey, cs)
//	if err != nil {
//	    return err
//	}
//
//	// Serialize for transmission
//	data := pubMsg.Marshal()
//
//	// Or create PrivateMessage (encrypted)
//	privMsg, err := framing.Encrypt(framing.EncryptParams{
//	    Content:          content,
//	    SenderLeafIndex:  0,
//	    Generation:       0,
//	    SenderDataSecret: senderDataSecret,
//	    SecretTree:       secretTree,
//	    SigKey:           sigKey,
//	})
//
// # RFC Compliance
//
// This package implements:
//   - RFC 9420 §6.1: FramedContent and AuthenticatedContent
//   - RFC 9420 §6.2: PublicMessage and membership_tag
//   - RFC 9420 §6.3: PrivateMessage and encryption
//   - RFC 9420 §6.3.1: Content encryption with ReuseGuard
//   - RFC 9420 §6.3.2: SenderData encryption
//
// # Security Considerations
//
//   - ReuseGuard prevents nonce reuse (§6.3.1)
//   - membership_tag verifies membership (§6.2)
//   - confirmation_tag verifies commits (§6.1)
//   - ECDSA-SHA256 signatures authenticate sender
//
// # References
//
//   - RFC 9420 §6: https://www.rfc-editor.org/rfc/rfc9420.html#section-6
//   - RFC 9420 §6.1: FramedContent
//   - RFC 9420 §6.2: PublicMessage
//   - RFC 9420 §6.3: PrivateMessage
package framing
