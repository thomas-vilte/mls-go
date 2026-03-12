// Package framing implements the MLS Message Framing layer as specified in RFC 9420 §6.
//
// # Overview
//
// The framing layer provides the cryptographic envelope for all MLS protocol messages.
// It ensures message authenticity, confidentiality, and membership verification while
// maintaining the protocol's security properties of Forward Secrecy (FS) and
// Post-Compromise Security (PCS).
//
// # Design Rationale
//
// Why separate framing from content? The MLS protocol separates message content
// (application data, proposals, commits) from the cryptographic framing to allow:
//
//  1. Independent evolution of content types and wire formats
//  2. Different security policies for handshake vs application messages
//  3. Efficient verification paths for different message categories
//
// # Message Types (RFC 9420 §6)
//
// MLS defines two primary wire formats:
//
// PublicMessage (§6.2) - For handshake messages that require transparency:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                    PublicMessage Structure                      │
//	├─────────────────────────────────────────────────────────────────┤
//	│  FramedContent        - Message content with metadata            │
//	│  FramedContentAuthData - Signature and optional confirmation tag │
//	│  membership_tag       - MAC proving group membership (members)   │
//	└─────────────────────────────────────────────────────────────────┘
//
// PrivateMessage (§6.3) - For confidential application and handshake messages:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                   PrivateMessage Structure                      │
//	├─────────────────────────────────────────────────────────────────┤
//	│  group_id             - Group identifier (cleartext)             │
//	│  epoch                - Current epoch number (cleartext)         │
//	│  content_type         - Type of content (cleartext)              │
//	│  authenticated_data   - Additional authenticated data (cleartext)│
//	│  encrypted_sender_data - Encrypted sender identification         │
//	│  ciphertext           - Encrypted content + auth data            │
//	└─────────────────────────────────────────────────────────────────┘
//
// # Content Authentication (RFC 9420 §6.1)
//
// All MLS messages are authenticated through a two-layer scheme:
//
//  1. Signature: Binds the message to the sender's identity using SignWithLabel
//     with label "FramedContentTBS". The signed content includes the GroupContext
//     for member senders, ensuring signatures are epoch-specific.
//
//  2. Membership Tag: A MAC computed over the authenticated content proves the
//     sender is a current member of the group. This prevents external parties
//     from injecting messages even if they possess valid credentials.
//
// Why two layers? The signature provides non-repudiation and binds to identity,
// while the membership tag provides efficient online verification that the sender
// is currently a member of the specific epoch.
//
// # Sender Data Encryption (RFC 9420 §6.3.2)
//
// PrivateMessages encrypt sender metadata separately from content to hide:
//
//   - Which member sent the message (leaf_index)
//   - The generation of the key used (for replay detection)
//   - Reuse guard (4 random bytes to prevent nonce reuse)
//
// The sender data is encrypted with a key derived from sender_data_secret and
// a sample of the ciphertext, ensuring the decryption key is bound to the
// specific message.
//
// # Key Schedule Integration
//
// The framing layer derives encryption keys from the SecretTree (RFC 9420 §9),
// which provides per-sender key ratchets for both handshake and application
// messages. Each message consumes one generation from the ratchet, and the
// reuse_guard XORs with the first 4 bytes of the nonce to prevent catastrophic
// key reuse if state is lost.
//
//	┌─────────────────┐
//	│  SecretTree     │
//	│  ├─ handshake   │──► Key Ratchet (per sender)
//	│  └─ application │──► Key Ratchet (per sender)
//	└────────┬────────┘
//	         │
//	         ▼
//	┌─────────────────┐
//	│  Generation N   │──► Key + Nonce
//	│  XOR reuse_guard│      │
//	└─────────────────┘      ▼
//	                    AEAD Encrypt
//
// # Security Properties
//
// Forward Secrecy: Each epoch derives independent encryption keys. Compromise
// of epoch N keys does not reveal messages from epoch N-1.
//
// Post-Compromise Security: The key schedule injects fresh entropy via commits,
// ensuring that compromised keys are eventually replaced with uncompromised ones.
//
// Message Authentication: All messages are signed by the sender and include
// epoch-specific context, preventing replay across epochs or groups.
//
// Membership Verification: The membership_tag proves the sender possessed the
// membership_key for the current epoch, preventing message injection by
// non-members.
//
// # Usage
//
// Creating a PublicMessage (for handshake transparency):
//
//	content := framing.FramedContent{...}
//	pm, err := framing.NewPublicMessage(content, sigKey, groupContext, membershipKey, cs)
//
// Creating a PrivateMessage (for confidentiality):
//
//	params := framing.EncryptParams{...}
//	pm, err := framing.EncryptPrivateMessage(content, sigKey, params)
//
// Processing received messages:
//
//	ac, err := msg.VerifySignature(sigPubKey, cs)
//	err = msg.VerifyMembershipTag(cs, membershipKey)
//
// # References
//
//   - RFC 9420 §6: Message Framing
//   - RFC 9420 §6.1: Content Authentication
//   - RFC 9420 §6.2: Public Messages
//   - RFC 9420 §6.3: Private Messages
//   - RFC 9420 §9: Secret Tree
package framing
