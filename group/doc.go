// Package group implements MLS Group Management according to RFC 9420 §11-12.
//
// This package provides functionality for creating and managing MLS groups,
// handling proposals (Add, Update, Remove), creating and processing commits,
// and managing the ratchet tree and key schedule.
//
// # Group Lifecycle
//
// ```text
// ┌─────────────┐    Create/Welcome    ┌─────────────┐
// │   Start     │ ───────────────────► │  Group      │
// └─────────────┘                      │  Epoch 0    │
//
//	└──────┬──────┘
//	       │ Proposals
//	       ▼
//	┌─────────────┐
//	│   Commit    │
//	│  Epoch N+1  │
//	└─────────────┘
//
// ```
//
// # Security Properties
//
// MLS provides two main security guarantees:
//
//   - Forward Secrecy (FS): Compromise of current keys does not reveal
//     past messages. Achieved through ratchet tree updates (RFC §4).
//
//   - Post-Compromise Security (PCS): After compromise, group members can
//     recover security through updates. Achieved by updating leaf keys
//     and rotating path secrets (RFC §12.4).
//
// # RFC References
//
//   - RFC 9420 §4: Ratchet Tree - Tree structure and operations
//   - RFC 9420 §8: Key Schedule - Epoch secret derivation
//   - RFC 9420 §11: Group Creation - Welcome, GroupInfo
//   - RFC 9420 §12: Group Evolution - Proposals, Commits
//
// # Implementation Notes
//
// This implementation follows the RFC 9420 specification for MLS 1.0.
// All wire format encoding uses the TLS presentation language (RFC 8446 §3).
package group
