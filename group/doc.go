// Package group implements MLS Group Management according to RFC 9420 §11-12.
//
// # Overview
//
// An MLS group is a set of members that share a common epoch secret, which is
// used to derive per-message encryption keys. The group evolves through epochs:
// each commit advances the epoch and rotates the shared key material.
//
// The entry point is [NewGroup] (creator) or [JoinFromWelcome] (joiner).
// For external joins (no Welcome), use [NewGroupFromExternalCommit].
//
// # Group Lifecycle (RFC 9420 §11-12)
//
//	                       ┌───────────────────────────────────────┐
//	                       │           RFC 9420 Group Lifecycle    │
//	                       └───────────────────────────────────────┘
//
//	Alice                              Bob
//	  │                                 │
//	  │  NewGroup()                     │  FreshKeyPackage()
//	  │  ───────────────────────────►   │  ◄────────────────
//	  │         (KeyPackage)            │
//	  │                                 │
//	  │  AddMember(bobKP)               │
//	  │  Commit() ──► StagedCommit      │
//	  │  MergeCommit(staged)            │
//	  │                                 │
//	  │  CreateWelcome() ──────────────►│  JoinFromWelcome()
//	  │                                 │
//	  │  ◄─────────── Epoch 1 ─────────►│
//	  │                                 │
//	  │  SendMessage() ────────────────►│  ReceiveApplicationMessage()
//	  │                                 │
//	  │  AddMember(carolKP)             │
//	  │  Commit()                       │  ProcessPublicMessage(commit)
//	  │  ◄─────────── Epoch 2 ─────────►│
//
// # Proposal-Commit Flow (RFC 9420 §12.1, §12.4)
//
// Proposals accumulate locally before being committed. A commit bundles all
// pending proposals into a single authenticated operation that advances the epoch.
//
//	┌─────────────────────────────────────────────────────────────┐
//	│                   Proposal-Commit Model                     │
//	├─────────────────────────────────────────────────────────────┤
//	│                                                             │
//	│  AddMember(kp)    ──► Proposal{Add}    ─┐                   │
//	│  RemoveMember(i)  ──► Proposal{Remove} ─┤──► proposals[]    │
//	│  SelfUpdate()     ──► Proposal{Update} ─┘                   │
//	│                                          │                   │
//	│  Commit() ──────────────────────────────►│                   │
//	│    1. Bundles all pending proposals       │                   │
//	│    2. Generates UpdatePath (TreeKEM)      │                   │
//	│    3. Derives new epoch secrets           │                   │
//	│    4. Returns StagedCommit                │                   │
//	│                                           │                   │
//	│  MergeCommit(staged) ───────────────────► advances epoch     │
//	│                                                             │
//	└─────────────────────────────────────────────────────────────┘
//
// # Staged Commit (RFC 9420 §14)
//
// For Delivery Service (DS) conflict resolution, use the staged commit API.
// The commit is generated but not applied until the DS confirms acceptance:
//
//	┌─────────────────────────────────────────────────────────────┐
//	│                  Staged Commit Flow (§14)                   │
//	├─────────────────────────────────────────────────────────────┤
//	│                                                             │
//	│  Commit() ──────────────────────────────► StagedCommit      │
//	│    (state = StatePendingCommit)                             │
//	│              │                                              │
//	│    ┌─────────┴─────────┐                                    │
//	│    │                   │                                    │
//	│  DS accepts          DS rejects                             │
//	│    │                   │                                    │
//	│  MergeCommit()    DiscardPendingCommit()                    │
//	│  (epoch N+1)      (epoch N, proposals preserved)            │
//	│                                                             │
//	└─────────────────────────────────────────────────────────────┘
//
// # TreeKEM — UpdatePath Encryption (RFC 9420 §7.6, §12.4.2)
//
// When a member commits with an UpdatePath, new path secrets are encrypted
// for each node in the filtered copath. This implementation parallelizes the
// HPKE encryption operations — one goroutine per copath level — while keeping
// secret derivation and tree mutation sequential:
//
//	Direct path from committer to root:
//	(L = own leaf, P = parent, R = root, C = copath node)
//
//	       R
//	      / \
//	     P   C3          ← encrypt pathSecret[3] to C3's resolution
//	    / \
//	   P   C2            ← encrypt pathSecret[2] to C2's resolution  ┐ parallel
//	  / \                                                              │
//	 L   C1              ← encrypt pathSecret[1] to C1's resolution  ┘
//
//	Cost: O(log N) HPKE operations, parallelized across CPU cores.
//	Sequential fallback is not applied — goroutine overhead is negligible
//	even for small groups on modern runtimes.
//
// # Security Properties
//
// MLS provides two fundamental security guarantees (RFC 9420 §1.2):
//
//   - Forward Secrecy (FS): each epoch derives independent keys; compromising
//     current keys reveals nothing about past messages.
//
//   - Post-Compromise Security (PCS): after a member is compromised, a commit
//     with UpdatePath refreshes the key material for the entire group, healing
//     the compromise for future messages.
//
// # Key RFC References
//
//   - §4:  Ratchet Tree — binary tree structure, leaf and parent nodes
//   - §7:  Tree Operations — blank nodes, resolution, tree hashing (§7.8), parent hash (§7.9)
//   - §8:  Key Schedule — epoch secret derivation chain
//   - §11: Group Creation — Welcome, GroupInfo, initial tree
//   - §12: Group Evolution — proposals (§12.1), commits (§12.4), UpdatePath (§12.4.2)
//   - §14: Handling Message Loss — staged commit and DS conflict model
//   - §16: Security Considerations — FS, PCS, deniability limitations
package group
