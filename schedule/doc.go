// Package schedule implements the MLS Key Schedule according to RFC 9420 §8.
//
// # Overview
//
// The Key Schedule is the cryptographic engine that derives all shared secrets
// for an MLS group. It provides forward secrecy and post-compromise security
// by ensuring that each epoch has independent encryption keys derived from
// fresh entropy introduced by commits.
//
// # Key Schedule Flow (RFC 9420 §8, Figure 22)
//
// The complete key schedule for a new epoch:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                    Key Schedule Overview                        │
//	├─────────────────────────────────────────────────────────────────┤
//	│                                                                 │
//	│  init_secret_[n-1] (from previous epoch)                        │
//	│      │                                                          │
//	│      │  HKDF-Extract(init_secret, commit_secret)                │
//	│      ▼                                                          │
//	│  intermediate_secret                                            │
//	│      │                                                          │
//	│      │  ExpandWithLabel(intermediate, "joiner", GroupContext)   │
//	│      ▼                                                          │
//	│  joiner_secret                                                  │
//	│      │                                                          │
//	│      │  HKDF-Extract(joiner_secret, psk_secret)                 │
//	│      ▼                                                          │
//	│  member_secret                                                  │
//	│      │                                                          │
//	│      │  ExpandWithLabel(member_secret, "epoch", GroupContext)   │
//	│      ▼                                                          │
//	│  epoch_secret ──┬──► DeriveSecret("sender data")                │
//	│                 ├──► DeriveSecret("encryption")                 │
//	│                 ├──► DeriveSecret("exporter")                   │
//	│                 ├──► DeriveSecret("authentication")             │
//	│                 ├──► DeriveSecret("confirm")                    │
//	│                 ├──► DeriveSecret("membership")                 │
//	│                 ├──► DeriveSecret("external")                   │
//	│                 ├──► DeriveSecret("resumption")                 │
//	│                 └──► DeriveSecret("init") ──► init_secret_[n]   │
//	│                                                                 │
//	└─────────────────────────────────────────────────────────────────┘
//
// # Key Schedule Inputs
//
// The key schedule takes three inputs to derive epoch secrets:
//
//  1. init_secret_[n-1]: From the previous epoch (or all zeros for epoch 0)
//  2. commit_secret: Fresh entropy from the current commit (UpdatePath)
//  3. GroupContext[n]: The current epoch's group context
//
// Optional fourth input:
//
//  4. psk_secret: Pre-shared keys (RFC 9420 §8.4) for external/resumption PSKs
//
// # Detailed Key Schedule Structure (RFC 9420 Figure 22)
//
//	                   init_secret_[n-1]
//	                         │
//	                         │
//	                         V
//	commit_secret ──► KDF.Extract
//	                         │
//	                         │
//	                         V
//	             ExpandWithLabel(., "joiner", GroupContext_[n], KDF.Nh)
//	                         │
//	                         │
//	                         V
//	                    joiner_secret
//	                         │
//	                         │
//	                         V
//	psk_secret (or 0) ──► KDF.Extract
//	                         │
//	                         │
//	                         +──► DeriveSecret(., "welcome")
//	                         │    = welcome_secret
//	                         │
//	                         V
//	             ExpandWithLabel(., "epoch", GroupContext_[n], KDF.Nh)
//	                         │
//	                         │
//	                         V
//	                    epoch_secret
//	                         │
//	                         │
//	                         +──► DeriveSecret(., <label>)
//	                         │    = <secret>
//	                         │
//	                         V
//	                   DeriveSecret(., "init")
//	                         │
//	                         │
//	                         V
//	                   init_secret_[n]
//
// # Epoch-Derived Secrets (RFC 9420 Table 4)
//
// From epoch_secret, the following secrets are derived:
//
//	┌────────────────────┬─────────────────────┬─────────────────────────────────────┐
//	│ Label              │ Secret              │ Purpose                             │
//	├────────────────────┼─────────────────────┼─────────────────────────────────────┤
//	│ "sender data"      │ sender_data_secret  │ Encrypt sender metadata in Private  │
//	│                    │                     │ Messages (hides sender identity)    │
//	├────────────────────┼─────────────────────┼─────────────────────────────────────┤
//	│ "encryption"       │ encryption_secret   │ Derive message encryption keys via  │
//	│                    │                     │ the secret tree (per-sender keys)   │
//	├────────────────────┼─────────────────────┼─────────────────────────────────────┤
//	│ "exporter"         │ exporter_secret     │ Export secrets to other protocols   │
//	│                    │                     │ (RFC 9420 §8.5)                     │
//	├────────────────────┼─────────────────────┼─────────────────────────────────────┤
//	│ "external"         │ external_secret     │ Derive HPKE key pair for external   │
//	│                    │                     │ commits (non-members can join)      │
//	├────────────────────┼─────────────────────┼─────────────────────────────────────┤
//	│ "confirm"          │ confirmation_key    │ Compute confirmation_tag to verify  │
//	│                    │                     │ all members have same group state   │
//	├────────────────────┼─────────────────────┼─────────────────────────────────────┤
//	│ "membership"       │ membership_key      │ Compute membership_tag for public   │
//	│                    │                     │ messages (proves group membership)  │
//	├────────────────────┼─────────────────────┼─────────────────────────────────────┤
//	│ "resumption"       │ resumption_psk      │ Prove membership in this epoch via  │
//	│                    │                     │ PSK injection (reinit, branch)      │
//	├────────────────────┼─────────────────────┼─────────────────────────────────────┤
//	│ "authentication"   │ epoch_authenticator │ Confirm two clients have same view  │
//	│                    │                     │ of the group (binding transcript)   │
//	└────────────────────┴─────────────────────┴─────────────────────────────────────┘
//
// # Design Rationale
//
// **Why HKDF Extract-Then-Expand?**
//
// The key schedule uses HKDF in two phases:
//  1. Extract: Combines high-entropy secrets (init_secret + commit_secret)
//     into a fixed-length pseudorandom key.
//  2. Expand: Derives multiple independent keys from that PRK.
//
// This provides domain separation: each secret is derived with a unique label,
// ensuring that compromising one secret doesn't compromise others.
//
// **Why GroupContext in every derivation?**
//
// The GroupContext binds all derived secrets to the specific group, epoch,
// and transcript hash. This prevents:
//   - Cross-group attacks (secrets can't be reused across groups)
//   - Replay attacks (secrets are epoch-specific)
//   - Forking attacks (secrets bind to the full history via transcript hash)
//
// **Why init_secret chains across epochs?**
//
// The init_secret from epoch N becomes the input to epoch N+1. This creates
// a hash chain where compromising epoch N+1 doesn't reveal epoch N-1 secrets
// (forward secrecy), and each commit introduces fresh entropy (post-compromise
// security).
//
// # Key Schedule State Machine
//
// The KeySchedule must be used in order:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│              KeySchedule State Machine                          │
//	├─────────────────────────────────────────────────────────────────┤
//	│                                                                 │
//	│  1. NewKeySchedule(initSecret)                                  │
//	│     │   Create with previous init_secret                        │
//	│     ▼                                                           │
//	│  2. SetCommitSecret(commitSecret)                               │
//	│     │   Set fresh entropy from commit                           │
//	│     ▼                                                           │
//	│  3. ComputeJoinerSecret(groupContext)                           │
//	│     │   Derive joiner_secret                                    │
//	│     ▼                                                           │
//	│  4. ComputePskSecret(psks)                                      │
//	│     │   Optional: mix in PSKs                                   │
//	│     ▼                                                           │
//	│  5. ComputeEpochSecret(groupContext)                            │
//	│     │   Derive epoch_secret                                     │
//	│     ▼                                                           │
//	│  6. DeriveEpochSecrets()                                        │
//	│     │   Derive all epoch secrets                                │
//	│     ▼                                                           │
//	│  7. Use secrets for encryption, MACs, etc.                      │
//	│                                                                 │
//	└─────────────────────────────────────────────────────────────────┘
//
// # Pre-Shared Keys (RFC 9420 §8.4)
//
// PSKs can be injected into the key schedule for:
//   - External PSKs: Application-defined pre-shared keys
//   - Resumption PSKs: Prove membership in a previous epoch
//   - Branch PSKs: Link a new group to an existing one
//
// Multiple PSKs are combined using iterated HKDF-Extract:
//
//	psk_secret_0 = 0^Nh
//	psk_secret_i = HKDF-Extract(psk_input[i], psk_secret_{i-1})
//	psk_secret   = psk_secret_n
//
// # Exporters (RFC 9420 §8.5)
//
// The exporter_secret allows other protocols to derive keys from MLS:
//
//	MLS-Exporter(Label, Context, Length) =
//	    ExpandWithLabel(
//	        DeriveSecret(exporter_secret, Label),
//	        "exporter", Hash(Context), Length)
//
// This is useful for applications that need to derive their own keys
// while ensuring they're cryptographically bound to the MLS group state.
//
// # Usage
//
// Creating a key schedule for a new epoch:
//
//	ks := schedule.NewKeySchedule(
//	    cs,                    // Cipher suite
//	    prevEpochSecrets.InitSecret, // init_secret from previous epoch
//	)
//	ks.SetCommitSecret(commitSecret)  // Fresh entropy from UpdatePath
//
//	joinerSecret, err := ks.ComputeJoinerSecret(groupContext)
//	if err != nil {
//	    return err
//	}
//
//	memberSecret, err := ks.ComputePskSecret(nil) // No PSKs
//	if err != nil {
//	    return err
//	}
//
//	epochSecret, err := ks.ComputeEpochSecret(groupContext)
//	if err != nil {
//	    return err
//	}
//
//	secrets, err := ks.DeriveEpochSecrets()
//	if err != nil {
//	    return err
//	}
//
//	// Use secrets.EncryptionSecret for the secret tree
//	// Use secrets.ConfirmationKey for confirmation_tag
//	// Use secrets.MembershipKey for membership_tag
//
// Computing confirmation_tag:
//
//	confirmationTag := schedule.ComputeConfirmationTag(
//	    cs,
//	    secrets.ConfirmationKey.AsSlice(),
//	    confirmedTranscriptHash,
//	)
//
// Exporting a secret for external use:
//
//	exported, err := schedule.Exporter(
//	    secrets.ExporterSecret,
//	    cs,
//	    schedule.ExporterLabelAuthenticationKey,
//	    []byte("app-context"),
//	    32,
//	)
//
// # Security Properties
//
// **Forward Secrecy:** Each epoch uses fresh commit_secret entropy. Compromise
// of epoch N keys doesn't reveal epoch N-1 keys because init_secret chains
// but doesn't expose previous secrets.
//
// **Post-Compromise Security:** Each commit introduces fresh entropy via
// commit_secret, so compromised keys are eventually replaced with uncompromised
// ones after enough epochs.
//
// **Domain Separation:** Each secret has a unique label. The same HKDF PRK
// produces independent secrets for different purposes.
//
// **Context Binding:** Every derivation includes GroupContext, binding secrets
// to the specific group, epoch, and history.
//
// # References
//
//   - RFC 9420 §8: Key Schedule
//   - RFC 9420 §8.1: Group Context
//   - RFC 9420 §8.2: Transcript Hashes
//   - RFC 9420 §8.3: External Initialization
//   - RFC 9420 §8.4: Pre-Shared Keys
//   - RFC 9420 §8.5: Exporters
//   - RFC 9420 §8.6: Resumption PSK
//   - RFC 9420 §8.7: Epoch Authenticators
//   - RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
package schedule
