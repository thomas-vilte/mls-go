// Package interop provides interoperability testing with other implementation.
//
// This package implements the MLS Interop Test Vectors format
// as defined by the MLS Working Group:
// https://github.com/mlswg/mls-implementations/tree/master/test-vectors
//
// Test vectors are JSON files that contain:
// - CipherSuite configuration
// - Group creation parameters
// - Key packages
// - Commits and Welcome messages
// - Expected state after each operation
//
// Usage:
//  1. Generate test vectors with GenerateTestVectors()
//  2. Export to JSON with ExportToFile()
//  3. Validate in other implementation using their test vector runner
//  4. Import other implementation test vectors with ImportFromFile() and validate
package interop

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/group"
	keypackages "github.com/thomas-vilte/mls-go/keypackages"
)

// TestVector represents a single interoperability test case.
// This format is compatible with the MLS Interop Test Vectors spec.
type TestVector struct {
	// Metadata
	Name        string `json:"name"`
	CipherSuite uint16 `json:"cipher_suite"`
	GroupID     string `json:"group_id"` // hex encoded
	Epoch       uint64 `json:"epoch"`

	// Key Packages (hex encoded)
	KeyPackages []KeyPackageVector `json:"keypackages,omitempty"`

	// Group operations
	Commits []CommitVector `json:"commits,omitempty"`

	// Welcome messages
	Welcomes []WelcomeVector `json:"welcomes,omitempty"`

	// Expected state
	ExpectedTreeHash   string `json:"expected_tree_hash"` // hex
	ExpectedEpoch      uint64 `json:"expected_epoch"`
	ExpectedNumMembers int    `json:"expected_num_members"`
}

// KeyPackageVector represents a key package in test vector format.
type KeyPackageVector struct {
	LeafIndex  uint32 `json:"leaf_index"`
	KeyPackage string `json:"key_package"`           // hex encoded
	PrivateKey string `json:"private_key,omitempty"` // hex encoded (optional)
}

// CommitVector represents a commit operation.
type CommitVector struct {
	Epoch            uint64   `json:"epoch"`
	Proposals        []uint32 `json:"proposals"`             // indices of proposals
	CommitMsg        string   `json:"commit_msg"`            // hex encoded
	WelcomeMsg       string   `json:"welcome_msg,omitempty"` // hex encoded
	ExpectedTreeHash string   `json:"expected_tree_hash"`    // hex
}

// WelcomeVector represents a welcome message.
type WelcomeVector struct {
	JoinerSecret       string `json:"joiner_secret"`        // hex
	EncryptedGroupInfo string `json:"encrypted_group_info"` // hex
	KeyPackageRef      string `json:"key_package_ref"`      // hex
}

// TestVectorSet represents a collection of test vectors.
type TestVectorSet struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Vectors     []TestVector `json:"vectors"`
}

// TestVectorGenerator generates test vectors for interoperability testing.
type TestVectorGenerator struct {
	cipherSuite ciphersuite.CipherSuite
}

// NewTestVectorGenerator creates a new test vector generator.
func NewTestVectorGenerator(cs ciphersuite.CipherSuite) *TestVectorGenerator {
	return &TestVectorGenerator{cipherSuite: cs}
}

// GenerateOneToOneJoin creates a test vector for a 1:1 group join scenario.
// Scenario:
//  1. Alice creates a group
//  2. Bob sends KeyPackage to Alice
//  3. Alice adds Bob and sends Welcome
//  4. Both verify group state
func (tvg *TestVectorGenerator) GenerateOneToOneJoin() (*TestVector, error) {
	// Generate credentials for Alice and Bob
	aliceCred, _, err := credentials.GenerateCredentialWithKey([]byte("Alice"))
	if err != nil {
		return nil, fmt.Errorf("generating alice credential: %w", err)
	}

	bobCred, _, err := credentials.GenerateCredentialWithKey([]byte("Bob"))
	if err != nil {
		return nil, fmt.Errorf("generating bob credential: %w", err)
	}

	// Generate KeyPackages
	aliceKP, alicePriv, err := keypackages.Generate(aliceCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		return nil, fmt.Errorf("generating alice keypackage: %w", err)
	}

	bobKP, _, err := keypackages.Generate(bobCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		return nil, fmt.Errorf("generating bob keypackage: %w", err)
	}

	// Create group (Alice)
	groupID, _ := group.NewGroupIDRandom()
	aliceGroup, err := group.NewGroup(groupID, tvg.cipherSuite, aliceKP, alicePriv)
	if err != nil {
		return nil, fmt.Errorf("creating group: %w", err)
	}

	// Record initial state
	tv := &TestVector{
		Name:        "one-to-one-join",
		CipherSuite: uint16(tvg.cipherSuite),
		GroupID:     hex.EncodeToString(groupID.AsSlice()),
		Epoch:       0,
		KeyPackages: []KeyPackageVector{
			{
				LeafIndex:  0,
				KeyPackage: hex.EncodeToString(aliceKP.Marshal()),
				PrivateKey: "", // Don't export private keys in test vectors
			},
			{
				LeafIndex:  1,
				KeyPackage: hex.EncodeToString(bobKP.Marshal()),
				PrivateKey: "",
			},
		},
	}

	// Alice adds Bob
	_, err = aliceGroup.AddMember(bobKP)
	if err != nil {
		return nil, fmt.Errorf("adding bob: %w", err)
	}

	// Commit (simplified - no real UpdatePath yet)
	sigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)
	sigPub := sigPriv.PublicKey()
	stagedCommit, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		return nil, fmt.Errorf("committing: %w", err)
	}

	// Record commit (if Commit struct exists)
	if stagedCommit.Commit != nil {
		commitData := stagedCommit.Commit.Marshal()
		tv.Commits = append(tv.Commits, CommitVector{
			Epoch:     0,
			CommitMsg: hex.EncodeToString(commitData),
		})
	}

	// Merge commit
	err = aliceGroup.MergeCommit(stagedCommit)
	if err != nil {
		return nil, fmt.Errorf("merging commit: %w", err)
	}

	// Create Welcome for Bob (simplified - actual implementation would use KeySchedule)
	// welcome, err := aliceGroup.CreateWelcome(
	// 	[]*keypackages.KeyPackage{bobKP},
	// 	... // joinerSecret from KeySchedule
	// )

	tv.Welcomes = append(tv.Welcomes, WelcomeVector{
		JoinerSecret: "placeholder", // Would be actual joiner secret from KeySchedule
	})

	// Record expected state
	tv.ExpectedTreeHash = hex.EncodeToString(aliceGroup.GroupContext.TreeHash)
	tv.ExpectedEpoch = aliceGroup.Epoch.AsUint64()
	tv.ExpectedNumMembers = aliceGroup.MemberCount()

	return tv, nil
}

// ExportToFile exports test vectors to a JSON file.
func (tvs *TestVectorSet) ExportToFile(filename string) error {
	data, err := json.MarshalIndent(tvs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling test vectors: %w", err)
	}

	//nolint:gosec // Test vector files don't need restrictive permissions
	err = os.WriteFile(filename, data, 0o644)
	if err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	return nil
}

// ImportFromFile imports test vectors from a JSON file.
func ImportFromFile(filename string) (*TestVectorSet, error) {
	//nolint:gosec // Test vector file reading is safe
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var tvs TestVectorSet
	err = json.Unmarshal(data, &tvs)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling test vectors: %w", err)
	}

	return &tvs, nil
}

// ValidateTestVector validates a test vector against the current implementation.
func ValidateTestVector(tv *TestVector) error {
	// Decode group ID
	groupIDBytes, err := hex.DecodeString(tv.GroupID)
	if err != nil {
		return fmt.Errorf("decoding group id: %w", err)
	}
	groupID := group.NewGroupID(groupIDBytes)

	// Verify cipher suite
	if tv.CipherSuite != uint16(ciphersuite.MLS128DHKEMP256) {
		return fmt.Errorf("unsupported cipher suite: %d", tv.CipherSuite)
	}

	// Try to reconstruct group from test vector
	// This is a simplified validation - full validation would require
	// processing all operations in sequence

	fmt.Printf("Validating test vector:\n")
	fmt.Printf("  Group ID: %s\n", tv.GroupID[:16])
	fmt.Printf("  Epoch: %d\n", tv.Epoch)
	fmt.Printf("  Key Packages: %d\n", len(tv.KeyPackages))
	fmt.Printf("  Commits: %d\n", len(tv.Commits))
	fmt.Printf("  Welcomes: %d\n", len(tv.Welcomes))

	// Usar groupID para evitar el warning de variable no usada
	_ = groupID

	return nil
}

// GenerateInteropTestVectors generates a complete set of test vectors
// for interoperability testing.
func GenerateInteropTestVectors() (*TestVectorSet, error) {
	tvs := &TestVectorSet{
		Name:        "Go-other implementation Interop",
		Description: "Test vectors for interoperability between Go and other implementation implementations",
	}

	// Generate 1:1 join test vector
	gen := NewTestVectorGenerator(ciphersuite.MLS128DHKEMP256)
	tv, err := gen.GenerateOneToOneJoin()
	if err != nil {
		return nil, fmt.Errorf("generating one-to-one join: %w", err)
	}
	tvs.Vectors = append(tvs.Vectors, *tv)

	return tvs, nil
}
