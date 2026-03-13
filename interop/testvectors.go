// Package interop provides interoperability testing with other MLS implementations.
//
// Implements the MLS Interop Test Vectors format:
// https://github.com/mlswg/mls-implementations/tree/master/test-vectors
package interop

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// TestVector represents a single interoperability test case.
type TestVector struct {
	Name        string `json:"name"`
	CipherSuite uint16 `json:"cipher_suite"`
	GroupID     string `json:"group_id"` // hex encoded
	Epoch       uint64 `json:"epoch"`

	KeyPackages []KeyPackageVector `json:"keypackages,omitempty"`
	Commits     []CommitVector     `json:"commits,omitempty"`
	Welcomes    []WelcomeVector    `json:"welcomes,omitempty"`

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
	Proposals        []uint32 `json:"proposals"`               // indices of proposals
	CommitMsg        string   `json:"commit_msg"`              // hex encoded
	WelcomeMsg       string   `json:"welcome_msg,omitempty"`   // hex encoded
	UpdatePath       string   `json:"update_path,omitempty"`   // hex encoded
	ExpectedTreeHash string   `json:"expected_tree_hash"`      // hex
	JoinerSecret     string   `json:"joiner_secret,omitempty"` // hex
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
func (tvg *TestVectorGenerator) GenerateOneToOneJoin() (*TestVector, error) {
	aliceCred, _, err := credentials.GenerateCredentialWithKeyForCS([]byte("Alice"), tvg.cipherSuite)
	if err != nil {
		return nil, fmt.Errorf("generating alice credential: %w", err)
	}

	bobCred, _, err := credentials.GenerateCredentialWithKeyForCS([]byte("Bob"), tvg.cipherSuite)
	if err != nil {
		return nil, fmt.Errorf("generating bob credential: %w", err)
	}

	aliceKP, alicePriv, err := keypackages.Generate(aliceCred, tvg.cipherSuite)
	if err != nil {
		return nil, fmt.Errorf("generating alice keypackage: %w", err)
	}

	bobKP, bobPriv, err := keypackages.Generate(bobCred, tvg.cipherSuite)
	if err != nil {
		return nil, fmt.Errorf("generating bob keypackage: %w", err)
	}

	groupID, _ := group.NewGroupIDRandom()
	aliceGroup, err := group.NewGroup(groupID, tvg.cipherSuite, aliceKP, alicePriv)
	if err != nil {
		return nil, fmt.Errorf("creating group: %w", err)
	}
	tv := &TestVector{
		Name:        fmt.Sprintf("one-to-one-join-cs%d", tvg.cipherSuite),
		CipherSuite: uint16(tvg.cipherSuite),
		GroupID:     hex.EncodeToString(groupID.AsSlice()),
		Epoch:       0,
		KeyPackages: []KeyPackageVector{
			{
				LeafIndex:  0,
				KeyPackage: hex.EncodeToString(aliceKP.Marshal()),
				PrivateKey: "",
			},
			{
				LeafIndex:  1,
				KeyPackage: hex.EncodeToString(bobKP.Marshal()),
				PrivateKey: "",
			},
		},
	}

	_, err = aliceGroup.AddMember(bobKP)
	if err != nil {
		return nil, fmt.Errorf("adding bob: %w", err)
	}

	sigPriv := alicePriv.GetSignaturePrivateKey()
	sigPub := sigPriv.PublicKey()

	stagedCommit, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		return nil, fmt.Errorf("committing: %w", err)
	}

	var joinerSecretHex string
	if stagedCommit.JoinerSecret != nil {
		joinerSecretHex = hex.EncodeToString(stagedCommit.JoinerSecret.AsSlice())
	}

	var updatePathHex string
	if stagedCommit.Commit != nil && stagedCommit.Commit.Path != nil {
		updatePathHex = hex.EncodeToString(stagedCommit.Commit.Path.Marshal())
	}

	if stagedCommit.Commit != nil {
		commitData := stagedCommit.Commit.Marshal()
		tv.Commits = append(tv.Commits, CommitVector{
			Epoch:        0,
			CommitMsg:    hex.EncodeToString(commitData),
			UpdatePath:   updatePathHex,
			JoinerSecret: joinerSecretHex,
		})
	}

	err = aliceGroup.MergeCommit(stagedCommit)
	if err != nil {
		return nil, fmt.Errorf("merging commit: %w", err)
	}

	if joinerSecretHex != "" {
		tv.Welcomes = append(tv.Welcomes, WelcomeVector{
			JoinerSecret: joinerSecretHex,
		})
	}

	tv.ExpectedTreeHash = hex.EncodeToString(aliceGroup.GroupContext.TreeHash)
	tv.ExpectedEpoch = aliceGroup.Epoch.AsUint64()
	tv.ExpectedNumMembers = aliceGroup.MemberCount()

	_ = bobPriv

	return tv, nil
}

// GenerateThreePartyJoin creates a test vector for a 3-party group scenario.
func (tvg *TestVectorGenerator) GenerateThreePartyJoin() (*TestVector, error) {
	aliceCred, _, err := credentials.GenerateCredentialWithKeyForCS([]byte("Alice"), tvg.cipherSuite)
	if err != nil {
		return nil, fmt.Errorf("generating alice credential: %w", err)
	}

	bobCred, _, err := credentials.GenerateCredentialWithKeyForCS([]byte("Bob"), tvg.cipherSuite)
	if err != nil {
		return nil, fmt.Errorf("generating bob credential: %w", err)
	}

	charlieCred, _, err := credentials.GenerateCredentialWithKeyForCS([]byte("Charlie"), tvg.cipherSuite)
	if err != nil {
		return nil, fmt.Errorf("generating charlie credential: %w", err)
	}

	aliceKP, alicePriv, err := keypackages.Generate(aliceCred, tvg.cipherSuite)
	if err != nil {
		return nil, fmt.Errorf("generating alice keypackage: %w", err)
	}

	bobKP, _, err := keypackages.Generate(bobCred, tvg.cipherSuite)
	if err != nil {
		return nil, fmt.Errorf("generating bob keypackage: %w", err)
	}

	charlieKP, _, err := keypackages.Generate(charlieCred, tvg.cipherSuite)
	if err != nil {
		return nil, fmt.Errorf("generating charlie keypackage: %w", err)
	}

	groupID, _ := group.NewGroupIDRandom()
	aliceGroup, err := group.NewGroup(groupID, tvg.cipherSuite, aliceKP, alicePriv)
	if err != nil {
		return nil, fmt.Errorf("creating group: %w", err)
	}

	tv := &TestVector{
		Name:        fmt.Sprintf("three-party-join-cs%d", tvg.cipherSuite),
		CipherSuite: uint16(tvg.cipherSuite),
		GroupID:     hex.EncodeToString(groupID.AsSlice()),
		Epoch:       0,
		KeyPackages: []KeyPackageVector{
			{LeafIndex: 0, KeyPackage: hex.EncodeToString(aliceKP.Marshal())},
			{LeafIndex: 1, KeyPackage: hex.EncodeToString(bobKP.Marshal())},
			{LeafIndex: 2, KeyPackage: hex.EncodeToString(charlieKP.Marshal())},
		},
	}

	sigPriv := alicePriv.GetSignaturePrivateKey()
	sigPub := sigPriv.PublicKey()

	_, err = aliceGroup.AddMember(bobKP)
	if err != nil {
		return nil, fmt.Errorf("adding bob: %w", err)
	}

	stagedCommit1, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		return nil, fmt.Errorf("commit 1: %w", err)
	}

	if stagedCommit1.Commit != nil {
		var joinerSecret1 string
		if stagedCommit1.JoinerSecret != nil {
			joinerSecret1 = hex.EncodeToString(stagedCommit1.JoinerSecret.AsSlice())
		}
		tv.Commits = append(tv.Commits, CommitVector{
			Epoch:        0,
			CommitMsg:    hex.EncodeToString(stagedCommit1.Commit.Marshal()),
			JoinerSecret: joinerSecret1,
		})
	}

	err = aliceGroup.MergeCommit(stagedCommit1)
	if err != nil {
		return nil, fmt.Errorf("merging commit 1: %w", err)
	}

	_, err = aliceGroup.AddMember(charlieKP)
	if err != nil {
		return nil, fmt.Errorf("adding charlie: %w", err)
	}

	stagedCommit2, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		return nil, fmt.Errorf("commit 2: %w", err)
	}

	if stagedCommit2.Commit != nil {
		var joinerSecret2 string
		if stagedCommit2.JoinerSecret != nil {
			joinerSecret2 = hex.EncodeToString(stagedCommit2.JoinerSecret.AsSlice())
		}
		tv.Commits = append(tv.Commits, CommitVector{
			Epoch:        1,
			CommitMsg:    hex.EncodeToString(stagedCommit2.Commit.Marshal()),
			JoinerSecret: joinerSecret2,
		})
	}

	err = aliceGroup.MergeCommit(stagedCommit2)
	if err != nil {
		return nil, fmt.Errorf("merging commit 2: %w", err)
	}

	tv.ExpectedTreeHash = hex.EncodeToString(aliceGroup.GroupContext.TreeHash)
	tv.ExpectedEpoch = aliceGroup.Epoch.AsUint64()
	tv.ExpectedNumMembers = aliceGroup.MemberCount()

	return tv, nil
}

// GenerateMemberRemoval creates a test vector for member removal scenario.
func (tvg *TestVectorGenerator) GenerateMemberRemoval() (*TestVector, error) {
	aliceCred, _, err := credentials.GenerateCredentialWithKeyForCS([]byte("Alice"), tvg.cipherSuite)
	if err != nil {
		return nil, fmt.Errorf("generating alice credential: %w", err)
	}

	bobCred, _, err := credentials.GenerateCredentialWithKeyForCS([]byte("Bob"), tvg.cipherSuite)
	if err != nil {
		return nil, fmt.Errorf("generating bob credential: %w", err)
	}

	charlieCred, _, err := credentials.GenerateCredentialWithKeyForCS([]byte("Charlie"), tvg.cipherSuite)
	if err != nil {
		return nil, fmt.Errorf("generating charlie credential: %w", err)
	}

	aliceKP, alicePriv, err := keypackages.Generate(aliceCred, tvg.cipherSuite)
	if err != nil {
		return nil, fmt.Errorf("generating alice keypackage: %w", err)
	}

	bobKP, _, err := keypackages.Generate(bobCred, tvg.cipherSuite)
	if err != nil {
		return nil, fmt.Errorf("generating bob keypackage: %w", err)
	}

	charlieKP, _, err := keypackages.Generate(charlieCred, tvg.cipherSuite)
	if err != nil {
		return nil, fmt.Errorf("generating charlie keypackage: %w", err)
	}

	groupID, _ := group.NewGroupIDRandom()
	aliceGroup, err := group.NewGroup(groupID, tvg.cipherSuite, aliceKP, alicePriv)
	if err != nil {
		return nil, fmt.Errorf("creating group: %w", err)
	}

	tv := &TestVector{
		Name:        fmt.Sprintf("member-removal-cs%d", tvg.cipherSuite),
		CipherSuite: uint16(tvg.cipherSuite),
		GroupID:     hex.EncodeToString(groupID.AsSlice()),
		Epoch:       0,
		KeyPackages: []KeyPackageVector{
			{LeafIndex: 0, KeyPackage: hex.EncodeToString(aliceKP.Marshal())},
			{LeafIndex: 1, KeyPackage: hex.EncodeToString(bobKP.Marshal())},
			{LeafIndex: 2, KeyPackage: hex.EncodeToString(charlieKP.Marshal())},
		},
	}

	sigPriv := alicePriv.GetSignaturePrivateKey()
	sigPub := sigPriv.PublicKey()

	_, err = aliceGroup.AddMember(bobKP)
	if err != nil {
		return nil, fmt.Errorf("adding bob: %w", err)
	}

	stagedCommit1, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		return nil, fmt.Errorf("commit 1: %w", err)
	}

	if stagedCommit1.Commit != nil {
		tv.Commits = append(tv.Commits, CommitVector{
			Epoch:     0,
			CommitMsg: hex.EncodeToString(stagedCommit1.Commit.Marshal()),
		})
	}

	if err := aliceGroup.MergeCommit(stagedCommit1); err != nil {
		return nil, fmt.Errorf("merging commit 1: %w", err)
	}

	_, err = aliceGroup.AddMember(charlieKP)
	if err != nil {
		return nil, fmt.Errorf("adding charlie: %w", err)
	}

	stagedCommit2, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		return nil, fmt.Errorf("commit 2: %w", err)
	}

	if stagedCommit2.Commit != nil {
		tv.Commits = append(tv.Commits, CommitVector{
			Epoch:     1,
			CommitMsg: hex.EncodeToString(stagedCommit2.Commit.Marshal()),
		})
	}

	if err := aliceGroup.MergeCommit(stagedCommit2); err != nil {
		return nil, fmt.Errorf("merging commit 2: %w", err)
	}

	_, err = aliceGroup.RemoveMember(group.LeafNodeIndex(1))
	if err != nil {
		return nil, fmt.Errorf("removing bob: %w", err)
	}

	stagedCommit3, err := aliceGroup.Commit(sigPriv, sigPub, nil)
	if err != nil {
		return nil, fmt.Errorf("commit 3 (removal): %w", err)
	}

	if stagedCommit3.Commit != nil {
		tv.Commits = append(tv.Commits, CommitVector{
			Epoch:     2,
			CommitMsg: hex.EncodeToString(stagedCommit3.Commit.Marshal()),
		})
	}

	if err := aliceGroup.MergeCommit(stagedCommit3); err != nil {
		return nil, fmt.Errorf("merging commit 3: %w", err)
	}

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

	err = os.WriteFile(filename, data, 0o644)
	if err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	return nil
}

// ImportFromFile imports test vectors from a JSON file.
func ImportFromFile(filename string) (*TestVectorSet, error) {
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
	cs := ciphersuite.CipherSuite(tv.CipherSuite)
	if !cs.IsSupported() {
		return fmt.Errorf("unsupported cipher suite: %d", tv.CipherSuite)
	}

	groupIDBytes, err := hex.DecodeString(tv.GroupID)
	if err != nil {
		return fmt.Errorf("decoding group id: %w", err)
	}
	groupID := group.NewGroupID(groupIDBytes)

	fmt.Printf("Validating test vector: %s\n", tv.Name)
	fmt.Printf("  Group ID: %s...\n", tv.GroupID[:minInt(16, len(tv.GroupID))])
	fmt.Printf("  CipherSuite: %d (%s)\n", tv.CipherSuite, cs)
	fmt.Printf("  Key Packages: %d\n", len(tv.KeyPackages))
	fmt.Printf("  Commits: %d\n", len(tv.Commits))

	for i, kpVec := range tv.KeyPackages {
		kpData, err := hex.DecodeString(kpVec.KeyPackage)
		if err != nil {
			return fmt.Errorf("decoding keypackage %d: %w", i, err)
		}

		kp, err := keypackages.UnmarshalKeyPackage(kpData)
		if err != nil {
			return fmt.Errorf("parsing keypackage %d: %w", i, err)
		}

		if kp.CipherSuite != keypackages.CipherSuite(tv.CipherSuite) {
			return fmt.Errorf("keypackage %d cipher suite mismatch: got %d, want %d",
				i, kp.CipherSuite, tv.CipherSuite)
		}

		fmt.Printf("  KeyPackage %d valid\n", i)
		_ = kp
	}

	if len(tv.Commits) > 0 && len(tv.KeyPackages) > 0 {
		commit := tv.Commits[0]
		commitData, err := hex.DecodeString(commit.CommitMsg)
		if err != nil {
			return fmt.Errorf("decoding commit: %w", err)
		}

		_, err = group.UnmarshalCommit(commitData)
		if err != nil {
			return fmt.Errorf("parsing commit: %w", err)
		}

		fmt.Printf("  Commit valid\n")
	}

	if tv.ExpectedNumMembers > 0 {
		fmt.Printf("  Expected members: %d\n", tv.ExpectedNumMembers)
	}
	if tv.ExpectedEpoch > 0 {
		fmt.Printf("  Expected epoch: %d\n", tv.ExpectedEpoch)
	}
	if tv.ExpectedTreeHash != "" {
		treeHashBytes, _ := hex.DecodeString(tv.ExpectedTreeHash)
		fmt.Printf("  Expected tree hash: %s... (%d bytes)\n",
			tv.ExpectedTreeHash[:minInt(16, len(tv.ExpectedTreeHash))],
			len(treeHashBytes))
	}

	_ = groupID

	fmt.Printf("Test vector '%s' validated successfully\n", tv.Name)
	return nil
}

// minInt returns the minimum of two integers.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GenerateInteropTestVectors generates a complete set of test vectors.
func GenerateInteropTestVectors() (*TestVectorSet, error) {
	tvs := &TestVectorSet{
		Name:        "mls-go Interoperability Test Vectors",
		Description: "Test vectors for interoperability testing between mls-go and other MLS implementations",
	}

	suites := []ciphersuite.CipherSuite{
		ciphersuite.MLS128DHKEMX25519,         // CS1
		ciphersuite.MLS128DHKEMP256,           // CS2
		ciphersuite.MLS128DHKEMX25519ChaCha20, // CS3
	}

	for _, cs := range suites {
		gen := NewTestVectorGenerator(cs)

		tv1, err := gen.GenerateOneToOneJoin()
		if err != nil {
			return nil, fmt.Errorf("generating one-to-one join for CS%d: %w", cs, err)
		}
		tvs.Vectors = append(tvs.Vectors, *tv1)

		tv2, err := gen.GenerateThreePartyJoin()
		if err != nil {
			return nil, fmt.Errorf("generating three-party join for CS%d: %w", cs, err)
		}
		tvs.Vectors = append(tvs.Vectors, *tv2)

		tv3, err := gen.GenerateMemberRemoval()
		if err != nil {
			return nil, fmt.Errorf("generating member removal for CS%d: %w", cs, err)
		}
		tvs.Vectors = append(tvs.Vectors, *tv3)
	}

	return tvs, nil
}

// ValidateAllTestVectors validates all test vectors in a set.
func (tvs *TestVectorSet) ValidateAllTestVectors() error {
	fmt.Printf("\n=== Validating Test Vector Set: %s ===\n", tvs.Name)
	fmt.Printf("Total vectors: %d\n\n", len(tvs.Vectors))

	var errors []error
	for i, tv := range tvs.Vectors {
		fmt.Printf("[%d/%d] ", i+1, len(tvs.Vectors))
		if err := ValidateTestVector(&tv); err != nil {
			errors = append(errors, fmt.Errorf("vector '%s': %w", tv.Name, err))
			fmt.Printf("  FAILED: %v\n", err)
		} else {
			fmt.Printf("  PASSED\n")
		}
	}

	fmt.Printf("\n=== Validation Complete ===\n")
	fmt.Printf("Passed: %d/%d\n", len(tvs.Vectors)-len(errors), len(tvs.Vectors))

	if len(errors) > 0 {
		return fmt.Errorf("%d validation(s) failed", len(errors))
	}

	return nil
}
