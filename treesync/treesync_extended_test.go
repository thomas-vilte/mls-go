// Package treesync - Tests exhaustivos para LeafNode, Validation según RFC 9420
package treesync

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/mls-go/ciphersuite"
	"github.com/mls-go/credentials"
	"github.com/mls-go/internal/tls"
)

// ============================================================================
// LeafNodeData Tests - RFC 9420 §7.2
// ============================================================================

func TestLeafNodeData_Hash(t *testing.T) {
	leaf := createTestLeafExt(t, "Test")

	hash1 := leaf.Hash()
	if len(hash1) == 0 {
		t.Fatal("LeafNodeData.Hash() returned empty hash")
	}

	hash2 := leaf.Hash()
	if !bytes.Equal(hash1, hash2) {
		t.Error("LeafNodeData.Hash() is not deterministic")
	}
}

func TestLeafNodeCapabilities_MarshalUnmarshal(t *testing.T) {
	caps := &LeafNodeCapabilities{
		ProtocolVersions: []uint16{1},
		CipherSuites:     []uint16{1, 2, 3},
		Extensions:       []uint16{1, 2},
		Proposals:        []uint16{1, 2, 3, 4},
		Credentials:      []uint16{1},
	}

	w := tls.NewWriter()
	caps.Marshal(w)

	if len(w.Bytes()) == 0 {
		t.Fatal("Capabilities.Marshal() returned empty data")
	}

	r := tls.NewReader(w.Bytes())
	got, err := UnmarshalCapabilities(r)
	if err != nil {
		t.Fatalf("UnmarshalCapabilities() failed: %v", err)
	}

	if len(got.CipherSuites) != len(caps.CipherSuites) {
		t.Errorf("CipherSuites len = %d, want %d", len(got.CipherSuites), len(caps.CipherSuites))
	}
}

// ============================================================================
// LeafNode Validation Tests - RFC 9420 §7.3
// ============================================================================

func TestValidateLeafNode_EmptyEncryptionKey(t *testing.T) {
	leaf := createTestLeafExt(t, "Invalid")
	leaf.EncryptionKey = []byte{}
	if err := ValidateLeafNode(&leaf); err == nil {
		t.Fatal("Should fail for empty encryption key")
	}
}

func TestValidateLeafNode_NilSignatureKey(t *testing.T) {
	leaf := createTestLeafExt(t, "Invalid")
	leaf.SignatureKey = nil
	if err := ValidateLeafNode(&leaf); err == nil {
		t.Fatal("Should fail for nil signature key")
	}
}

func TestValidateLeafNode_NilCredential(t *testing.T) {
	leaf := createTestLeafExt(t, "Invalid")
	leaf.Credential = nil
	if err := ValidateLeafNode(&leaf); err == nil {
		t.Fatal("Should fail for nil credential")
	}
}

func TestValidateLeafNode_InvalidSource(t *testing.T) {
	leaf := createTestLeafExt(t, "Invalid")
	leaf.LeafNodeSource = 99
	if err := ValidateLeafNode(&leaf); err == nil {
		t.Fatal("Should fail for invalid leaf_node_source")
	}
}

// ============================================================================
// Tree Serialization Tests
// ============================================================================

func TestUnmarshalLeafNodeData(t *testing.T) {
	leaf := createTestLeafExt(t, "Test")
	data := leaf.Marshal()

	got, err := UnmarshalLeafNodeData(data)
	if err != nil {
		t.Fatalf("UnmarshalLeafNodeData() failed: %v", err)
	}

	if got.Credential == nil {
		t.Error("Unmarshaled leaf has nil credential")
	}
}

func TestLeafNodeData_Roundtrip(t *testing.T) {
	leaf := createTestLeafExt(t, "Roundtrip")
	data := leaf.Marshal()

	got, err := UnmarshalLeafNodeData(data)
	if err != nil {
		t.Fatalf("Roundtrip failed: %v", err)
	}

	if !bytes.Equal(got.EncryptionKey, leaf.EncryptionKey) {
		t.Error("Encryption key mismatch")
	}
}

// ============================================================================
// Tree Navigation Tests
// ============================================================================

func TestGetLeaf(t *testing.T) {
	tree := createTestTreeExt(t, 4)

	node := tree.GetLeaf(0)
	if node == nil {
		t.Fatal("GetLeaf(0) returned nil")
	}
	if node.State != NodeStatePresent {
		t.Errorf("State = %v, want Present", node.State)
	}

	node = tree.GetLeaf(999)
	if node != nil {
		t.Error("GetLeaf(999) should return nil")
	}
}

func TestLeafIndexToNodeIndex(t *testing.T) {
	tests := []struct{ leaf, want uint32 }{
		{0, 0}, {1, 2}, {2, 4}, {3, 6},
	}
	for _, tt := range tests {
		if got := LeafIndexToNodeIndex(LeafIndex(tt.leaf)); uint32(got) != tt.want {
			t.Errorf("LeafIndexToNodeIndex(%d) = %d, want %d", tt.leaf, got, tt.want)
		}
	}
}

func TestNodeIndexToLeafIndex(t *testing.T) {
	tests := []struct {
		node    uint32
		want    uint32
		wantErr bool
	}{
		{0, 0, false}, {2, 1, false}, {1, 0, true}, {3, 0, true},
	}
	for _, tt := range tests {
		got, err := NodeIndexToLeafIndex(NodeIndex(tt.node))
		if (err != nil) != tt.wantErr {
			t.Errorf("NodeIndexToLeafIndex(%d) err = %v", tt.node, err)
		}
		if uint32(got) != tt.want && !tt.wantErr {
			t.Errorf("NodeIndexToLeafIndex(%d) = %d, want %d", tt.node, got, tt.want)
		}
	}
}

// ============================================================================
// Tree Hash Tests
// ============================================================================

func TestComputeParentHash(t *testing.T) {
	hash := ComputeParentHash([]byte("key"), []byte("ph"), []byte("sh"))
	if len(hash) == 0 {
		t.Fatal("ComputeParentHash() returned empty hash")
	}

	hash2 := ComputeParentHash([]byte("key"), []byte("ph"), []byte("sh"))
	if !bytes.Equal(hash, hash2) {
		t.Error("Not deterministic")
	}
}

func TestComputeLeafNodeHash(t *testing.T) {
	hash := ComputeLeafNodeHash(0, &LeafNodeData{EncryptionKey: []byte("key")})
	if len(hash) == 0 {
		t.Fatal("ComputeLeafNodeHash() returned empty hash")
	}
}

// ============================================================================
// Edge Cases
// ============================================================================

func TestResolution_OutOfBounds(t *testing.T) {
	tree := NewRatchetTree(4)
	if res := tree.Resolution(999); res != nil {
		t.Errorf("Resolution(999) = %v, want nil", res)
	}
}

func TestDirectPath_AllLeaves(t *testing.T) {
	tree := createTestTreeExt(t, 4)
	for i := LeafIndex(0); i < LeafIndex(tree.NumLeaves); i++ {
		path := tree.DirectPath(i)
		if len(path) == 0 {
			t.Errorf("DirectPath(%d) empty", i)
		}
		if path[len(path)-1] != tree.Root() {
			t.Errorf("DirectPath(%d) doesn't end at root", i)
		}
	}
}

func TestCopath_Length(t *testing.T) {
	tree := createTestTreeExt(t, 4)
	for i := LeafIndex(0); i < LeafIndex(tree.NumLeaves); i++ {
		direct := tree.DirectPath(i)
		copath := tree.Copath(i)
		if len(copath) != len(direct)-1 {
			t.Errorf("Copath(%d) len = %d, want %d", i, len(copath), len(direct)-1)
		}
	}
}

func TestLargeTree(t *testing.T) {
	tree := NewRatchetTree(100)
	if tree.NumLeaves < 100 {
		t.Errorf("NumLeaves = %d, want >= 100", tree.NumLeaves)
	}
	if len(tree.TreeHash()) == 0 {
		t.Error("TreeHash() empty on large tree")
	}
}

// ============================================================================
// Helpers
// ============================================================================

// ============================================================================
// ValidateLeafNodeSignature Tests
// ============================================================================

func TestValidateLeafNodeSignature_Valid(t *testing.T) {
	sigPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := createTestLeafExt(t, "signed")
	leaf.SignatureKey = &sigPriv.PublicKey

	tbsBytes := leaf.MarshalTBS()
	hash := sha256sum(tbsBytes)
	r, s, _ := ecdsa.Sign(rand.Reader, sigPriv, hash)

	// Pack r||s as 32-byte big-endian each
	sig := make([]byte, 64)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(sig[32-len(rb):32], rb)
	copy(sig[64-len(sb):64], sb)

	if err := ValidateLeafNodeSignature(&leaf, sig); err != nil {
		t.Fatalf("ValidateLeafNodeSignature() failed: %v", err)
	}
}

func TestValidateLeafNodeSignature_BadSig(t *testing.T) {
	sigPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := createTestLeafExt(t, "signed")
	leaf.SignatureKey = &sigPriv.PublicKey

	badSig := make([]byte, 64)
	badSig[0] = 0x01 // garbage
	if err := ValidateLeafNodeSignature(&leaf, badSig); err == nil {
		t.Fatal("expected error for bad signature")
	}
}

func TestValidateLeafNodeSignature_TooShort(t *testing.T) {
	leaf := createTestLeafExt(t, "signed")
	if err := ValidateLeafNodeSignature(&leaf, []byte{0x01, 0x02}); err == nil {
		t.Fatal("expected error for short signature")
	}
}

func TestValidateLeafNodeSignature_NilKey(t *testing.T) {
	leaf := createTestLeafExt(t, "signed")
	leaf.SignatureKey = nil
	if err := ValidateLeafNodeSignature(&leaf, make([]byte, 64)); err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestValidateLeafNodeSignature_EmptySig(t *testing.T) {
	leaf := createTestLeafExt(t, "signed")
	if err := ValidateLeafNodeSignature(&leaf, nil); err == nil {
		t.Fatal("expected error for empty signature")
	}
}

func sha256sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// ============================================================================
// LeafNodeData.Verify Tests - RFC 9420 §7.2
// ============================================================================

func TestLeafNodeData_Verify_Valid(t *testing.T) {
	// Crear leaf con firma válida usando ECDSA (como en el resto del código)
	sigPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	cred := credentials.NewBasicCredential([]byte("test-verify"))
	encPriv, _ := ecdh.P256().GenerateKey(rand.Reader)

	leaf := LeafNodeData{
		Credential:     cred,
		SignatureKey:   &sigPriv.PublicKey,
		EncryptionKey:  encPriv.PublicKey().Bytes(),
		LeafNodeSource: 1, // key_package
		Capabilities:   &LeafNodeCapabilities{ProtocolVersions: []uint16{1}},
		Lifetime:       &LeafNodeLifetime{NotBefore: 0, NotAfter: 9999999999},
	}

	// Firmar el TBS usando SignWithLabel (como en el código real)
	tbsBytes := leaf.MarshalTBS()
	sigPrivWrapper := ciphersuite.NewSignaturePrivateKey(sigPriv)
	sig, err := ciphersuite.SignWithLabel(sigPrivWrapper, "LeafNodeTBS", tbsBytes)
	if err != nil {
		t.Fatalf("SignWithLabel failed: %v", err)
	}
	leaf.Signature = sig.AsSlice()

	// Verify debería retornar nil
	if err := leaf.Verify(ciphersuite.MLS128DHKEMP256); err != nil {
		t.Errorf("Verify should succeed: %v", err)
	}
}

func TestLeafNodeData_Verify_TamperedContent(t *testing.T) {
	// Crear leaf firmado
	sigPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	cred := credentials.NewBasicCredential([]byte("test-tamper"))
	encPriv, _ := ecdh.P256().GenerateKey(rand.Reader)

	leaf := LeafNodeData{
		Credential:     cred,
		SignatureKey:   &sigPriv.PublicKey,
		EncryptionKey:  encPriv.PublicKey().Bytes(),
		LeafNodeSource: 1,
		Capabilities:   &LeafNodeCapabilities{ProtocolVersions: []uint16{1}},
		Lifetime:       &LeafNodeLifetime{NotBefore: 0, NotAfter: 9999999999},
	}

	// Firmar
	tbsBytes := leaf.MarshalTBS()
	sigPrivWrapper := ciphersuite.NewSignaturePrivateKey(sigPriv)
	sig, err := ciphersuite.SignWithLabel(sigPrivWrapper, "LeafNodeTBS", tbsBytes)
	if err != nil {
		t.Fatalf("SignWithLabel failed: %v", err)
	}
	leaf.Signature = sig.AsSlice()

	// Corromper el encryption key
	originalKey := make([]byte, len(leaf.EncryptionKey))
	copy(originalKey, leaf.EncryptionKey)
	leaf.EncryptionKey[0] ^= 0xFF

	// Verify debería fallar
	if err := leaf.Verify(ciphersuite.MLS128DHKEMP256); err == nil {
		t.Error("Verify should fail with tampered content")
	}

	// Restaurar para cleanup
	copy(leaf.EncryptionKey, originalKey)
}

func TestLeafNodeData_VerifyWithContext_KeyPackageSource(t *testing.T) {
	// LeafNode de KeyPackage (source=1) no necesita group_id/leaf_index
	sigPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	cred := credentials.NewBasicCredential([]byte("test-context-kp"))
	encPriv, _ := ecdh.P256().GenerateKey(rand.Reader)

	leaf := LeafNodeData{
		Credential:     cred,
		SignatureKey:   &sigPriv.PublicKey,
		EncryptionKey:  encPriv.PublicKey().Bytes(),
		LeafNodeSource: 1, // key_package
		Capabilities:   &LeafNodeCapabilities{ProtocolVersions: []uint16{1}},
		Lifetime:       &LeafNodeLifetime{NotBefore: 0, NotAfter: 9999999999},
	}

	// Firmar con TBSWithContext (groupID=nil, leafIndex=0)
	tbsBytes := leaf.MarshalTBSWithContext(nil, 0)
	sigPrivWrapper := ciphersuite.NewSignaturePrivateKey(sigPriv)
	sig, err := ciphersuite.SignWithLabel(sigPrivWrapper, "LeafNodeTBS", tbsBytes)
	if err != nil {
		t.Fatalf("SignWithLabel failed: %v", err)
	}
	leaf.Signature = sig.AsSlice()

	// VerifyWithContext debería verificar OK
	if err := leaf.VerifyWithContext(ciphersuite.MLS128DHKEMP256, nil, 0); err != nil {
		t.Errorf("VerifyWithContext should succeed for key_package source: %v", err)
	}
}

func TestLeafNodeData_VerifyWithContext_CommitSource(t *testing.T) {
	// LeafNode de Commit (source=3) necesita parent_hash
	sigPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	cred := credentials.NewBasicCredential([]byte("test-context-commit"))
	encPriv, _ := ecdh.P256().GenerateKey(rand.Reader)

	groupID := []byte("test-group-123")
	parentHash := []byte("parent-hash-abc")

	leaf := LeafNodeData{
		Credential:     cred,
		SignatureKey:   &sigPriv.PublicKey,
		EncryptionKey:  encPriv.PublicKey().Bytes(),
		LeafNodeSource: 3, // commit
		ParentHash:     parentHash,
		Capabilities:   &LeafNodeCapabilities{ProtocolVersions: []uint16{1}},
	}

	// Firmar con TBSWithContext (groupID y leafIndex)
	tbsBytes := leaf.MarshalTBSWithContext(groupID, 5)
	sigPrivWrapper := ciphersuite.NewSignaturePrivateKey(sigPriv)
	sig, err := ciphersuite.SignWithLabel(sigPrivWrapper, "LeafNodeTBS", tbsBytes)
	if err != nil {
		t.Fatalf("SignWithLabel failed: %v", err)
	}
	leaf.Signature = sig.AsSlice()

	// VerifyWithContext con groupID y leafIndex correctos debería verificar OK
	if err := leaf.VerifyWithContext(ciphersuite.MLS128DHKEMP256, groupID, 5); err != nil {
		t.Errorf("VerifyWithContext should succeed with correct context: %v", err)
	}

	// VerifyWithContext con groupID incorrecto debería fallar
	if err := leaf.VerifyWithContext(ciphersuite.MLS128DHKEMP256, []byte("wrong-group"), 5); err == nil {
		t.Error("VerifyWithContext should fail with wrong groupID")
	}
}

func TestLeafNodeData_Verify_InvalidSignature(t *testing.T) {
	// Crear leaf con firma inválida
	cred := credentials.NewBasicCredential([]byte("test-invalid-sig"))
	encPriv, _ := ecdh.P256().GenerateKey(rand.Reader)
	sigPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	leaf := LeafNodeData{
		Credential:     cred,
		SignatureKey:   &sigPriv.PublicKey,
		EncryptionKey:  encPriv.PublicKey().Bytes(),
		LeafNodeSource: 1,
		Capabilities:   &LeafNodeCapabilities{ProtocolVersions: []uint16{1}},
		Lifetime:       &LeafNodeLifetime{NotBefore: 0, NotAfter: 9999999999},
		Signature:      []byte("invalid-signature-bytes"),
	}

	// Verify debería fallar
	if err := leaf.Verify(ciphersuite.MLS128DHKEMP256); err == nil {
		t.Error("Verify should fail with invalid signature")
	}
}

func TestLeafNodeData_Verify_NilSignature(t *testing.T) {
	// Crear leaf sin firma
	cred := credentials.NewBasicCredential([]byte("test-nil-sig"))
	encPriv, _ := ecdh.P256().GenerateKey(rand.Reader)
	sigPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	leaf := LeafNodeData{
		Credential:     cred,
		SignatureKey:   &sigPriv.PublicKey,
		EncryptionKey:  encPriv.PublicKey().Bytes(),
		LeafNodeSource: 1,
		Capabilities:   &LeafNodeCapabilities{ProtocolVersions: []uint16{1}},
		Lifetime:       &LeafNodeLifetime{NotBefore: 0, NotAfter: 9999999999},
		Signature:      nil,
	}

	// Verify debería fallar
	if err := leaf.Verify(ciphersuite.MLS128DHKEMP256); err == nil {
		t.Error("Verify should fail with nil signature")
	}
}

// ============================================================================
// ValidateLeafNodeLifetime Tests
// ============================================================================

func TestValidateLeafNodeLifetime_Valid(t *testing.T) {
	lt := &LeafNodeLifetime{NotBefore: 0, NotAfter: 9999999999}
	if err := ValidateLeafNodeLifetime(lt); err != nil {
		t.Fatalf("expected valid lifetime: %v", err)
	}
}

func TestValidateLeafNodeLifetime_Nil(t *testing.T) {
	// nil lifetime is valid (no constraint)
	if err := ValidateLeafNodeLifetime(nil); err != nil {
		t.Fatalf("nil lifetime should be valid: %v", err)
	}
}

func TestValidateLeafNodeLifetime_Expired(t *testing.T) {
	lt := &LeafNodeLifetime{NotBefore: 0, NotAfter: 1} // expired in 1970
	if err := ValidateLeafNodeLifetime(lt); err == nil {
		t.Fatal("expected error for expired lifetime")
	}
}

func TestValidateLeafNodeLifetime_NotYetValid(t *testing.T) {
	lt := &LeafNodeLifetime{NotBefore: 9999999999, NotAfter: 99999999999}
	if err := ValidateLeafNodeLifetime(lt); err == nil {
		t.Fatal("expected error for future not_before")
	}
}

// ============================================================================
// ValidateLeafNodeCapabilities Tests
// ============================================================================

func TestValidateLeafNodeCapabilities_Valid(t *testing.T) {
	caps := &LeafNodeCapabilities{
		ProtocolVersions: []uint16{1},
		CipherSuites:     []uint16{2},
	}
	if err := ValidateLeafNodeCapabilities(caps); err != nil {
		t.Fatalf("expected valid capabilities: %v", err)
	}
}

func TestValidateLeafNodeCapabilities_Nil(t *testing.T) {
	if err := ValidateLeafNodeCapabilities(nil); err == nil {
		t.Fatal("nil capabilities should fail")
	}
}

func TestValidateLeafNodeCapabilities_EmptyVersions(t *testing.T) {
	caps := &LeafNodeCapabilities{CipherSuites: []uint16{2}}
	if err := ValidateLeafNodeCapabilities(caps); err == nil {
		t.Fatal("empty protocol_versions should fail")
	}
}

func TestValidateLeafNodeCapabilities_EmptyCipherSuites(t *testing.T) {
	caps := &LeafNodeCapabilities{ProtocolVersions: []uint16{1}}
	if err := ValidateLeafNodeCapabilities(caps); err == nil {
		t.Fatal("empty cipher_suites should fail")
	}
}

func TestValidateLeafNodeCapabilities_InvalidVersion0(t *testing.T) {
	caps := &LeafNodeCapabilities{ProtocolVersions: []uint16{0}, CipherSuites: []uint16{2}}
	if err := ValidateLeafNodeCapabilities(caps); err == nil {
		t.Fatal("protocol version 0 should fail")
	}
}

func TestValidateLeafNodeCapabilities_InvalidCipherSuite0(t *testing.T) {
	caps := &LeafNodeCapabilities{ProtocolVersions: []uint16{1}, CipherSuites: []uint16{0}}
	if err := ValidateLeafNodeCapabilities(caps); err == nil {
		t.Fatal("cipher suite 0 should fail")
	}
}

// ============================================================================
// BlankNode and TruncateTrailingBlanks Tests
// ============================================================================

func TestBlankNode(t *testing.T) {
	tree := createTestTreeExt(t, 4)

	// Blank leaf 0 (node index 0)
	tree.BlankNode(NodeIndex(0))
	if tree.Nodes[0].State != NodeStateBlank {
		t.Errorf("expected NodeStateBlank, got %v", tree.Nodes[0].State)
	}
	if tree.Nodes[0].LeafData != nil {
		t.Error("LeafData should be nil after blanking")
	}

	// Out-of-bounds blank is a no-op
	tree.BlankNode(NodeIndex(9999))
}

func TestTruncateTrailingBlanks(t *testing.T) {
	tree := NewRatchetTree(4)
	for i := 0; i < 4; i++ {
		tree.AddLeaf(createTestLeafExt(t, string(rune('A'+i))))
	}
	// Blank the last leaf so TruncateTrailingBlanks has something to remove
	lastLeafIdx := LeafIndex(tree.NumLeaves - 1)
	tree.BlankNode(LeafIndexToNodeIndex(lastLeafIdx))

	before := tree.NumLeaves
	tree.TruncateTrailingBlanks()
	after := tree.NumLeaves
	if after >= before {
		t.Errorf("TruncateTrailingBlanks: NumLeaves %d >= %d (should have shrunk)", after, before)
	}
}

// ============================================================================
// UpdatePath Marshal/Unmarshal Tests
// ============================================================================

func TestUpdatePath_MarshalUnmarshal(t *testing.T) {
	leaf := createTestLeafExt(t, "sender")
	up := NewUpdatePath(&leaf, nil)

	data := up.Marshal()
	if len(data) == 0 {
		t.Fatal("Marshal() returned empty")
	}

	got, err := UnmarshalUpdatePath(data)
	if err != nil {
		t.Fatalf("UnmarshalUpdatePath() failed: %v", err)
	}
	if got.LeafNode == nil {
		t.Error("unmarshaled LeafNode is nil")
	}
	if len(got.Nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(got.Nodes))
	}
}

func TestUpdatePath_Validate_NilLeafNode(t *testing.T) {
	up := &UpdatePath{LeafNode: nil}
	if err := up.Validate(); err == nil {
		t.Fatal("expected error for nil leaf_node")
	}
}

func TestUpdatePath_MarshalUnmarshal_WithNodes(t *testing.T) {
	leaf := createTestLeafExt(t, "sender")
	nodes := []ciphersuite.HpkeCiphertext{
		{KEMOutput: []byte{0x01, 0x02}, Ciphertext: []byte{0x03, 0x04}},
		{KEMOutput: []byte{0xAA}, Ciphertext: []byte{0xBB, 0xCC, 0xDD}},
	}
	up := NewUpdatePath(&leaf, nodes)

	data := up.Marshal()
	got, err := UnmarshalUpdatePath(data)
	if err != nil {
		t.Fatalf("UnmarshalUpdatePath() with nodes failed: %v", err)
	}
	if len(got.Nodes) != len(nodes) {
		t.Errorf("Nodes count = %d, want %d", len(got.Nodes), len(nodes))
	}
	if !bytes.Equal(got.Nodes[0].KEMOutput, nodes[0].KEMOutput) {
		t.Error("KEMOutput mismatch")
	}
	if !bytes.Equal(got.Nodes[1].Ciphertext, nodes[1].Ciphertext) {
		t.Error("Ciphertext mismatch")
	}
}

func TestUpdatePath_Validate_Valid(t *testing.T) {
	leaf := createTestLeafExt(t, "sender")
	leaf.Signature = []byte{0x01}
	up := NewUpdatePath(&leaf, nil)
	// Validate calls LeafData.Validate(), which requires non-empty signature
	// but leaf.Validate() doesn't check signature format, just emptiness
	if err := up.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
}

func TestDerivePathSecret(t *testing.T) {
	ps, err := DerivePathSecret([]byte("secret"), []byte("ctx"))
	if err != nil {
		t.Fatalf("DerivePathSecret() failed: %v", err)
	}
	if len(ps.Secret) == 0 {
		t.Error("expected non-empty secret")
	}

	_, err = DerivePathSecret(nil, nil)
	if err == nil {
		t.Error("expected error for empty shared secret")
	}
}

// ============================================================================
// MarshalTree / UnmarshalTree Roundtrip Tests
// ============================================================================

func TestMarshalUnmarshalTree_Roundtrip(t *testing.T) {
	tree := createTestTreeExt(t, 4)

	data := tree.MarshalTree()
	if len(data) == 0 {
		t.Fatal("MarshalTree() returned empty")
	}

	got, err := UnmarshalTree(data)
	if err != nil {
		t.Fatalf("UnmarshalTree() failed: %v", err)
	}
	if got.NumLeaves != tree.NumLeaves {
		t.Errorf("NumLeaves = %d, want %d", got.NumLeaves, tree.NumLeaves)
	}

	// Tree hashes must match
	if !bytes.Equal(got.TreeHash(), tree.TreeHash()) {
		t.Error("TreeHash mismatch after marshal/unmarshal roundtrip")
	}
}

func TestUnmarshalTree_EmptyData(t *testing.T) {
	_, err := UnmarshalTree([]byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestUnmarshalTreeFromExtension_FallsBackToUnmarshalTree(t *testing.T) {
	// If the data is not a valid extension format, it falls back to UnmarshalTree
	tree := createTestTreeExt(t, 2)
	data := tree.MarshalTree()

	got, err := UnmarshalTreeFromExtension(data)
	if err != nil {
		t.Fatalf("UnmarshalTreeFromExtension() failed: %v", err)
	}
	if got.NumLeaves != tree.NumLeaves {
		t.Errorf("NumLeaves = %d, want %d", got.NumLeaves, tree.NumLeaves)
	}
}

func TestUnmarshalTree_ZeroLeaves(t *testing.T) {
	// Write num_leaves=0
	w := make([]byte, 4) // 0 as uint32 big-endian
	_, err := UnmarshalTree(w)
	if err == nil {
		t.Fatal("expected error for num_leaves=0")
	}
}

// ============================================================================
// RatchetTree.Clone Tests
// ============================================================================

func TestRatchetTree_Clone(t *testing.T) {
	tree := createTestTreeExt(t, 4)
	clone := tree.Clone()

	if clone.NumLeaves != tree.NumLeaves {
		t.Errorf("Clone NumLeaves = %d, want %d", clone.NumLeaves, tree.NumLeaves)
	}
	if !bytes.Equal(clone.TreeHash(), tree.TreeHash()) {
		t.Error("Clone TreeHash mismatch")
	}

	// Mutating clone should not affect original
	clone.BlankNode(NodeIndex(0))
	if tree.Nodes[0].State == NodeStateBlank {
		t.Error("Blanking clone affected original")
	}
}

// ============================================================================
// Clone Tests (LeafNodeData, Node, LeafNodeCapabilities)
// ============================================================================

func TestLeafNodeData_Clone(t *testing.T) {
	orig := createTestLeafExt(t, "original")
	origPtr := &orig
	cloned := origPtr.Clone()

	if cloned == nil {
		t.Fatal("Clone() returned nil")
	}
	if !bytes.Equal(cloned.EncryptionKey, orig.EncryptionKey) {
		t.Error("Clone EncryptionKey mismatch")
	}
	// Mutate clone — original must not change
	cloned.EncryptionKey[0] ^= 0xFF
	if bytes.Equal(cloned.EncryptionKey, orig.EncryptionKey) {
		t.Error("Clone is not a deep copy (EncryptionKey shared)")
	}
}

func TestLeafNodeData_Clone_Nil(t *testing.T) {
	var l *LeafNodeData
	if c := l.clone(); c != nil {
		t.Error("clone of nil should return nil")
	}
}

func TestNode_clone(t *testing.T) {
	leaf := createTestLeafExt(t, "leaf")
	n := Node{
		State:          NodeStatePresent,
		LeafData:       &leaf,
		ParentHash:     []byte{0x01, 0x02},
		UnmergedLeaves: []LeafIndex{1, 2},
	}
	c := n.clone()

	if c.State != n.State {
		t.Errorf("State mismatch: %v vs %v", c.State, n.State)
	}
	if !bytes.Equal(c.ParentHash, n.ParentHash) {
		t.Error("ParentHash mismatch")
	}
	if c.LeafData == nil {
		t.Error("LeafData not cloned")
	}
	// Verify deep copy of ParentHash
	c.ParentHash[0] = 0xFF
	if n.ParentHash[0] == 0xFF {
		t.Error("ParentHash not deep copied")
	}
}

func TestNode_Validate_PresentLeafNilData(t *testing.T) {
	n := Node{State: NodeStatePresent, LeafData: nil}
	if err := n.Validate(NodeIndex(0), 4); err == nil {
		t.Fatal("expected error for present leaf with nil LeafData")
	}
}

func TestNode_Validate_PresentLeafValid(t *testing.T) {
	leaf := createTestLeafExt(t, "x")
	n := Node{State: NodeStatePresent, LeafData: &leaf}
	if err := n.Validate(NodeIndex(0), 4); err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}
}

func TestNode_Validate_PresentParentNilEncKey(t *testing.T) {
	n := Node{State: NodeStatePresent, EncryptionKey: nil, ParentHash: []byte{0x01}}
	if err := n.Validate(NodeIndex(1), 4); err == nil {
		t.Fatal("expected error for present parent with nil EncryptionKey")
	}
}

func TestNode_Validate_PresentParentEmptyHash(t *testing.T) {
	encKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	n := Node{State: NodeStatePresent, EncryptionKey: encKey.PublicKey(), ParentHash: nil}
	if err := n.Validate(NodeIndex(1), 4); err == nil {
		t.Fatal("expected error for present parent with empty ParentHash")
	}
}

// ============================================================================
// LeafNodeData.Validate() Tests (method on node, different from ValidateLeafNode)
// ============================================================================

func TestLeafNodeData_Validate_Valid(t *testing.T) {
	leaf := createTestLeafExt(t, "valid")
	leaf.Signature = []byte{0x01} // non-empty signature
	if err := leaf.Validate(); err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}
}

func TestLeafNodeData_Validate_EmptyEncKey(t *testing.T) {
	leaf := createTestLeafExt(t, "x")
	leaf.EncryptionKey = nil
	leaf.Signature = []byte{0x01}
	if err := leaf.Validate(); err == nil {
		t.Fatal("expected error for empty encryption_key")
	}
}

func TestLeafNodeData_Validate_NilSigKey(t *testing.T) {
	leaf := createTestLeafExt(t, "x")
	leaf.SignatureKey = nil
	leaf.Signature = []byte{0x01}
	if err := leaf.Validate(); err == nil {
		t.Fatal("expected error for nil signature_key")
	}
}

func TestLeafNodeData_Validate_EmptySignature(t *testing.T) {
	leaf := createTestLeafExt(t, "x")
	leaf.Signature = nil
	if err := leaf.Validate(); err == nil {
		t.Fatal("expected error for empty signature")
	}
}

// ============================================================================
// MarshalTBSWithContext Tests
// ============================================================================

func TestMarshalTBSWithContext_Source2(t *testing.T) {
	leaf := createTestLeafExt(t, "update")
	leaf.LeafNodeSource = 2 // update

	tbs := leaf.MarshalTBSWithContext([]byte("group-id"), 3)
	if len(tbs) == 0 {
		t.Fatal("MarshalTBSWithContext(source=2) returned empty")
	}

	// With group context, result must be larger than without
	tbsBase := leaf.MarshalTBS()
	if len(tbs) <= len(tbsBase) {
		t.Errorf("source=2 TBS (%d) not larger than base TBS (%d)", len(tbs), len(tbsBase))
	}
}

func TestMarshalTBSWithContext_Source3(t *testing.T) {
	leaf := createTestLeafExt(t, "commit")
	leaf.LeafNodeSource = 3 // commit

	tbs := leaf.MarshalTBSWithContext([]byte("group-id"), 0)
	tbsBase := leaf.MarshalTBS()
	if len(tbs) <= len(tbsBase) {
		t.Errorf("source=3 TBS (%d) not larger than base TBS (%d)", len(tbs), len(tbsBase))
	}
}

func TestMarshalTBSWithContext_Source1_NoContext(t *testing.T) {
	leaf := createTestLeafExt(t, "keypackage")
	// source=1 (key_package): no group context appended

	tbs := leaf.MarshalTBSWithContext([]byte("group-id"), 99)
	tbsBase := leaf.MarshalTBS()
	if len(tbs) != len(tbsBase) {
		t.Errorf("source=1 TBS should equal base: %d vs %d", len(tbs), len(tbsBase))
	}
}

// ============================================================================
// RatchetTree.Validate() Tests
// ============================================================================

func TestRatchetTree_Validate_Valid(t *testing.T) {
	tree := createTestTreeExt(t, 4)
	if err := tree.Validate(); err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}
}

func TestRatchetTree_Validate_ZeroLeaves(t *testing.T) {
	tree := &RatchetTree{NumLeaves: 0, Nodes: []Node{}}
	if err := tree.Validate(); err == nil {
		t.Fatal("expected error for 0 leaves")
	}
}

func TestRatchetTree_Validate_WrongNodeCount(t *testing.T) {
	tree := &RatchetTree{NumLeaves: 4, Nodes: make([]Node, 5)} // should be 7
	if err := tree.Validate(); err == nil {
		t.Fatal("expected error for wrong node count")
	}
}

// ============================================================================
// AddLeaf Reuse Blank Slot Test
// ============================================================================

func TestAddLeaf_ReuseBlankSlot(t *testing.T) {
	tree := NewRatchetTree(4)
	for i := 0; i < 4; i++ {
		tree.AddLeaf(createTestLeafExt(t, string(rune('A'+i))))
	}
	// Blank leaf 1
	tree.BlankNode(LeafIndexToNodeIndex(LeafIndex(1)))

	before := tree.NumLeaves
	newLeaf := createTestLeafExt(t, "new")
	tree.AddLeaf(newLeaf)
	after := tree.NumLeaves

	// Should reuse the blank slot, not expand
	if after != before {
		t.Errorf("AddLeaf should reuse blank slot: NumLeaves %d → %d", before, after)
	}
}

// ============================================================================
// MarshalTree with intermediate parent nodes
// ============================================================================

func TestMarshalTree_WithParents(t *testing.T) {
	tree := createTestTreeExt(t, 2)
	// After adding 2 leaves there's 1 parent node (root)
	data := tree.MarshalTree()

	got, err := UnmarshalTree(data)
	if err != nil {
		t.Fatalf("UnmarshalTree() failed: %v", err)
	}
	if got.NumLeaves != tree.NumLeaves {
		t.Errorf("NumLeaves = %d, want %d", got.NumLeaves, tree.NumLeaves)
	}
}

func TestMarshalTree_ParentWithEncKey(t *testing.T) {
	// Build a 2-leaf tree and manually set a parent node with encryption key
	tree := createTestTreeExt(t, 2)
	// Root is at index 1 for 2-leaf tree (nodes: [0]=leaf0, [1]=root, [2]=leaf1)
	encPriv, _ := ecdh.P256().GenerateKey(rand.Reader)
	tree.Nodes[1].State = NodeStatePresent
	tree.Nodes[1].EncryptionKey = encPriv.PublicKey()
	tree.Nodes[1].ParentHash = []byte{0xDE, 0xAD}
	tree.Nodes[1].UnmergedLeaves = []LeafIndex{0, 1}

	data := tree.MarshalTree()
	got, err := UnmarshalTree(data)
	if err != nil {
		t.Fatalf("UnmarshalTree() with parent enckey failed: %v", err)
	}
	if got.Nodes[1].EncryptionKey == nil {
		t.Error("parent EncryptionKey not preserved through marshal/unmarshal")
	}
	if !bytes.Equal(got.Nodes[1].ParentHash, tree.Nodes[1].ParentHash) {
		t.Error("parent ParentHash mismatch")
	}
	if len(got.Nodes[1].UnmergedLeaves) != 2 {
		t.Errorf("UnmergedLeaves = %d, want 2", len(got.Nodes[1].UnmergedLeaves))
	}
}

func TestAddLeaf_Expansion(t *testing.T) {
	// Create a tree with 2 leaves (fills 2 slots), then add a 3rd to force expansion
	tree := NewRatchetTree(2)
	tree.AddLeaf(createTestLeafExt(t, "A"))
	tree.AddLeaf(createTestLeafExt(t, "B"))

	before := tree.NumLeaves
	tree.AddLeaf(createTestLeafExt(t, "C"))
	after := tree.NumLeaves

	if after <= before {
		t.Errorf("AddLeaf expansion: NumLeaves %d should be > %d", after, before)
	}
	if tree.GetLeaf(2) == nil {
		t.Error("GetLeaf(2) returned nil after expansion")
	}
}

// ============================================================================
// TreeHash with zero-leaves edge case
// ============================================================================

func TestTreeHash_ZeroLeaves(t *testing.T) {
	tree := &RatchetTree{NumLeaves: 0, Nodes: nil}
	if h := tree.TreeHash(); h != nil {
		t.Errorf("TreeHash() on empty tree should return nil, got %x", h)
	}
}

func createTestLeafExt(t *testing.T, id string) LeafNodeData {
	t.Helper()
	cred := credentials.NewBasicCredential([]byte(id))
	encPriv, _ := ecdh.P256().GenerateKey(rand.Reader)
	sigPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	return LeafNodeData{
		Credential:     cred,
		SignatureKey:   &sigPriv.PublicKey,
		EncryptionKey:  encPriv.PublicKey().Bytes(),
		LeafNodeSource: 1,
		Capabilities:   &LeafNodeCapabilities{ProtocolVersions: []uint16{1}, CipherSuites: []uint16{1, 2, 3}},
		Lifetime:       &LeafNodeLifetime{NotBefore: 0, NotAfter: 9999999999},
	}
}

func createTestTreeExt(t *testing.T, n uint32) *RatchetTree {
	t.Helper()
	tree := NewRatchetTree(n)
	for i := uint32(0); i < n; i++ {
		tree.AddLeaf(createTestLeafExt(t, string(rune('A'+i))))
	}
	return tree
}
