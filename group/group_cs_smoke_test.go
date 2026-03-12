package group

import (
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/keypackages"
)

func TestNewGroup_CS1_Ed25519(t *testing.T) {
	cred, sigPriv, err := credentials.GenerateCredentialWithKeyForCS([]byte("alice"), ciphersuite.MLS128DHKEMX25519)
	if err != nil {
		t.Fatalf("GenerateCredentialWithKeyForCS CS1: %v", err)
	}
	kp, priv, err := keypackages.Generate(cred, keypackages.MLS128DHKEMX25519)
	if err != nil {
		t.Fatalf("Generate CS1: %v", err)
	}
	gid, _ := NewGroupIDRandom()
	g, err := NewGroup(gid, ciphersuite.MLS128DHKEMX25519, kp, priv)
	if err != nil {
		t.Fatalf("NewGroup CS1: %v", err)
	}

	// Add Bob and commit
	credBob, _, err := credentials.GenerateCredentialWithKeyForCS([]byte("bob"), ciphersuite.MLS128DHKEMX25519)
	if err != nil {
		t.Fatalf("GenerateCredentialWithKeyForCS CS1 bob: %v", err)
	}
	kpBob, _, err := keypackages.Generate(credBob, keypackages.MLS128DHKEMX25519)
	if err != nil {
		t.Fatalf("Generate CS1 bob: %v", err)
	}
	if _, err := g.AddMember(kpBob); err != nil {
		t.Fatalf("AddMember CS1: %v", err)
	}
	sigPub := sigPriv.PublicKey()
	sc, err := g.Commit(sigPriv, sigPub, nil)
	if err != nil {
		t.Fatalf("Commit CS1: %v", err)
	}
	if err := g.MergeCommit(sc); err != nil {
		t.Fatalf("MergeCommit CS1: %v", err)
	}
	if g.MemberCount() != 2 {
		t.Errorf("MemberCount = %d, want 2", g.MemberCount())
	}

	// Export should work
	key, err := g.Export("test", []byte("ctx"), 32)
	if err != nil {
		t.Fatalf("Export CS1: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("Export len = %d, want 32", len(key))
	}
}

func TestNewGroup_CS3_ChaCha20Ed25519(t *testing.T) {
	cred, sigPriv, err := credentials.GenerateCredentialWithKeyForCS([]byte("alice"), ciphersuite.MLS128DHKEMX25519ChaCha20)
	if err != nil {
		t.Fatalf("GenerateCredentialWithKeyForCS CS3: %v", err)
	}
	kp, priv, err := keypackages.Generate(cred, keypackages.MLS128DHKEMX25519ChaCha20)
	if err != nil {
		t.Fatalf("Generate CS3: %v", err)
	}
	gid, _ := NewGroupIDRandom()
	g, err := NewGroup(gid, ciphersuite.MLS128DHKEMX25519ChaCha20, kp, priv)
	if err != nil {
		t.Fatalf("NewGroup CS3: %v", err)
	}

	// Add Bob and commit
	credBob, _, err := credentials.GenerateCredentialWithKeyForCS([]byte("bob"), ciphersuite.MLS128DHKEMX25519ChaCha20)
	if err != nil {
		t.Fatalf("GenerateCredentialWithKeyForCS CS3 bob: %v", err)
	}
	kpBob, _, err := keypackages.Generate(credBob, keypackages.MLS128DHKEMX25519ChaCha20)
	if err != nil {
		t.Fatalf("Generate CS3 bob: %v", err)
	}
	if _, err := g.AddMember(kpBob); err != nil {
		t.Fatalf("AddMember CS3: %v", err)
	}
	sigPub := sigPriv.PublicKey()
	sc, err := g.Commit(sigPriv, sigPub, nil)
	if err != nil {
		t.Fatalf("Commit CS3: %v", err)
	}
	if err := g.MergeCommit(sc); err != nil {
		t.Fatalf("MergeCommit CS3: %v", err)
	}
	if g.MemberCount() != 2 {
		t.Errorf("MemberCount = %d, want 2", g.MemberCount())
	}
}
