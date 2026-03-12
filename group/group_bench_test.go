package group

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// setupBenchGroup creates a group with `count` members, calling b.Fatal on any error.
// All errors in setup are fatal — a silently broken group gives meaningless benchmark results.
func setupBenchGroup(b *testing.B, count int) (*Group, *ciphersuite.SignaturePrivateKey) {
	b.Helper()

	credWithKey, _, err := credentials.GenerateCredentialWithKey([]byte("Creator"))
	if err != nil {
		b.Fatalf("GenerateCredentialWithKey: %v", err)
	}
	kp, kpPriv, err := keypackages.Generate(credWithKey, keypackages.MLS128DHKEMP256)
	if err != nil {
		b.Fatalf("Generate: %v", err)
	}
	groupID, err := NewGroupIDRandom()
	if err != nil {
		b.Fatalf("NewGroupIDRandom: %v", err)
	}
	g, err := NewGroup(groupID, ciphersuite.MLS128DHKEMP256, kp, kpPriv)
	if err != nil {
		b.Fatalf("NewGroup: %v", err)
	}

	sigPriv := ciphersuite.NewSignaturePrivateKey(kpPriv.SignatureKey)

	if count <= 1 {
		return g, sigPriv
	}

	for i := 1; i < count; i++ {
		cred, _, err := credentials.GenerateCredentialWithKey(fmt.Appendf(nil, "Member-%d", i))
		if err != nil {
			b.Fatalf("GenerateCredentialWithKey member %d: %v", i, err)
		}
		memberKp, _, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
		if err != nil {
			b.Fatalf("Generate member %d: %v", i, err)
		}
		if _, err := g.AddMember(memberKp); err != nil {
			b.Fatalf("AddMember %d: %v", i, err)
		}
	}

	sc, err := g.Commit(sigPriv, sigPriv.PublicKey(), nil)
	if err != nil {
		b.Fatalf("Commit: %v", err)
	}
	if err := g.MergeCommit(sc); err != nil {
		b.Fatalf("MergeCommit: %v", err)
	}

	return g, sigPriv
}

// benchMemberKP generates a stable KeyPackage for use as the "new member" in commit benchmarks.
func benchMemberKP(b *testing.B) *keypackages.KeyPackage {
	b.Helper()
	cred, _, err := credentials.GenerateCredentialWithKey([]byte("NewMember"))
	if err != nil {
		b.Fatalf("GenerateCredentialWithKey: %v", err)
	}
	kp, _, err := keypackages.Generate(cred, keypackages.MLS128DHKEMP256)
	if err != nil {
		b.Fatalf("Generate: %v", err)
	}
	return kp
}

func BenchmarkCommit_2Members(b *testing.B) {
	memberKp := benchMemberKP(b)

	for b.Loop() {
		b.StopTimer()
		// Re-create the group each iteration — avoids shared key schedule state
		// from corrupting subsequent iterations.
		g, sigPriv := setupBenchGroup(b, 1)
		if _, err := g.AddMember(memberKp); err != nil {
			b.Fatalf("AddMember: %v", err)
		}
		b.StartTimer()

		sc, err := g.Commit(sigPriv, sigPriv.PublicKey(), nil)
		if err != nil {
			b.Fatalf("Commit: %v", err)
		}
		if err := g.MergeCommit(sc); err != nil {
			b.Fatalf("MergeCommit: %v", err)
		}
	}
}

func BenchmarkCommit_10Members(b *testing.B) {
	memberKp := benchMemberKP(b)

	for b.Loop() {
		b.StopTimer()
		g, sigPriv := setupBenchGroup(b, 9)
		if _, err := g.AddMember(memberKp); err != nil {
			b.Fatalf("AddMember: %v", err)
		}
		b.StartTimer()

		sc, err := g.Commit(sigPriv, sigPriv.PublicKey(), nil)
		if err != nil {
			b.Fatalf("Commit: %v", err)
		}
		if err := g.MergeCommit(sc); err != nil {
			b.Fatalf("MergeCommit: %v", err)
		}
	}
}

func BenchmarkCommit_100Members(b *testing.B) {
	memberKp := benchMemberKP(b)

	for b.Loop() {
		b.StopTimer()
		g, sigPriv := setupBenchGroup(b, 99)
		if _, err := g.AddMember(memberKp); err != nil {
			b.Fatalf("AddMember: %v", err)
		}
		b.StartTimer()

		sc, err := g.Commit(sigPriv, sigPriv.PublicKey(), nil)
		if err != nil {
			b.Fatalf("Commit: %v", err)
		}
		if err := g.MergeCommit(sc); err != nil {
			b.Fatalf("MergeCommit: %v", err)
		}
	}
}

func BenchmarkAddMember(b *testing.B) {
	memberKp := benchMemberKP(b)

	for b.Loop() {
		b.StopTimer()
		g, _ := setupBenchGroup(b, 2)
		b.StartTimer()

		if _, err := g.AddMember(memberKp); err != nil {
			b.Fatalf("AddMember: %v", err)
		}
	}
}

func BenchmarkSendMessage(b *testing.B) {
	g, sigPriv := setupBenchGroup(b, 2)

	data := make([]byte, 1024)
	if _, err := rand.Read(data); err != nil {
		b.Fatalf("rand.Read: %v", err)
	}

	for b.Loop() {
		if _, err := g.SendMessage(data, sigPriv); err != nil {
			b.Fatalf("SendMessage: %v", err)
		}
	}
}

func BenchmarkReceiveMessage(b *testing.B) {
	g, sigPriv := setupBenchGroup(b, 2)

	data := make([]byte, 1024)
	if _, err := rand.Read(data); err != nil {
		b.Fatalf("rand.Read: %v", err)
	}

	for b.Loop() {
		b.StopTimer()
		// Each iteration needs a fresh ciphertext — the secret tree ratchets
		// forward on every decryption, so re-using the same ciphertext would
		// fail on the second iteration with a generation mismatch.
		pm, err := g.SendMessage(data, sigPriv)
		if err != nil {
			b.Fatalf("SendMessage: %v", err)
		}
		b.StartTimer()

		if _, err := g.ReceiveMessage(pm, 0); err != nil {
			b.Fatalf("ReceiveMessage: %v", err)
		}
	}
}
