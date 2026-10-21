package group

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/internal/tls"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/treesync"
)

// credentialTestIdentity identifies the BasicCredential used in these tests.
var credentialTestIdentity = []byte("alice")

// recoverPanic runs fn and returns the value it panicked with, or nil if fn returned
// normally. Without it, a panic inside a subtest aborts the whole test binary.
func recoverPanic(fn func()) (panicked any) {
	defer func() {
		panicked = recover()
	}()
	fn()
	return nil
}

// newCredentialTestKeyPackage returns a valid CS1 KeyPackage with a BasicCredential.
func newCredentialTestKeyPackage(t *testing.T) *keypackages.KeyPackage {
	t.Helper()
	cred, _, err := credentials.GenerateCredentialWithKeyForCS(credentialTestIdentity, ciphersuite.MLS128DHKEMX25519)
	if err != nil {
		t.Fatalf("GenerateCredentialWithKeyForCS: %v", err)
	}
	kp, _, err := keypackages.Generate(cred, keypackages.MLS128DHKEMX25519)
	if err != nil {
		t.Fatalf("keypackages.Generate: %v", err)
	}
	return kp
}

// keyPackageBytesWithCredentialType returns a copy of kpBytes in which the BasicCredential
// (uint16 credential_type || VL(identity)) carries credential_type ct instead. The
// encoded credential must occur exactly once, so no other field is ever modified.
func keyPackageBytesWithCredentialType(t *testing.T, kpBytes []byte, ct uint16) []byte {
	t.Helper()
	w := tls.NewWriter()
	w.WriteUint16(uint16(credentials.BasicCredential))
	w.WriteVLBytes(credentialTestIdentity)
	pattern := w.Bytes()
	if n := bytes.Count(kpBytes, pattern); n != 1 {
		t.Fatalf("encoded BasicCredential found %d times, want 1", n)
	}
	out := bytes.Clone(kpBytes)
	idx := bytes.Index(out, pattern)
	out[idx] = byte(ct >> 8)
	out[idx+1] = byte(ct)
	return out
}

// TestCredentialParsingAndValidation checks that reserved credential types are
// rejected and nil credentials do not panic during validation or marshaling.
func TestCredentialParsingAndValidation(t *testing.T) {
	kp := newCredentialTestKeyPackage(t)
	kpBytes := kp.Marshal()

	t.Run("control_valid_basic_credential", func(t *testing.T) {
		got, err := keypackages.UnmarshalKeyPackage(kpBytes)
		if err != nil {
			t.Fatalf("UnmarshalKeyPackage(valid): %v", err)
		}
		cred := got.LeafNode.Credential
		if cred == nil || cred.Type() != credentials.BasicCredential {
			t.Fatalf("parsed credential = %v, want BasicCredential", cred)
		}
		if err := kp.Verify(ciphersuite.MLS128DHKEMX25519); err != nil {
			t.Fatalf("Verify(valid KeyPackage): %v", err)
		}
		add := &Proposal{Type: ProposalTypeAdd, Add: &AddProposal{KeyPackage: kp}}
		if len(ProposalMarshal(add)) == 0 {
			t.Fatal("ProposalMarshal(valid Add) returned no bytes")
		}
	})

	t.Run("type0_keypackage_rejected", func(t *testing.T) {
		bad := keyPackageBytesWithCredentialType(t, kpBytes, 0x0000)
		var err error
		if p := recoverPanic(func() { _, err = keypackages.UnmarshalKeyPackage(bad) }); p != nil {
			t.Fatalf("UnmarshalKeyPackage panicked: %v", p)
		}
		if err == nil {
			t.Fatal("UnmarshalKeyPackage accepted reserved credential_type 0x0000")
		}
	})

	t.Run("type0_credential_parsers_rejected", func(t *testing.T) {
		w := tls.NewWriter()
		w.WriteUint16(0x0000)
		w.WriteVLBytes(credentialTestIdentity)
		data := w.Bytes()

		var cred *credentials.Credential
		var err error
		if p := recoverPanic(func() { cred, err = credentials.UnmarshalCredential(data) }); p != nil {
			t.Fatalf("UnmarshalCredential panicked: %v", p)
		}
		if err == nil {
			t.Errorf("UnmarshalCredential accepted reserved credential_type 0x0000 (got %v)", cred)
		}

		if p := recoverPanic(func() { cred, err = credentials.UnmarshalCredentialFromReader(tls.NewReader(data)) }); p != nil {
			t.Fatalf("UnmarshalCredentialFromReader panicked: %v", p)
		}
		if err == nil {
			t.Errorf("UnmarshalCredentialFromReader accepted reserved credential_type 0x0000 (got %v)", cred)
		}
	})

	t.Run("type0_external_sender_rejected", func(t *testing.T) {
		// ExternalSenders<V> entry: VL(signature_key) || Credential (inline), wrapped in VL.
		entry := tls.NewWriter()
		entry.WriteVLBytes([]byte{0x01, 0x02, 0x03})
		entry.WriteUint16(0x0000)
		entry.WriteVLBytes(nil)
		outer := tls.NewWriter()
		outer.WriteVLBytes(entry.Bytes())

		var err error
		if p := recoverPanic(func() { _, err = parseExternalSenders(outer.Bytes()) }); p != nil {
			t.Fatalf("parseExternalSenders panicked: %v", p)
		}
		if err == nil {
			t.Fatal("parseExternalSenders accepted an external sender with credential_type 0x0000")
		}
	})

	t.Run("nil_credential_verify_returns_error", func(t *testing.T) {
		nilCred := newCredentialTestKeyPackage(t)
		nilCred.LeafNode.Credential = nil
		var err error
		if p := recoverPanic(func() { err = nilCred.Verify(ciphersuite.MLS128DHKEMX25519) }); p != nil {
			t.Fatalf("KeyPackage.Verify panicked with nil credential: %v", p)
		}
		if err == nil {
			t.Fatal("KeyPackage.Verify accepted a KeyPackage with nil credential")
		}
	})

	t.Run("nil_credential_validate_returns_error", func(t *testing.T) {
		nilCred := newCredentialTestKeyPackage(t)
		nilCred.LeafNode.Credential = nil
		leafData := &treesync.LeafNodeData{
			EncryptionKey:   []byte{0x01},
			SignatureKeyRaw: []byte{0x02},
		}
		checks := map[string]func() error{
			"KeyPackage.Validate": nilCred.Validate,
			"LeafNode.Validate":   nilCred.LeafNode.Validate,
			"treesync.ValidateLeafNode": func() error {
				return treesync.ValidateLeafNode(leafData, ciphersuite.MLS128DHKEMX25519)
			},
		}
		for name, check := range checks {
			var err error
			if p := recoverPanic(func() { err = check() }); p != nil {
				t.Fatalf("%s panicked with nil credential: %v", name, p)
			}
			if err == nil {
				t.Errorf("%s accepted a nil credential", name)
			}
		}
	})

	t.Run("nil_credential_ProposalMarshal_no_panic", func(t *testing.T) {
		nilCred := newCredentialTestKeyPackage(t)
		nilCred.LeafNode.Credential = nil
		proposals := []*Proposal{
			{Type: ProposalTypeAdd, Add: &AddProposal{KeyPackage: nilCred}},
			{Type: ProposalTypeUpdate, Update: &UpdateProposal{LeafNode: nilCred.LeafNode}},
		}
		for _, prop := range proposals {
			if p := recoverPanic(func() { _ = ProposalMarshal(prop) }); p != nil {
				t.Fatalf("ProposalMarshal(%v) panicked with nil credential: %v", prop.Type, p)
			}
		}
	})
}
