package group

import (
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/internal/tls"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// reInitProposalBytes encodes a ReInit proposal with a fixed group_id, version MLS10, cipher suite
// MLS128DHKEMP256 and the given extensions<V> vector, already encoded.
func reInitProposalBytes(extensions []byte) []byte {
	w := tls.NewWriter()
	w.WriteUint16(uint16(ProposalTypeReInit))
	w.WriteVLBytes([]byte{0x01, 0x02, 0x03, 0x04})
	w.WriteUint16(uint16(keypackages.MLS10))
	w.WriteUint16(uint16(ciphersuite.MLS128DHKEMP256))
	w.WriteVLBytes(extensions)
	return w.Bytes()
}

// groupContextExtensionsProposalBytes encodes a GroupContextExtensions proposal with the given
// extensions<V> vector, already encoded.
func groupContextExtensionsProposalBytes(extensions []byte) []byte {
	w := tls.NewWriter()
	w.WriteUint16(uint16(ProposalTypeGroupContextExtensions))
	w.WriteVLBytes(extensions)
	return w.Bytes()
}

// oneExtensionList encodes an extensions<V> vector that holds a single Extension.
func oneExtensionList(extType uint16, data []byte) []byte {
	w := tls.NewWriter()
	w.WriteUint16(extType)
	w.WriteVLBytes(data)
	return w.Bytes()
}

// TestUnmarshalProposalRejectsMalformedExtensionList checks that a malformed extensions<V> list in a
// ReInit or GroupContextExtensions proposal is an error. The parse error used to be discarded, so the
// proposal was accepted with nil extensions, as if the list were empty.
func TestUnmarshalProposalRejectsMalformedExtensionList(t *testing.T) {
	valid := oneExtensionList(0x0001, []byte{0xAA})
	// An Extension without its extension_data<V>: the list ends in the middle of an entry.
	truncatedEntry := []byte{0x00, 0x01}
	// extension_data<V> declares 5 bytes and carries only 1.
	shortData := []byte{0x00, 0x01, 0x05, 0xAA}

	// Controls: a valid list is accepted and keeps its extension.
	p, err := UnmarshalProposal(groupContextExtensionsProposalBytes(valid))
	if err != nil {
		t.Fatalf("control: valid GroupContextExtensions = %v", err)
	}
	if n := len(p.GroupContextExtensions.Extensions); n != 1 {
		t.Fatalf("control: valid GroupContextExtensions decoded %d extensions, want 1", n)
	}
	p, err = UnmarshalProposal(reInitProposalBytes(valid))
	if err != nil {
		t.Fatalf("control: valid ReInit = %v", err)
	}
	if n := len(p.ReInit.Extensions); n != 1 {
		t.Fatalf("control: valid ReInit decoded %d extensions, want 1", n)
	}

	for _, ext := range [][]byte{truncatedEntry, shortData} {
		if p, err := UnmarshalProposal(groupContextExtensionsProposalBytes(ext)); err == nil {
			t.Errorf("GroupContextExtensions accepted malformed extension list %x as %d extensions",
				ext, len(p.GroupContextExtensions.Extensions))
		}
		if p, err := UnmarshalProposal(reInitProposalBytes(ext)); err == nil {
			t.Errorf("ReInit accepted malformed extension list %x as %d extensions",
				ext, len(p.ReInit.Extensions))
		}
	}
}
