package group

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/schedule"
)

func TestNewResumptionPSKProposal(t *testing.T) {
	t.Parallel()

	groupID := []byte("test-group-1234")
	var epoch uint64 = 42
	nonce := []byte("nonce-bytes-here1234567890123456") // 32 bytes

	p := NewResumptionPSKProposal(groupID, epoch, nonce)

	if p.Type != ProposalTypePreSharedKey {
		t.Fatalf("expected ProposalTypePreSharedKey, got %d", p.Type)
	}
	if p.PreSharedKey == nil {
		t.Fatal("expected non-nil PreSharedKey")
	}
	if p.PreSharedKey.PskType != 2 {
		t.Fatalf("expected PskType 2 (resumption), got %d", p.PreSharedKey.PskType)
	}
	id := p.PreSharedKey.PskID
	if id.Usage != uint8(schedule.ResumptionUsageApplication) {
		t.Fatalf("expected Usage 0x%02x (application), got 0x%02x", schedule.ResumptionUsageApplication, id.Usage)
	}
	if !bytes.Equal(id.PskGroupID, groupID) {
		t.Fatalf("group ID mismatch: got %x, want %x", id.PskGroupID, groupID)
	}
	if id.PskEpoch != epoch {
		t.Fatalf("epoch mismatch: got %d, want %d", id.PskEpoch, epoch)
	}
	if !bytes.Equal(id.Nonce, nonce) {
		t.Fatalf("nonce mismatch: got %x, want %x", id.Nonce, nonce)
	}
}

func TestNewBranchPSKProposal(t *testing.T) {
	t.Parallel()

	groupID := []byte("branch-group-5678")
	var epoch uint64 = 99
	nonce := []byte("branch-nonce-1234567890123456789") // 32 bytes

	p := NewBranchPSKProposal(groupID, epoch, nonce)

	if p.Type != ProposalTypePreSharedKey {
		t.Fatalf("expected ProposalTypePreSharedKey, got %d", p.Type)
	}
	if p.PreSharedKey == nil {
		t.Fatal("expected non-nil PreSharedKey")
	}
	if p.PreSharedKey.PskType != 2 {
		t.Fatalf("expected PskType 2 (resumption), got %d", p.PreSharedKey.PskType)
	}
	id := p.PreSharedKey.PskID
	if id.Usage != uint8(schedule.ResumptionUsageBranch) {
		t.Fatalf("expected Usage 0x%02x (branch), got 0x%02x", schedule.ResumptionUsageBranch, id.Usage)
	}
	if !bytes.Equal(id.PskGroupID, groupID) {
		t.Fatalf("group ID mismatch: got %x, want %x", id.PskGroupID, groupID)
	}
	if id.PskEpoch != epoch {
		t.Fatalf("epoch mismatch: got %d, want %d", id.PskEpoch, epoch)
	}
	if !bytes.Equal(id.Nonce, nonce) {
		t.Fatalf("nonce mismatch: got %x, want %x", id.Nonce, nonce)
	}
}

func TestNewReInitProposal(t *testing.T) {
	t.Parallel()

	newGroupID := []byte("new-group-id")
	extensions := []Extension{
		{Type: 0xff01, Data: []byte("ext1")},
	}

	p := NewReInitProposal(newGroupID, 1, 0x0001, extensions)

	if p.Type != ProposalTypeReInit {
		t.Fatalf("expected ProposalTypeReInit, got %d", p.Type)
	}
	if p.ReInit == nil {
		t.Fatal("expected non-nil ReInit")
	}
	if !bytes.Equal(p.ReInit.GroupID, newGroupID) {
		t.Fatalf("group ID mismatch: got %x, want %x", p.ReInit.GroupID, newGroupID)
	}
	if len(p.ReInit.Extensions) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(p.ReInit.Extensions))
	}
}

func TestNewGroupContextExtensionsProposal(t *testing.T) {
	t.Parallel()

	extensions := []Extension{
		{Type: 0xff01, Data: []byte("data1")},
		{Type: 0xff02, Data: []byte("data2")},
	}

	p := NewGroupContextExtensionsProposal(extensions)

	if p.Type != ProposalTypeGroupContextExtensions {
		t.Fatalf("expected ProposalTypeGroupContextExtensions, got %d", p.Type)
	}
	if p.GroupContextExtensions == nil {
		t.Fatal("expected non-nil GroupContextExtensions")
	}
	if len(p.GroupContextExtensions.Extensions) != 2 {
		t.Fatalf("expected 2 extensions, got %d", len(p.GroupContextExtensions.Extensions))
	}
	if p.GroupContextExtensions.Extensions[0].Type != 0xff01 {
		t.Fatalf("unexpected extension type: %d", p.GroupContextExtensions.Extensions[0].Type)
	}
}

// TestParseExtensions_RoundTrip verifies ParseExtensions (the exported
// wrapper Client.ProposeGroupContextExtensions uses to decode caller-supplied
// TLS-encoded extension bytes) round-trips a real extension correctly.
//
// NOTE: `go test ./...` (no -coverpkg) attributes coverage per-package, so a
// root-package test calling this indirectly does not count towards group's
// own coverage — this direct test is what actually closes that gap.
func TestParseExtensions_RoundTrip(t *testing.T) {
	t.Parallel()

	ext := Extension{Type: 0xff01, Data: []byte("hello")}
	data := ext.Marshal()

	got, err := ParseExtensions(data)
	if err != nil {
		t.Fatalf("ParseExtensions: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(got))
	}
	if got[0].Type != ext.Type || !bytes.Equal(got[0].Data, ext.Data) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got[0], ext)
	}
}

func TestParseExtensions_Invalid(t *testing.T) {
	t.Parallel()

	if _, err := ParseExtensions([]byte{0xFF, 0xFF, 0xFF}); err == nil {
		t.Fatal("expected error for malformed extension bytes")
	}
}

func TestNewGroupContextExtensionsProposal_Empty(t *testing.T) {
	t.Parallel()

	p := NewGroupContextExtensionsProposal(nil)

	if p.Type != ProposalTypeGroupContextExtensions {
		t.Fatalf("expected ProposalTypeGroupContextExtensions, got %d", p.Type)
	}
	if p.GroupContextExtensions == nil {
		t.Fatal("expected non-nil GroupContextExtensions")
	}
	if len(p.GroupContextExtensions.Extensions) != 0 {
		t.Fatalf("expected 0 extensions, got %d", len(p.GroupContextExtensions.Extensions))
	}
}
