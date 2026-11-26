package group

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/schedule"
)

// expectedTranscript returns the confirmation tag and interim transcript hash that RFC 9420 §8.2 assigns to
// g's current epoch: MAC(confirmation_key, confirmed_transcript_hash), then
// Hash(confirmed_transcript_hash || VL(confirmation_tag)).
func expectedTranscript(g *Group) (tag, interim []byte) {
	cth := g.groupContext.ConfirmedTranscriptHash
	tag = schedule.ComputeConfirmationTag(g.cipherSuite, g.epochSecrets.ConfirmationKey.AsSlice(), cth)
	interim = schedule.ComputeInterimTranscriptHash(g.cipherSuite, cth, tag)
	return tag, interim
}

func checkTranscript(t *testing.T, label string, g *Group) {
	t.Helper()
	tag, interim := expectedTranscript(g)
	if got := g.ConfirmationTag(); len(got) == 0 || !bytes.Equal(got, tag) {
		t.Fatalf("%s: ConfirmationTag() = %x, want %x", label, got, tag)
	}
	if got := g.InterimTranscriptHash(); !bytes.Equal(got, interim) {
		t.Fatalf("%s: InterimTranscriptHash() = %x, want %x", label, got, interim)
	}
}

// editState decodes a marshaled state, applies edit to its JSON fields and encodes it again.
func editState(t *testing.T, data []byte, edit func(fields map[string]json.RawMessage)) []byte {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("decoding state JSON: %v", err)
	}
	edit(fields)
	out, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("encoding state JSON: %v", err)
	}
	return out
}

func rawJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encoding JSON value: %v", err)
	}
	return raw
}

// newEpochZeroGroup creates a one-member group at epoch 0 and returns it with its marshaled state.
func newEpochZeroGroup(t *testing.T, name string) (*Group, *testUser, []byte) {
	t.Helper()
	alice := newTestUser(t, name)
	g, err := NewGroup(NewGroupID([]byte(name+"-group")), ciphersuite.MLS128DHKEMP256, alice.kp, alice.priv)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	data, err := g.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState: %v", err)
	}
	return g, alice, data
}

// TestNewGroupEpochZeroTranscriptFollowsRFC checks that NewGroup computes the confirmation tag over the empty
// confirmed transcript hash and the interim transcript hash from it (RFC 9420 §11), and that the GroupInfo of
// epoch 0 carries that tag.
func TestNewGroupEpochZeroTranscriptFollowsRFC(t *testing.T) {
	g, alice, _ := newEpochZeroGroup(t, "alice")
	checkTranscript(t, "NewGroup", g)

	info, err := g.GetGroupInfo(alice.sigPriv)
	if err != nil {
		t.Fatalf("GetGroupInfo: %v", err)
	}
	if !bytes.Equal(info.ConfirmationTag, g.ConfirmationTag()) {
		t.Fatalf("GroupInfo.ConfirmationTag = %x, want %x", info.ConfirmationTag, g.ConfirmationTag())
	}
}

// TestReInitEpochZeroTranscriptFollowsRFC checks that the group NewGroupFromReInit creates also starts epoch 0
// with the RFC 9420 §11 confirmation tag and interim transcript hash.
func TestReInitEpochZeroTranscriptFollowsRFC(t *testing.T) {
	kp, priv := makeSingleKP(t)
	g, err := NewGroupFromReInit(
		makeReInitProposal([]byte("reinit-group")),
		ciphersuite.NewSecret(bytes.Repeat([]byte{0x44}, 32)),
		[]byte("old-group-id"),
		0,
		kp, priv,
	)
	if err != nil {
		t.Fatalf("NewGroupFromReInit: %v", err)
	}
	checkTranscript(t, "NewGroupFromReInit", g)
}

// TestCurrentStateWithoutConfirmationTagIsRefused checks that a state of the current format without a
// confirmation tag is refused: the tag is the integrity check of the epoch secrets.
func TestCurrentStateWithoutConfirmationTagIsRefused(t *testing.T) {
	_, _, data := newEpochZeroGroup(t, "alice")
	stripped := editState(t, data, func(f map[string]json.RawMessage) {
		f["confirmation_tag"] = json.RawMessage("null")
	})
	if _, err := UnmarshalGroupState(stripped); !errors.Is(err, ErrInvalidGroupState) {
		t.Fatalf("UnmarshalGroupState(state without tag) = %v, want ErrInvalidGroupState", err)
	}
}

// TestStateWithInconsistentInterimHashIsRefused checks that a stored interim transcript hash that does not
// follow from the confirmed transcript hash and the confirmation tag is refused.
func TestStateWithInconsistentInterimHashIsRefused(t *testing.T) {
	g, _, data := newEpochZeroGroup(t, "alice")
	bad := append([]byte(nil), g.InterimTranscriptHash()...)
	bad[0] ^= 0xFF
	tampered := editState(t, data, func(f map[string]json.RawMessage) {
		f["interim_transcript_hash"] = rawJSON(t, bad)
	})
	if _, err := UnmarshalGroupState(tampered); !errors.Is(err, ErrInvalidGroupState) {
		t.Fatalf("UnmarshalGroupState(inconsistent interim hash) = %v, want ErrInvalidGroupState", err)
	}
}

// TestStateWithNewerVersionIsRefused checks that a state written by a newer format version is refused
// instead of being read with the rules of this one.
func TestStateWithNewerVersionIsRefused(t *testing.T) {
	_, _, data := newEpochZeroGroup(t, "alice")
	newer := editState(t, data, func(f map[string]json.RawMessage) {
		f["state_version"] = rawJSON(t, stateVersion+1)
	})
	if _, err := UnmarshalGroupState(newer); !errors.Is(err, ErrInvalidGroupState) {
		t.Fatalf("UnmarshalGroupState(newer state version) = %v, want ErrInvalidGroupState", err)
	}
}

// TestLegacyEpochZeroStateIsMigrated checks that an epoch 0 state saved by an earlier version, with no
// format version, no confirmation tag and the old interim hash Hash(VL("")), is migrated to the RFC values
// when loaded instead of being refused.
func TestLegacyEpochZeroStateIsMigrated(t *testing.T) {
	g, _, data := newEpochZeroGroup(t, "alice")
	legacyInterim := schedule.ComputeInterimTranscriptHash(g.cipherSuite, nil, nil)
	legacy := editState(t, data, func(f map[string]json.RawMessage) {
		delete(f, "state_version")
		f["confirmation_tag"] = json.RawMessage("null")
		f["interim_transcript_hash"] = rawJSON(t, legacyInterim)
	})
	restored, err := UnmarshalGroupState(legacy)
	if err != nil {
		t.Fatalf("UnmarshalGroupState(legacy epoch 0 state): %v", err)
	}
	checkTranscript(t, "legacy epoch 0 state", restored)
}

// TestLegacyExternalJoinerStateIsMigrated checks that an external joiner state saved by an earlier version,
// with no format version and no confirmation tag, is migrated: its interim hash was already computed from the
// real tag, so loading recomputes the tag and keeps the interim hash.
func TestLegacyExternalJoinerStateIsMigrated(t *testing.T) {
	_, joiner, _, sc := joinByExternalCommit(t)
	data, err := joiner.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState: %v", err)
	}
	legacy := editState(t, data, func(f map[string]json.RawMessage) {
		delete(f, "state_version")
		f["confirmation_tag"] = json.RawMessage("null")
	})
	restored, err := UnmarshalGroupState(legacy)
	if err != nil {
		t.Fatalf("UnmarshalGroupState(legacy external joiner state): %v", err)
	}
	if want := sc.authenticatedContent.Auth.ConfirmationTag; !bytes.Equal(restored.ConfirmationTag(), want) {
		t.Fatalf("migrated tag = %x, want the commit's %x", restored.ConfirmationTag(), want)
	}
	checkTranscript(t, "legacy external joiner state", restored)
}

// TestGroupInfoWithEmptyConfirmationTagIsRefused checks that UnmarshalGroupInfo refuses a GroupInfo whose
// confirmation tag is empty. Every epoch has a tag of Nh bytes (RFC 9420 §8.2, §11), so an external joiner
// fails before it stores a commit the group would reject.
func TestGroupInfoWithEmptyConfirmationTagIsRefused(t *testing.T) {
	aliceGroup, _, alice, _ := makeTwoMemberGroups(t)
	info, err := aliceGroup.GetGroupInfo(alice.sigPriv)
	if err != nil {
		t.Fatalf("GetGroupInfo: %v", err)
	}
	if _, err := UnmarshalGroupInfo(info.Marshal()); err != nil {
		t.Fatalf("UnmarshalGroupInfo(genuine GroupInfo): %v", err)
	}
	info.ConfirmationTag = nil
	if _, err := UnmarshalGroupInfo(info.Marshal()); err == nil {
		t.Fatal("UnmarshalGroupInfo accepted a GroupInfo with an empty confirmation tag")
	}
}
