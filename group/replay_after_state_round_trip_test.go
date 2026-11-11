package group

import (
	"bytes"
	"encoding/json"
	"testing"
)

// roundTripState saves g the way the Client does with CacheNone (MarshalState) and loads it back
// (UnmarshalGroupState), so the next operation runs on the restored state.
func roundTripState(t *testing.T, g *Group) *Group {
	t.Helper()
	data, err := g.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState: %v", err)
	}
	restored, err := UnmarshalGroupState(data)
	if err != nil {
		t.Fatalf("UnmarshalGroupState: %v", err)
	}
	return restored
}

// stripGenerationMarks rewrites a state as it was written before the used-generation marks existed: the
// used_application_generations and used_handshake_generations fields are removed from every leaf.
func stripGenerationMarks(t *testing.T, data []byte) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal state: %v", err)
	}
	tree, ok := doc["secret_tree"].(map[string]any)
	if !ok {
		t.Fatal("state has no secret_tree")
	}
	leaves, _ := tree["leaf_states"].(map[string]any)
	for _, raw := range leaves {
		if leaf, ok := raw.(map[string]any); ok {
			delete(leaf, "used_application_generations")
			delete(leaf, "used_handshake_generations")
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal legacy state: %v", err)
	}
	return out
}

// TestConsumedGenerationStaysRefusedAfterStateRoundTrip checks that a generation that was consumed stays refused
// after the group state is saved and loaded again, which the Client does on every operation with CacheNone, the
// default (RFC 9420 §9.2: a generation is not accepted twice, §6.3 the same for application messages).
func TestConsumedGenerationStaysRefusedAfterStateRoundTrip(t *testing.T) {
	t.Run("duplicate_refused_after_state_round_trip", func(t *testing.T) {
		aliceGroup, bobGroup, alice, _ := makeTwoMemberGroups(t)
		m0, err := aliceGroup.SendMessage([]byte("pay 10"), alice.sigPriv)
		if err != nil {
			t.Fatalf("alice SendMessage: %v", err)
		}
		if got, err := bobGroup.ReceiveMessage(m0, aliceGroup.ownLeafIndex); err != nil || !bytes.Equal(got, []byte("pay 10")) {
			t.Fatalf("ReceiveMessage(first) = %q, %v; want %q", got, err, "pay 10")
		}
		if got, err := bobGroup.ReceiveMessage(m0, aliceGroup.ownLeafIndex); err == nil {
			t.Fatalf("duplicate refused in memory? accepted again: %q", got)
		}

		restored := roundTripState(t, bobGroup)
		if got, err := restored.ReceiveMessage(m0, aliceGroup.ownLeafIndex); err == nil {
			t.Fatalf("duplicate accepted after state round trip: %q", got)
		}
	})

	t.Run("new_message_accepted_after_round_trip", func(t *testing.T) {
		aliceGroup, bobGroup, alice, _ := makeTwoMemberGroups(t)
		m0, err := aliceGroup.SendMessage([]byte("pay 10"), alice.sigPriv)
		if err != nil {
			t.Fatalf("alice SendMessage(m0): %v", err)
		}
		if _, err := bobGroup.ReceiveMessage(m0, aliceGroup.ownLeafIndex); err != nil {
			t.Fatalf("ReceiveMessage(m0): %v", err)
		}
		restored := roundTripState(t, bobGroup)

		m1, err := aliceGroup.SendMessage([]byte("pay 20"), alice.sigPriv)
		if err != nil {
			t.Fatalf("alice SendMessage(m1): %v", err)
		}
		got, err := restored.ReceiveMessage(m1, aliceGroup.ownLeafIndex)
		if err != nil || !bytes.Equal(got, []byte("pay 20")) {
			t.Fatalf("new message after round trip = %q, %v; want %q", got, err, "pay 20")
		}
		if got, err := restored.ReceiveMessage(m0, aliceGroup.ownLeafIndex); err == nil {
			t.Fatalf("m0 accepted after the newer m1 was received: %q", got)
		}

		// A second round trip keeps the mark of m1 and the refusal of m0.
		again := roundTripState(t, restored)
		if got, err := again.ReceiveMessage(m1, aliceGroup.ownLeafIndex); err == nil {
			t.Fatalf("duplicate of m1 accepted after a second round trip: %q", got)
		}
		if got, err := again.ReceiveMessage(m0, aliceGroup.ownLeafIndex); err == nil {
			t.Fatalf("m0 accepted after a second round trip: %q", got)
		}
	})

	t.Run("legacy_state_without_mark_fields_loads", func(t *testing.T) {
		aliceGroup, bobGroup, alice, _ := makeTwoMemberGroups(t)
		m0, err := aliceGroup.SendMessage([]byte("pay 10"), alice.sigPriv)
		if err != nil {
			t.Fatalf("alice SendMessage(m0): %v", err)
		}
		if _, err := bobGroup.ReceiveMessage(m0, aliceGroup.ownLeafIndex); err != nil {
			t.Fatalf("ReceiveMessage(m0): %v", err)
		}
		data, err := bobGroup.MarshalState()
		if err != nil {
			t.Fatalf("MarshalState: %v", err)
		}
		restored, err := UnmarshalGroupState(stripGenerationMarks(t, data))
		if err != nil {
			t.Fatalf("legacy state without the mark fields refused: %v", err)
		}

		m1, err := aliceGroup.SendMessage([]byte("pay 20"), alice.sigPriv)
		if err != nil {
			t.Fatalf("alice SendMessage(m1): %v", err)
		}
		got, err := restored.ReceiveMessage(m1, aliceGroup.ownLeafIndex)
		if err != nil || !bytes.Equal(got, []byte("pay 20")) {
			t.Fatalf("new message on a legacy state = %q, %v; want %q", got, err, "pay 20")
		}
	})
}
