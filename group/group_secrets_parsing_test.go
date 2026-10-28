package group

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/internal/tls"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// encodeTestGroupSecrets encodes GroupSecrets with the given presence octet, path secret (used when the octet
// is 1) and psks<V> body.
func encodeTestGroupSecrets(presence uint8, pathSecret, psks []byte) []byte {
	w := tls.NewWriter()
	w.WriteVLBytes(bytes.Repeat([]byte{0x11}, 32))
	w.WriteUint8(presence)
	if presence == 1 {
		w.WriteVLBytes(pathSecret)
	}
	w.WriteVLBytes(psks)
	return w.Bytes()
}

// encodeTestExternalPSKID encodes one external PreSharedKeyID with the given psktype octet.
func encodeTestExternalPSKID(pskType uint8) []byte {
	psk := tls.NewWriter()
	psk.WriteUint8(pskType)
	psk.WriteVLBytes([]byte{0xAB}) // id
	psk.WriteVLBytes([]byte{0xCD}) // nonce
	return psk.Bytes()
}

// TestUnmarshalGroupSecretsRejectsInvalidPresenceOctet checks that optional<PathSecret> accepts a presence
// octet of 0 or 1 only.
func TestUnmarshalGroupSecretsRejectsInvalidPresenceOctet(t *testing.T) {
	path := bytes.Repeat([]byte{0x22}, 32)
	cases := []struct {
		presence uint8
		ok       bool
	}{{0, true}, {1, true}, {2, false}, {0xFF, false}}
	for _, tc := range cases {
		_, err := UnmarshalGroupSecrets(encodeTestGroupSecrets(tc.presence, path, nil))
		if tc.ok && err != nil {
			t.Errorf("presence octet %d rejected: %v", tc.presence, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("presence octet %d accepted, want rejection (RFC 9420 §2.1.1)", tc.presence)
		}
	}
}

// TestUnmarshalGroupSecretsRejectsUndefinedPSKType checks that external and resumption PSK IDs parse and every
// other PSKType is an error (RFC 9420 §8.4).
func TestUnmarshalGroupSecretsRejectsUndefinedPSKType(t *testing.T) {
	if _, err := UnmarshalGroupSecrets(encodeTestGroupSecrets(0, nil, encodeTestExternalPSKID(1))); err != nil {
		t.Fatalf("control: external psktype rejected: %v", err)
	}
	resumption := tls.NewWriter()
	resumption.WriteUint8(2)              // psktype resumption
	resumption.WriteUint8(1)              // usage
	resumption.WriteVLBytes([]byte{0x01}) // psk_group_id
	resumption.WriteUint64(7)             // psk_epoch
	resumption.WriteVLBytes([]byte{0xCD}) // psk_nonce
	if _, err := UnmarshalGroupSecrets(encodeTestGroupSecrets(0, nil, resumption.Bytes())); err != nil {
		t.Fatalf("control: resumption psktype rejected: %v", err)
	}
	for _, ty := range []uint8{0, 3, 7} {
		if _, err := UnmarshalGroupSecrets(encodeTestGroupSecrets(0, nil, encodeTestExternalPSKID(ty))); err == nil {
			t.Errorf("GroupSecrets accepted undefined psktype %d", ty)
		}
	}
}

// TestUnmarshalPreSharedKeyProposalRejectsUndefinedPSKType checks that the PreSharedKey proposal follows the
// same PSKType rule as GroupSecrets.
func TestUnmarshalPreSharedKeyProposalRejectsUndefinedPSKType(t *testing.T) {
	build := func(pskType uint8) []byte {
		w := tls.NewWriter()
		w.WriteUint16(uint16(ProposalTypePreSharedKey))
		w.WriteUint8(pskType)
		w.WriteVLBytes([]byte{0xAB}) // id
		w.WriteVLBytes([]byte{0xCD}) // nonce
		return w.Bytes()
	}
	if _, err := UnmarshalProposal(build(1)); err != nil {
		t.Fatalf("control: external psktype proposal rejected: %v", err)
	}
	for _, ty := range []uint8{0, 3, 7} {
		if _, err := UnmarshalProposal(build(ty)); err == nil {
			t.Errorf("PreSharedKey proposal accepted undefined psktype %d", ty)
		}
	}
}

// TestUnmarshalProposalRejectsTrailingBytes checks that a Remove proposal followed by bytes is an error.
func TestUnmarshalProposalRejectsTrailingBytes(t *testing.T) {
	w := tls.NewWriter()
	w.WriteUint16(uint16(ProposalTypeRemove))
	w.WriteUint32(1)
	remove := w.Bytes()
	if _, err := UnmarshalProposal(remove); err != nil {
		t.Fatalf("control: UnmarshalProposal(remove) = %v", err)
	}
	if _, err := UnmarshalProposal(append(append([]byte{}, remove...), 0xDE, 0xAD, 0xBE, 0xEF)); err == nil {
		t.Error("UnmarshalProposal(remove) accepted 4 trailing bytes")
	}
}

// TestUnmarshalGroupContextRejectsTrailingBytes checks that UnmarshalGroupContext reads exactly one
// GroupContext, while the reader variant leaves the remaining bytes to its caller.
func TestUnmarshalGroupContextRejectsTrailingBytes(t *testing.T) {
	gc := &GroupContext{
		Version:                 keypackages.MLS10,
		CipherSuite:             ciphersuite.MLS128DHKEMP256,
		GroupID:                 NewGroupID([]byte("parse-group")),
		Epoch:                   NewGroupEpoch(3),
		TreeHash:                bytes.Repeat([]byte{0x33}, 32),
		ConfirmedTranscriptHash: bytes.Repeat([]byte{0x44}, 32),
	}
	raw := gc.Marshal()
	if _, err := UnmarshalGroupContext(raw); err != nil {
		t.Fatalf("control: UnmarshalGroupContext(valid) = %v", err)
	}
	if _, err := UnmarshalGroupContext(append(append([]byte{}, raw...), 0xAA)); err == nil {
		t.Error("UnmarshalGroupContext accepted a trailing byte")
	}

	r := tls.NewReader(append(append([]byte{}, raw...), 0xAA))
	if _, err := UnmarshalGroupContextFromReader(r); err != nil {
		t.Fatalf("UnmarshalGroupContextFromReader: %v", err)
	}
	if r.Remaining() != 1 {
		t.Errorf("reader left %d bytes after the GroupContext, want 1", r.Remaining())
	}
}
