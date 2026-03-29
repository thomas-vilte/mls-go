package group

import (
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/internal/tls"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// GroupContext represents the shared, public state of the group per RFC 9420 §8.1.
//
// All members must agree on the GroupContext for the group to function.
// It is hashed into the transcript and used to derive epoch secrets.
//
// ```text
//
//	struct {
//	    ProtocolVersion version = mls10;
//	    CipherSuite cipher_suite;
//	    opaque group_id<V>;
//	    uint64 epoch;
//	    opaque tree_hash<V>;
//	    opaque confirmed_transcript_hash<V>;
//	    Extension extensions<V>;
//	} GroupContext;
//
// ```
type GroupContext struct {
	Version                 keypackages.ProtocolVersion
	CipherSuite             ciphersuite.CipherSuite
	GroupID                 *GroupID
	Epoch                   GroupEpoch
	TreeHash                []byte
	ConfirmedTranscriptHash []byte
	Extensions              []Extension
}

// Clone returns a deep copy of the GroupContext.
func (gc *GroupContext) Clone() *GroupContext {
	if gc == nil {
		return nil
	}

	clonedExtensions := make([]Extension, len(gc.Extensions))
	for i, ext := range gc.Extensions {
		clonedExtensions[i] = Extension{
			Type: ext.Type,
			Data: append([]byte(nil), ext.Data...),
		}
	}

	return &GroupContext{
		Version:                 gc.Version,
		CipherSuite:             gc.CipherSuite,
		GroupID:                 NewGroupID(gc.GroupID.AsSlice()),
		Epoch:                   gc.Epoch,
		TreeHash:                append([]byte(nil), gc.TreeHash...),
		ConfirmedTranscriptHash: append([]byte(nil), gc.ConfirmedTranscriptHash...),
		Extensions:              clonedExtensions,
	}
}

// IncrementEpoch increments the epoch counter.
//
// Called after a commit is merged to advance to the next epoch.
func (gc *GroupContext) IncrementEpoch() {
	gc.Epoch++
}

// UpdateTreeHash updates the tree hash.
//
// Called after the ratchet tree is modified.
func (gc *GroupContext) UpdateTreeHash(newTreeHash []byte) {
	gc.TreeHash = newTreeHash
}

// UpdateConfirmedTranscriptHash updates the confirmed transcript hash.
//
// Called after a commit is confirmed.
func (gc *GroupContext) UpdateConfirmedTranscriptHash(newHash []byte) {
	gc.ConfirmedTranscriptHash = newHash
}

// SetExtensions sets the extensions.
//
// Used when applying GroupContextExtensions proposals.
func (gc *GroupContext) SetExtensions(extensions []Extension) {
	gc.Extensions = extensions
}

// Marshal serializes the GroupContext to TLS format per RFC 9420 §8.1.
func (gc *GroupContext) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteUint16(uint16(gc.Version))
	w.WriteUint16(uint16(gc.CipherSuite))
	w.WriteVLBytes(gc.GroupID.AsSlice())
	w.WriteUint64(gc.Epoch.AsUint64())
	w.WriteVLBytes(gc.TreeHash)
	w.WriteVLBytes(gc.ConfirmedTranscriptHash)

	// Extensions
	extBuf := tls.NewWriter()
	for _, ext := range gc.Extensions {
		extBuf.WriteUint16(ext.Type)
		extBuf.WriteVLBytes(ext.Data)
	}
	w.WriteVLBytes(extBuf.Bytes())

	return w.Bytes()
}

// UnmarshalGroupContext deserializes a GroupContext from TLS format per RFC 9420 §8.1.
func UnmarshalGroupContext(data []byte) (*GroupContext, error) {
	r := tls.NewReader(data)

	version, err := r.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("reading version: %w", err)
	}

	cipherSuite, err := r.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("reading cipher suite: %w", err)
	}

	groupID, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading group ID: %w", err)
	}

	epoch, err := r.ReadUint64()
	if err != nil {
		return nil, fmt.Errorf("reading epoch: %w", err)
	}

	treeHash, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading tree hash: %w", err)
	}

	confirmedTranscriptHash, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading confirmed transcript hash: %w", err)
	}

	extensionsData, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading extensions: %w", err)
	}

	extensions, err := parseExtensions(extensionsData)
	if err != nil {
		return nil, fmt.Errorf("parsing extensions: %w", err)
	}

	return &GroupContext{
		Version:                 keypackages.ProtocolVersion(version),
		CipherSuite:             ciphersuite.CipherSuite(cipherSuite),
		GroupID:                 NewGroupID(groupID),
		Epoch:                   NewGroupEpoch(epoch),
		TreeHash:                treeHash,
		ConfirmedTranscriptHash: confirmedTranscriptHash,
		Extensions:              extensions,
	}, nil
}

// parseExtensions parses a vector of extensions from TLS-encoded data.
func parseExtensions(data []byte) ([]Extension, error) {
	r := tls.NewReader(data)
	var extensions []Extension

	for r.Remaining() > 0 {
		extType, err := r.ReadUint16()
		if err != nil {
			return nil, fmt.Errorf("reading extension type: %w", err)
		}

		extData, err := r.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading extension data: %w", err)
		}

		extensions = append(extensions, Extension{
			Type: extType,
			Data: extData,
		})
	}

	return extensions, nil
}
