package group

import (
	"fmt"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/internal/tls"
	keypackages "github.com/openmls/go/keypackages"
)

// GroupContext represents the shared, public state of the group (RFC 9420 §8.1).
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
type GroupContext struct {
	Version                 keypackages.ProtocolVersion
	CipherSuite             ciphersuite.CipherSuite
	GroupID                 *GroupID
	Epoch                   GroupEpoch
	TreeHash                []byte
	ConfirmedTranscriptHash []byte
	Extensions              []Extension
}

// IncrementEpoch increments the epoch counter.
func (gc *GroupContext) IncrementEpoch() {
	gc.Epoch++
}

// UpdateTreeHash updates the tree hash.
func (gc *GroupContext) UpdateTreeHash(newTreeHash []byte) {
	gc.TreeHash = newTreeHash
}

// UpdateConfirmedTranscriptHash updates the confirmed transcript hash.
func (gc *GroupContext) UpdateConfirmedTranscriptHash(newHash []byte) {
	gc.ConfirmedTranscriptHash = newHash
}

// SetExtensions sets the extensions.
func (gc *GroupContext) SetExtensions(extensions []Extension) {
	gc.Extensions = extensions
}

// Marshal serializes the GroupContext to TLS format.
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

// UnmarshalGroupContext deserializes a GroupContext from TLS format.
func UnmarshalGroupContext(data []byte) (*GroupContext, error) {
	r := tls.NewReader(data)
	version, err := r.ReadUint16()
	if err != nil {
		return nil, err
	}
	cipherSuite, err := r.ReadUint16()
	if err != nil {
		return nil, err
	}
	groupID, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	epoch, err := r.ReadUint64()
	if err != nil {
		return nil, err
	}
	treeHash, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	confirmedTranscriptHash, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	// Extensions - parsear correctamente
	extensionsData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
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

// Función auxiliar para parsear extensions
func parseExtensions(data []byte) ([]Extension, error) {
	r := tls.NewReader(data)
	var extensions []Extension

	for r.Remaining() > 0 {
		extType, err := r.ReadUint16()
		if err != nil {
			return nil, err
		}

		extData, err := r.ReadVLBytes()
		if err != nil {
			return nil, err
		}

		extensions = append(extensions, Extension{
			Type: extType,
			Data: extData,
		})
	}

	return extensions, nil
}
