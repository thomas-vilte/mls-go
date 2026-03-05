package group

import (
	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/internal/tls"
	keypackages "github.com/openmls/go/key_packages"
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
	// Extensions
	_, err = r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	return &GroupContext{
		Version:                 keypackages.ProtocolVersion(version),
		CipherSuite:             ciphersuite.CipherSuite(cipherSuite),
		GroupID:                 NewGroupID(groupID),
		Epoch:                   NewGroupEpoch(epoch),
		TreeHash:                treeHash,
		ConfirmedTranscriptHash: confirmedTranscriptHash,
		Extensions:              []Extension{},
	}, nil
}
