package treesync

import (
	"crypto/sha256"
	"errors"

	"github.com/openmls/go/internal/tls"
)

// Marshal serializes LeafNodeData to TLS format (RFC 9420 §7.2).
func (l *LeafNodeData) Marshal() []byte {
	buf := tls.NewWriter()

	// TBS portion
	buf.WriteRaw(l.MarshalTBS())

	// Signature
	buf.WriteVLBytes(l.Signature)

	return buf.Bytes()
}

// MarshalTBS serializes the To-Be-Signed portion of LeafNode (RFC 9420 §7.2).
func (l *LeafNodeData) MarshalTBS() []byte {
	buf := tls.NewWriter()

	// Credential
	if l.Credential != nil {
		buf.WriteRaw(l.Credential.Marshal())
	} else {
		buf.WriteVLBytes([]byte{})
	}

	// EncryptionKey
	buf.WriteVLBytes(l.EncryptionKey)

	// Capabilities
	if l.Capabilities != nil {
		l.Capabilities.Marshal(buf)
	} else {
		buf.WriteUint8(0)
	}

	// Lifetime
	if l.Lifetime != nil {
		buf.WriteUint64(l.Lifetime.NotBefore)
		buf.WriteUint64(l.Lifetime.NotAfter)
	} else {
		buf.WriteUint64(0)
		buf.WriteUint64(0)
	}

	// Extensions
	extBuf := tls.NewWriter()
	for _, extData := range l.Extensions {
		extBuf.WriteRaw(extData)
	}
	buf.WriteVLBytes(extBuf.Bytes())

	// LeafNodeSource
	buf.WriteUint8(l.LeafNodeSource)

	// ParentHash (only if source == commit)
	if l.LeafNodeSource == 3 { // commit
		buf.WriteVLBytes(l.ParentHash)
	}

	return buf.Bytes()
}

// Marshal serializes LeafNodeCapabilities to TLS format.
func (c *LeafNodeCapabilities) Marshal(buf *tls.Writer) {
	verBuf := tls.NewWriter()
	for _, v := range c.ProtocolVersions {
		verBuf.WriteUint16(v)
	}
	buf.WriteVLBytes(verBuf.Bytes())

	csBuf := tls.NewWriter()
	for _, cs := range c.CipherSuites {
		csBuf.WriteUint16(cs)
	}
	buf.WriteVLBytes(csBuf.Bytes())

	extBuf := tls.NewWriter()
	for _, e := range c.Extensions {
		extBuf.WriteUint16(e)
	}
	buf.WriteVLBytes(extBuf.Bytes())

	propBuf := tls.NewWriter()
	for _, p := range c.Proposals {
		propBuf.WriteUint16(p)
	}
	buf.WriteVLBytes(propBuf.Bytes())

	credBuf := tls.NewWriter()
	for _, c := range c.Credentials {
		credBuf.WriteUint16(c)
	}
	buf.WriteVLBytes(credBuf.Bytes())
}

// Hash computes the hash of a LeafNode.
func (l *LeafNodeData) Hash() []byte {
	data := l.Marshal()
	hash := sha256.Sum256(data)
	return hash[:]
}

// Validate validates a LeafNode according to RFC 9420 §7.3.
func (l *LeafNodeData) Validate() error {
	if len(l.EncryptionKey) == 0 {
		return errors.New("encryption_key is empty")
	}

	if l.SignatureKey == nil {
		return errors.New("signature_key is nil")
	}

	if l.Credential == nil {
		return errors.New("credential is nil")
	}

	if err := l.Credential.Validate(); err != nil {
		return err
	}

	if l.Capabilities == nil {
		return errors.New("capabilities is nil")
	}

	if len(l.Signature) == 0 {
		return errors.New("signature is empty")
	}

	return nil
}

// clone creates a deep copy of a node.
func (n Node) clone() Node {
	result := Node{
		State:          n.State,
		ParentHash:     append([]byte(nil), n.ParentHash...),
		UnmergedLeaves: make([]LeafIndex, len(n.UnmergedLeaves)),
	}

	if n.EncryptionKey != nil {
		result.EncryptionKey = n.EncryptionKey
	}

	copy(result.UnmergedLeaves, n.UnmergedLeaves)

	if n.LeafData != nil {
		result.LeafData = n.LeafData.clone()
	}

	return result
}

// clone creates a deep copy of LeafNodeData.
func (l *LeafNodeData) clone() *LeafNodeData {
	if l == nil {
		return nil
	}

	result := &LeafNodeData{
		EncryptionKey:  append([]byte(nil), l.EncryptionKey...),
		ParentHash:     append([]byte(nil), l.ParentHash...),
		Signature:      append([]byte(nil), l.Signature...),
		LeafNodeSource: l.LeafNodeSource,
	}

	if l.Credential != nil {
		result.Credential = l.Credential
	}

	if l.SignatureKey != nil {
		result.SignatureKey = l.SignatureKey
	}

	if l.Capabilities != nil {
		result.Capabilities = l.Capabilities.clone()
	}

	if l.Lifetime != nil {
		result.Lifetime = &LeafNodeLifetime{
			NotBefore: l.Lifetime.NotBefore,
			NotAfter:  l.Lifetime.NotAfter,
		}
	}

	result.Extensions = make([][]byte, len(l.Extensions))
	for i := range l.Extensions {
		result.Extensions[i] = append([]byte(nil), l.Extensions[i]...)
	}

	return result
}

// Clone creates a public deep copy of LeafNodeData.
func (l *LeafNodeData) Clone() *LeafNodeData {
	return l.clone()
}

// clone creates a deep copy of LeafNodeCapabilities.
func (c *LeafNodeCapabilities) clone() *LeafNodeCapabilities {
	if c == nil {
		return nil
	}

	result := &LeafNodeCapabilities{
		ProtocolVersions: append([]uint16(nil), c.ProtocolVersions...),
		CipherSuites:     append([]uint16(nil), c.CipherSuites...),
		Extensions:       append([]uint16(nil), c.Extensions...),
		Proposals:        append([]uint16(nil), c.Proposals...),
		Credentials:      append([]uint16(nil), c.Credentials...),
	}

	return result
}

// Validate validates a node.
func (n Node) Validate(index NodeIndex, numLeaves uint32) error {
	if index%2 == 0 {
		if n.State == NodeStatePresent && n.LeafData == nil {
			return errors.New("present leaf has nil LeafData")
		}
	} else {
		if n.State == NodeStatePresent {
			if n.EncryptionKey == nil {
				return errors.New("present parent has nil EncryptionKey")
			}
			if len(n.ParentHash) == 0 {
				return errors.New("present parent has empty ParentHash")
			}
		}
	}

	return nil
}
