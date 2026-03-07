package treesync

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/credentials"
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

	// SignatureKey (formato uncompressed P-256: 0x04 || X || Y)
	buf.WriteVLBytes(l.marshalSignatureKey())

	// Capabilities
	capsBuf := tls.NewWriter()
	if l.Capabilities != nil {
		l.Capabilities.Marshal(capsBuf)
	}
	buf.WriteVLBytes(capsBuf.Bytes())

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

// UnmarshalLeafNodeData deserializes a LeafNodeData from TLS format (RFC 9420 §7.2).
func UnmarshalLeafNodeData(data []byte) (*LeafNodeData, error) {
	r := tls.NewReader(data)
	return UnmarshalLeafNodeDataFromReader(r)
}

// UnmarshalLeafNodeDataFromReader deserializes a LeafNodeData from a TLS reader.
func UnmarshalLeafNodeDataFromReader(r *tls.Reader) (*LeafNodeData, error) {
	l := &LeafNodeData{}

	// Credential
	credData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	l.Credential, err = credentials.UnmarshalCredential(credData)
	if err != nil {
		return nil, err
	}

	// EncryptionKey
	l.EncryptionKey, err = r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	// SignatureKey (formato uncompressed P-256: 0x04 || X || Y)
	sigKeyBytes, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	if len(sigKeyBytes) == 65 && sigKeyBytes[0] == 0x04 {
		x := new(big.Int).SetBytes(sigKeyBytes[1:33])
		y := new(big.Int).SetBytes(sigKeyBytes[33:65])
		l.SignatureKey = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	}

	// Capabilities
	capsData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	if len(capsData) == 0 {
		l.Capabilities = nil
	} else {
		l.Capabilities, err = UnmarshalCapabilities(tls.NewReader(capsData))
		if err != nil {
			return nil, err
		}
	}

	// Lifetime
	nb, err := r.ReadUint64()
	if err != nil {
		return nil, err
	}
	na, err := r.ReadUint64()
	if err != nil {
		return nil, err
	}
	l.Lifetime = &LeafNodeLifetime{NotBefore: nb, NotAfter: na}

	// Extensions
	extsData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	// For now, store raw extensions
	l.Extensions = [][]byte{extsData}

	// LeafNodeSource
	l.LeafNodeSource, err = r.ReadUint8()
	if err != nil {
		return nil, err
	}

	// ParentHash (only if source == commit)
	if l.LeafNodeSource == 3 {
		l.ParentHash, err = r.ReadVLBytes()
		if err != nil {
			return nil, err
		}
	}

	// Signature
	l.Signature, err = r.ReadVLBytes()
	if err != nil {
		return nil, err
	}

	return l, nil
}

// UnmarshalCapabilities deserializes capabilities.
func UnmarshalCapabilities(r *tls.Reader) (*LeafNodeCapabilities, error) {
	c := &LeafNodeCapabilities{}

	// ProtocolVersions
	versData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	versReader := tls.NewReader(versData)
	for versReader.Remaining() > 0 {
		v, err := versReader.ReadUint16()
		if err != nil {
			return nil, err
		}
		c.ProtocolVersions = append(c.ProtocolVersions, v)
	}

	// CipherSuites
	csData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	csReader := tls.NewReader(csData)
	for csReader.Remaining() > 0 {
		cs, err := csReader.ReadUint16()
		if err != nil {
			return nil, err
		}
		c.CipherSuites = append(c.CipherSuites, cs)
	}

	// Extensions
	extsData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	extsReader := tls.NewReader(extsData)
	for extsReader.Remaining() > 0 {
		e, err := extsReader.ReadUint16()
		if err != nil {
			return nil, err
		}
		c.Extensions = append(c.Extensions, e)
	}

	// Proposals
	propsData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	propsReader := tls.NewReader(propsData)
	for propsReader.Remaining() > 0 {
		p, err := propsReader.ReadUint16()
		if err != nil {
			return nil, err
		}
		c.Proposals = append(c.Proposals, p)
	}

	// Credentials
	credsData, err := r.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	credsReader := tls.NewReader(credsData)
	for credsReader.Remaining() > 0 {
		cr, err := credsReader.ReadUint16()
		if err != nil {
			return nil, err
		}
		c.Credentials = append(c.Credentials, cr)
	}

	return c, nil
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

// Verify verifies the LeafNode signature (RFC 9420 §7.3).
func (l *LeafNodeData) Verify(cs ciphersuite.CipherSuite) error {
	tbs := l.MarshalTBS()

	// Convert *ecdsa.PublicKey to OpenMlsSignaturePublicKey
	// We need the raw bytes. For P-256, it's 0x04 || X || Y
	pubKeyBytes := l.marshalSignatureKey()
	pk := ciphersuite.NewOpenMlsSignaturePublicKey(pubKeyBytes, ciphersuite.SignatureScheme(0)) // scheme not strictly needed for raw verify

	return ciphersuite.VerifyWithLabel(pk, "LeafNodeTBS", tbs, ciphersuite.NewSignature(l.Signature))
}

func (l *LeafNodeData) marshalSignatureKey() []byte {
	if l.SignatureKey == nil {
		return nil
	}
	xBytes := l.SignatureKey.X.Bytes()
	yBytes := l.SignatureKey.Y.Bytes()

	// Pad to 32 bytes
	paddedX := make([]byte, 32)
	copy(paddedX[32-len(xBytes):], xBytes)
	paddedY := make([]byte, 32)
	copy(paddedY[32-len(yBytes):], yBytes)

	res := make([]byte, 65)
	res[0] = 0x04
	copy(res[1:33], paddedX)
	copy(res[33:65], paddedY)
	return res
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
