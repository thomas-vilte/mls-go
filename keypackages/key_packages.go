// Package keypackages implements MLS KeyPackages according to RFC 9420 §10.
//
// KeyPackages are used to add new members to MLS groups.
// They contain the member's public keys and capabilities.
package keypackages

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/openmls/go/credentials"
	"github.com/openmls/go/internal/tls"
)

// CipherSuite represents an MLS cipher suite.
type CipherSuite uint16

const (
	// MLS_128_DHKEMP256_AES128GCM_SHA256_P256 is the baseline cipher suite for MLS.
	// This is the only cipher suite required for DAVE compatibility.
	MLS128DHKEMP256 CipherSuite = 0x0002
)

// ProtocolVersion represents the MLS protocol version.
type ProtocolVersion uint16

const (
	// MLS10 is MLS version 1.0 (RFC 9420).
	MLS10 ProtocolVersion = 1
)

// KeyPackage represents an MLS KeyPackage (RFC 9420 §10.1).
//
// KeyPackages are used to add new members to groups.
// They contain HPKE and signature public keys, along with capabilities.
type KeyPackage struct {
	ProtocolVersion ProtocolVersion
	CipherSuite     CipherSuite
	InitKey         []byte // HPKE public key
	LeafNode        *LeafNode
	Extensions      []Extension
	Signature       []byte
}

// LeafNode represents an MLS LeafNode (RFC 9420 §11.2.1).
//
// LeafNodes contain a member's public keys and credentials.
type LeafNode struct {
	EncryptionKey     []byte
	SignatureKey      *ecdsa.PublicKey
	SignatureKeyBytes []byte // For parsing
	Credential        *credentials.Credential
	CredentialBytes   []byte // For parsing
	Capabilities      *Capabilities
	Lifetime          *Lifetime
	Extensions        []Extension
	LeafNodeSource    uint8
	ParentHash        []byte
	Signature         []byte // LeafNode signature
}

// Capabilities represents what a client supports (RFC 9420 §11.2.1).
type Capabilities struct {
	ProtocolVersions []ProtocolVersion
	CipherSuites     []CipherSuite
	Extensions       []uint16
	Proposals        []uint16
	Credentials      []uint16
}

// Lifetime represents the validity period of a LeafNode (RFC 9420 §11.2.1).
type Lifetime struct {
	NotBefore uint64
	NotAfter  uint64
}

// LeafNodeLifetime is an alias for Lifetime.
type LeafNodeLifetime = Lifetime

// Extension represents a KeyPackage extension.
type Extension struct {
	Type uint16
	Data []byte
}

// DefaultCapabilities returns the default capabilities for DAVE compatibility.
func DefaultCapabilities() *Capabilities {
	return &Capabilities{
		ProtocolVersions: []ProtocolVersion{MLS10},
		CipherSuites:     []CipherSuite{MLS128DHKEMP256},
		Extensions:       []uint16{},
		Proposals:        []uint16{},
		Credentials:      []uint16{0x0001}, // BasicCredential
	}
}

// DefaultLifetime returns a Lifetime valid for 24 hours from now.
func DefaultLifetime() *Lifetime {
	now := uint64(time.Now().Unix())
	day := uint64(24 * 60 * 60)

	return &Lifetime{
		NotBefore: now,
		NotAfter:  now + day,
	}
}

// Generate creates a new KeyPackage.
//
// This is the main entry point for creating KeyPackages.
// It generates HPKE and signature keys, creates a LeafNode, and signs everything.
func Generate(credWithKey *credentials.CredentialWithKey, cipherSuite CipherSuite) (*KeyPackage, *KeyPackagePrivateKeys, error) {
	if credWithKey == nil || credWithKey.Credential == nil {
		return nil, nil, errors.New("credential is nil")
	}

	// Generate HPKE key pair (P-256 for MLS)
	hpkePrivKey, hpkePubKey, err := generateHPKEKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("generating HPKE keys: %w", err)
	}

	// Create LeafNode
	leafNode := &LeafNode{
		EncryptionKey:  hpkePubKey.Bytes(),
		SignatureKey:   credWithKey.SignatureKey,
		Credential:     credWithKey.Credential,
		Capabilities:   DefaultCapabilities(),
		Lifetime:       DefaultLifetime(),
		Extensions:     []Extension{},
		LeafNodeSource: 1, // key_package
	}

	// Sign LeafNode
	leafNodeTBS := leafNode.marshalTBS()
	leafNodeSig, err := signData(credWithKey.PrivateKey, leafNodeTBS)
	if err != nil {
		return nil, nil, fmt.Errorf("signing LeafNode: %w", err)
	}
	leafNode.Signature = leafNodeSig

	// Create KeyPackage
	keyPackage := &KeyPackage{
		ProtocolVersion: MLS10,
		CipherSuite:     cipherSuite,
		InitKey:         hpkePubKey.Bytes(),
		LeafNode:        leafNode,
		Extensions:      []Extension{},
	}

	// Sign KeyPackage
	keyPackageTBS := keyPackage.marshalTBS()
	signature, err := signData(credWithKey.PrivateKey, keyPackageTBS)
	if err != nil {
		return nil, nil, fmt.Errorf("signing KeyPackage: %w", err)
	}
	keyPackage.Signature = signature

	// Create private keys
	privKeys := &KeyPackagePrivateKeys{
		InitKey:       hpkePrivKey,
		EncryptionKey: hpkePrivKey,
		SignatureKey:  credWithKey.PrivateKey,
	}

	return keyPackage, privKeys, nil
}

// KeyPackagePrivateKeys contains the private keys associated with a KeyPackage.
//
// These must be kept secret and are used for decryption and signing.
type KeyPackagePrivateKeys struct {
	InitKey       *ecdh.PrivateKey // HPKE private key
	EncryptionKey *ecdh.PrivateKey // Same as InitKey for DAVE
	SignatureKey  *ecdsa.PrivateKey
}

// generateHPKEKeyPair generates a P-256 HPKE key pair.
func generateHPKEKeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	privKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privKey, privKey.PublicKey(), nil
}

// signData signs data with an ECDSA private key using SHA-256.
func signData(privKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return nil, err
	}

	// Concatenate R and S (64 bytes total for P-256)
	signature := append(r.Bytes(), s.Bytes()...)
	return signature, nil
}

// marshalTBS serializes the KeyPackage TBS (To Be Signed).
func (kp *KeyPackage) marshalTBS() []byte {
	buf := tls.NewWriter()

	buf.WriteUint16(uint16(kp.ProtocolVersion))
	buf.WriteUint16(uint16(kp.CipherSuite))
	buf.WriteVLBytes(kp.InitKey)
	buf.WriteRaw(kp.LeafNode.Marshal())

	// Extensions<V>
	extBuf := tls.NewWriter()
	for _, ext := range kp.Extensions {
		extBuf.WriteUint16(ext.Type)
		extBuf.WriteVLBytes(ext.Data)
	}
	buf.WriteVLBytes(extBuf.Bytes())

	return buf.Bytes()
}

// Marshal serializes the KeyPackage to TLS format.
func (kp *KeyPackage) Marshal() []byte {
	tbsBytes := kp.marshalTBS()

	buf := tls.NewWriter()
	buf.WriteRaw(tbsBytes)
	buf.WriteVLBytes(kp.Signature)

	return buf.Bytes()
}

// Marshal serializes the LeafNode to TLS format.
func (ln *LeafNode) Marshal() []byte {
	buf := tls.NewWriter()

	buf.WriteVLBytes(ln.EncryptionKey)

	// Serialize ECDSA public key as uncompressed point (0x04 || X || Y)
	pubKeyBytes := append([]byte{0x04}, ln.SignatureKey.X.Bytes()...)
	pubKeyBytes = append(pubKeyBytes, ln.SignatureKey.Y.Bytes()...)
	buf.WriteRaw(pubKeyBytes)

	buf.WriteRaw(ln.Credential.Marshal())

	// Capabilities
	if ln.Capabilities != nil {
		ln.Capabilities.Marshal(buf)
	} else {
		buf.WriteUint8(0) // Empty capabilities
	}

	// Lifetime
	if ln.Lifetime != nil {
		buf.WriteUint64(ln.Lifetime.NotBefore)
		buf.WriteUint64(ln.Lifetime.NotAfter)
	} else {
		buf.WriteUint64(0)
		buf.WriteUint64(0)
	}

	// Extensions<V>
	extBuf := tls.NewWriter()
	for _, ext := range ln.Extensions {
		extBuf.WriteUint16(ext.Type)
		extBuf.WriteVLBytes(ext.Data)
	}
	buf.WriteVLBytes(extBuf.Bytes())

	buf.WriteUint8(ln.LeafNodeSource)
	buf.WriteVLBytes(ln.ParentHash)

	return buf.Bytes()
}

// marshalTBS serializes the LeafNode TBS.
func (ln *LeafNode) marshalTBS() []byte {
	buf := tls.NewWriter()

	buf.WriteVLBytes(ln.EncryptionKey)

	// Serialize ECDSA public key as uncompressed point (0x04 || X || Y)
	pubKeyBytes := append([]byte{0x04}, ln.SignatureKey.X.Bytes()...)
	pubKeyBytes = append(pubKeyBytes, ln.SignatureKey.Y.Bytes()...)
	buf.WriteRaw(pubKeyBytes)

	buf.WriteRaw(ln.Credential.Marshal())

	if ln.Capabilities != nil {
		ln.Capabilities.Marshal(buf)
	} else {
		buf.WriteUint8(0)
	}

	if ln.Lifetime != nil {
		buf.WriteUint64(ln.Lifetime.NotBefore)
		buf.WriteUint64(ln.Lifetime.NotAfter)
	} else {
		buf.WriteUint64(0)
		buf.WriteUint64(0)
	}

	extBuf := tls.NewWriter()
	for _, ext := range ln.Extensions {
		extBuf.WriteUint16(ext.Type)
		extBuf.WriteVLBytes(ext.Data)
	}
	buf.WriteVLBytes(extBuf.Bytes())

	buf.WriteUint8(ln.LeafNodeSource)
	buf.WriteVLBytes(ln.ParentHash)

	return buf.Bytes()
}

// Marshal serializes Capabilities to TLS format.
func (c *Capabilities) Marshal(buf *tls.Writer) {
	// ProtocolVersions<V>
	verBuf := tls.NewWriter()
	for _, v := range c.ProtocolVersions {
		verBuf.WriteUint16(uint16(v))
	}
	buf.WriteVLBytes(verBuf.Bytes())

	// CipherSuites<V>
	csBuf := tls.NewWriter()
	for _, cs := range c.CipherSuites {
		csBuf.WriteUint16(uint16(cs))
	}
	buf.WriteVLBytes(csBuf.Bytes())

	// Extensions<V>
	extBuf := tls.NewWriter()
	for _, e := range c.Extensions {
		extBuf.WriteUint16(e)
	}
	buf.WriteVLBytes(extBuf.Bytes())

	// Proposals<V>
	propBuf := tls.NewWriter()
	for _, p := range c.Proposals {
		propBuf.WriteUint16(p)
	}
	buf.WriteVLBytes(propBuf.Bytes())

	// Credentials<V>
	credBuf := tls.NewWriter()
	for _, c := range c.Credentials {
		credBuf.WriteUint16(uint16(c))
	}
	buf.WriteVLBytes(credBuf.Bytes())
}

// Hash computes the hash reference of a KeyPackage.
//
// This is used to identify KeyPackages in Welcome messages.
func (kp *KeyPackage) Hash() []byte {
	data := kp.Marshal()
	hash := sha256.Sum256(data)
	return hash[:]
}

// UnmarshalKeyPackage parses a KeyPackage from TLS format.
func UnmarshalKeyPackage(data []byte) (*KeyPackage, error) {
	buf := tls.NewReader(data)

	protocolVersion, err := buf.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("reading protocol_version: %w", err)
	}

	cipherSuite, err := buf.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("reading cipher_suite: %w", err)
	}

	initKey, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading init_key: %w", err)
	}

	leafNode, err := unmarshalLeafNodeFromReader(buf)
	if err != nil {
		return nil, fmt.Errorf("parsing LeafNode: %w", err)
	}

	// Extensions<V>
	extBytes, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading extensions: %w", err)
	}
	// Extensions parsing - simplified for now
	_ = extBytes // Mark as used

	signature, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading signature: %w", err)
	}

	return &KeyPackage{
		ProtocolVersion: ProtocolVersion(protocolVersion),
		CipherSuite:     CipherSuite(cipherSuite),
		InitKey:         initKey,
		LeafNode:        leafNode,
		Extensions:      nil, // Simplified - extensions parsing is complex
		Signature:       signature,
	}, nil
}

// UnmarshalLeafNode parses a LeafNode from TLS format.
func UnmarshalLeafNode(data []byte) (*LeafNode, error) {
	buf := tls.NewReader(data)
	return unmarshalLeafNodeFromReader(buf)
}

func unmarshalLeafNodeFromReader(buf *tls.Reader) (*LeafNode, error) {
	leafNode := &LeafNode{}

	encKey, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading encryption_key: %w", err)
	}
	leafNode.EncryptionKey = encKey

	sigKeyBytes, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading signature_key: %w", err)
	}
	leafNode.SignatureKeyBytes = append([]byte(nil), sigKeyBytes...)
	if len(sigKeyBytes) == 65 && sigKeyBytes[0] == 0x04 {
		x := new(big.Int).SetBytes(sigKeyBytes[1:33])
		y := new(big.Int).SetBytes(sigKeyBytes[33:65])
		leafNode.SignatureKey = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	}

	cred, err := credentials.UnmarshalCredentialFromReader(buf)
	if err != nil {
		return nil, fmt.Errorf("reading credential: %w", err)
	}
	leafNode.Credential = cred
	if cred != nil {
		leafNode.CredentialBytes = cred.Marshal()
	}

	caps, err := UnmarshalCapabilities(buf)
	if err != nil {
		return nil, fmt.Errorf("reading capabilities: %w", err)
	}
	leafNode.Capabilities = caps

	source, err := buf.ReadUint8()
	if err != nil {
		return nil, fmt.Errorf("reading leaf_node_source: %w", err)
	}
	leafNode.LeafNodeSource = source

	switch leafNode.LeafNodeSource {
	case 1:
		notBefore, err := buf.ReadUint64()
		if err != nil {
			return nil, fmt.Errorf("reading not_before: %w", err)
		}
		notAfter, err := buf.ReadUint64()
		if err != nil {
			return nil, fmt.Errorf("reading not_after: %w", err)
		}
		leafNode.Lifetime = &LeafNodeLifetime{NotBefore: notBefore, NotAfter: notAfter}
	case 2:
	case 3:
		parentHash, err := buf.ReadVLBytes()
		if err != nil {
			return nil, fmt.Errorf("reading parent_hash: %w", err)
		}
		leafNode.ParentHash = parentHash
	default:
		notBefore, err := buf.ReadUint64()
		if err != nil {
			return nil, fmt.Errorf("reading not_before: %w", err)
		}
		notAfter, err := buf.ReadUint64()
		if err != nil {
			return nil, fmt.Errorf("reading not_after: %w", err)
		}
		leafNode.Lifetime = &LeafNodeLifetime{NotBefore: notBefore, NotAfter: notAfter}
	}

	extBytes, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading extensions: %w", err)
	}
	if len(extBytes) > 0 {
		extReader := tls.NewReader(extBytes)
		for extReader.Remaining() > 0 {
			extType, err := extReader.ReadUint16()
			if err != nil {
				break
			}
			extData, err := extReader.ReadVLBytes()
			if err != nil {
				break
			}
			leafNode.Extensions = append(leafNode.Extensions, Extension{
				Type: extType,
				Data: extData,
			})
		}
	}

	signature, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading signature: %w", err)
	}
	leafNode.Signature = signature

	return leafNode, nil
}

// UnmarshalCapabilities parses LeafNodeCapabilities from TLS format.
func UnmarshalCapabilities(buf *tls.Reader) (*Capabilities, error) {
	caps := &Capabilities{}

	// protocol_versions<V>
	verBytes, err := buf.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	verReader := tls.NewReader(verBytes)
	for verReader.Remaining() > 0 {
		v, err := verReader.ReadUint16()
		if err != nil {
			break
		}
		caps.ProtocolVersions = append(caps.ProtocolVersions, ProtocolVersion(v))
	}

	// cipher_suites<V>
	csBytes, err := buf.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	csReader := tls.NewReader(csBytes)
	for csReader.Remaining() > 0 {
		cs, err := csReader.ReadUint16()
		if err != nil {
			break
		}
		caps.CipherSuites = append(caps.CipherSuites, CipherSuite(cs))
	}

	// extensions<V>
	extBytes, err := buf.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	extReader := tls.NewReader(extBytes)
	for extReader.Remaining() > 0 {
		e, err := extReader.ReadUint16()
		if err != nil {
			break
		}
		caps.Extensions = append(caps.Extensions, e)
	}

	// proposals<V>
	propBytes, err := buf.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	propReader := tls.NewReader(propBytes)
	for propReader.Remaining() > 0 {
		p, err := propReader.ReadUint16()
		if err != nil {
			break
		}
		caps.Proposals = append(caps.Proposals, p)
	}

	// credentials<V>
	credBytes, err := buf.ReadVLBytes()
	if err != nil {
		return nil, err
	}
	credReader := tls.NewReader(credBytes)
	for credReader.Remaining() > 0 {
		c, err := credReader.ReadUint16()
		if err != nil {
			break
		}
		caps.Credentials = append(caps.Credentials, uint16(c))
	}

	return caps, nil
}

// Validate validates a KeyPackage according to MLS rules.
func (kp *KeyPackage) Validate() error {
	if kp.ProtocolVersion != MLS10 {
		return fmt.Errorf("unsupported protocol version: %d", kp.ProtocolVersion)
	}

	if kp.CipherSuite != MLS128DHKEMP256 {
		return fmt.Errorf("unsupported cipher suite: %d", kp.CipherSuite)
	}

	if len(kp.InitKey) == 0 {
		return errors.New("init_key is empty")
	}

	if kp.LeafNode == nil {
		return errors.New("LeafNode is nil")
	}

	if err := kp.LeafNode.Validate(); err != nil {
		return fmt.Errorf("LeafNode validation failed: %w", err)
	}

	return nil
}

// Validate validates a LeafNode.
func (ln *LeafNode) Validate() error {
	if len(ln.EncryptionKey) == 0 {
		return errors.New("encryption_key is empty")
	}

	if ln.SignatureKey == nil {
		return errors.New("signature_key is nil")
	}

	if ln.Credential == nil {
		return errors.New("credential is nil")
	}

	if err := ln.Credential.Validate(); err != nil {
		return fmt.Errorf("credential validation failed: %w", err)
	}

	return nil
}
