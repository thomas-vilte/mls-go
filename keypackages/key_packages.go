package keypackages

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	mlsext "github.com/thomas-vilte/mls-go/extensions"
	"github.com/thomas-vilte/mls-go/internal/tls"
	"github.com/thomas-vilte/mls-go/treesync"
)

// CipherSuite is an alias for ciphersuite.CipherSuite.
// Using a type alias (=) instead of a distinct type eliminates the need for
// explicit casts between keypackages.CipherSuite and ciphersuite.CipherSuite.
type CipherSuite = ciphersuite.CipherSuite

// Re-export cipher suite constants for convenience.
const (
	MLS128DHKEMX25519         = ciphersuite.MLS128DHKEMX25519
	MLS128DHKEMP256           = ciphersuite.MLS128DHKEMP256
	MLS128DHKEMX25519ChaCha20 = ciphersuite.MLS128DHKEMX25519ChaCha20
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
	Raw             []byte // Original wire bytes when unmarshaled
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

// Extension re-exports the canonical MLS extension type.
type Extension = mlsext.Extension

// DefaultCapabilities returns the default capabilities for DAVE compatibility.
func DefaultCapabilities() *Capabilities {
	return &Capabilities{
		ProtocolVersions: []ProtocolVersion{MLS10},
		CipherSuites:     []CipherSuite{MLS128DHKEMX25519, MLS128DHKEMP256, MLS128DHKEMX25519ChaCha20},
		Extensions:       []uint16{},
		Proposals:        []uint16{},
		Credentials:      []uint16{0x0001}, // BasicCredential
	}
}

// DefaultLifetime returns a Lifetime valid from 1 hour ago through 90 days from now.
// The 1-hour back-dated not_before matches OpenMLS's default margin for clock skew,
// and is required for cross-interop (OpenMLS rejects KeyPackages where not_before >= now).
func DefaultLifetime() *Lifetime {
	now := uint64(time.Now().Unix())
	margin := uint64(60 * 60)             // 1 hour back (matches OpenMLS DEFAULT_KEY_PACKAGE_LIFETIME_MARGIN_SECONDS)
	lifetime := uint64(83 * 24 * 60 * 60) // 83 days forward; total range < OpenMLS MAX (7261200s ≈ 84 days)
	return &Lifetime{
		NotBefore: now - margin,
		NotAfter:  now + lifetime,
	}
}

// GenerateOption configures optional behavior for Generate.
type GenerateOption func(*generateConfig)

type generateConfig struct {
	lifetime *Lifetime
}

// WithLifetime overrides the default KeyPackage lifetime.
func WithLifetime(notBefore, notAfter uint64) GenerateOption {
	return func(cfg *generateConfig) {
		cfg.lifetime = &Lifetime{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		}
	}
}

// InfiniteLifetime returns a GenerateOption that sets the KeyPackage lifetime to
// not_before=0, not_after=2^64-1, effectively making it never expire.
func InfiniteLifetime() GenerateOption {
	return WithLifetime(0, ^uint64(0))
}

// Generate creates a new KeyPackage.
//
// This is the main entry point for creating KeyPackages.
// It generates HPKE and signature keys, creates a LeafNode, and signs everything.
// Generate creates a new KeyPackage and its associated private keys.
//
// RFC 9420 §10.1
// This function generates the necessary HPKE keys, constructs the LeafNode with the
// provided credential, signs the LeafNode, and finally signs the entire KeyPackage.
// The resulting KeyPackage can be published to a directory or sent directly to a group creator.
func Generate(
	credWithKey *credentials.CredentialWithKey,
	cipherSuite CipherSuite,
	opts ...GenerateOption,
) (*KeyPackage, *KeyPackagePrivateKeys, error) {
	if credWithKey == nil || credWithKey.Credential == nil {
		return nil, nil, errors.New("credential is nil")
	}

	cfg := &generateConfig{
		lifetime: DefaultLifetime(),
	}

	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}

	// Generate two separate HPKE key pairs per RFC §10.1:
	// init_key is used once for Welcome decryption; encryption_key is for TreeKEM.
	initPrivKey, initPubKey, err := generateHPKEKeyPairForCS(cipherSuite)
	if err != nil {
		return nil, nil, fmt.Errorf("generating init HPKE keys: %w", err)
	}
	encPrivKey, encPubKey, err := generateHPKEKeyPairForCS(cipherSuite)
	if err != nil {
		return nil, nil, fmt.Errorf("generating encryption HPKE keys: %w", err)
	}
	// Create LeafNode with capabilities that advertise the actual cipher suite.
	caps := DefaultCapabilities()
	caps.CipherSuites = []CipherSuite{cipherSuite}
	leafNode := &LeafNode{
		EncryptionKey:     encPubKey.Bytes(),
		SignatureKey:      credWithKey.SignatureKey,
		SignatureKeyBytes: credWithKey.SignatureKeyBytes,
		Credential:        credWithKey.Credential,
		Capabilities:      caps,
		Lifetime:          cfg.lifetime,
		Extensions:        []Extension{},
		LeafNodeSource:    1, // key_package
	}
	keyPackage := &KeyPackage{
		ProtocolVersion: MLS10,
		CipherSuite:     cipherSuite,
		InitKey:         initPubKey.Bytes(),
		LeafNode:        leafNode,
		Extensions:      []Extension{},
	}
	var sigPrivKey *ciphersuite.SignaturePrivateKey
	if credWithKey.Ed25519PrivateKey != nil {
		sigPrivKey = ciphersuite.NewEd25519SignaturePrivateKey(credWithKey.Ed25519PrivateKey)
	} else {
		sigPrivKey = ciphersuite.NewSignaturePrivateKey(credWithKey.PrivateKey)
	}
	leafNodeTBS := leafNode.marshalTBS()
	leafNodeSig, err := ciphersuite.SignWithLabel(sigPrivKey, "LeafNodeTBS", leafNodeTBS)
	if err != nil {
		return nil, nil, fmt.Errorf("signing LeafNode: %w", err)
	}
	leafNode.Signature = leafNodeSig.AsSlice()
	keyPackageTBS := keyPackage.marshalTBS()
	signature, err := ciphersuite.SignWithLabel(sigPrivKey, "KeyPackageTBS", keyPackageTBS)
	if err != nil {
		return nil, nil, fmt.Errorf("signing KeyPackage: %w", err)
	}
	keyPackage.Signature = signature.AsSlice()
	privKeys := &KeyPackagePrivateKeys{
		InitKey:             initPrivKey,
		EncryptionKey:       encPrivKey,
		SignatureKey:        credWithKey.PrivateKey,
		Ed25519SignatureKey: credWithKey.Ed25519PrivateKey,
	}
	return keyPackage, privKeys, nil
}

// KeyPackagePrivateKeys contains the private keys associated with a KeyPackage.
//
// These must be kept secret and are used for decryption and signing.
type KeyPackagePrivateKeys struct {
	InitKey             *ecdh.PrivateKey   // HPKE private key for Welcome decryption (one-time use)
	EncryptionKey       *ecdh.PrivateKey   // HPKE private key for TreeKEM (LeafNode.EncryptionKey)
	SignatureKey        *ecdsa.PrivateKey  // nil for Ed25519 (CS1/CS3)
	Ed25519SignatureKey ed25519.PrivateKey // non-nil for CS1/CS3
}

// GetSignaturePrivateKey returns a SignaturePrivateKey for either ECDSA or Ed25519.
func (k *KeyPackagePrivateKeys) GetSignaturePrivateKey() *ciphersuite.SignaturePrivateKey {
	if k.Ed25519SignatureKey != nil {
		return ciphersuite.NewEd25519SignaturePrivateKey(k.Ed25519SignatureKey)
	}
	return ciphersuite.NewSignaturePrivateKey(k.SignatureKey)
}

// generateHPKEKeyPairForCS generates an HPKE key pair for the given cipher suite.
// CS1/CS3 use X25519; CS2 uses P-256.
func generateHPKEKeyPairForCS(cs ciphersuite.CipherSuite) (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	privKey, err := cs.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubKey := privKey.PublicKey()
	return privKey, pubKey, nil
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
		extBuf.WriteUint16(uint16(ext.Type))
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

// Marshal serializes the LeafNode to TLS format (RFC 9420 §7.2): TBS fields + signature.
func (ln *LeafNode) Marshal() []byte {
	buf := tls.NewWriter()
	buf.WriteRaw(ln.marshalTBS())
	buf.WriteVLBytes(ln.Signature)
	return buf.Bytes()
}

// marshalTBS serializes the LeafNode TBS (RFC 9420 §7.2).
// Field order: encryption_key, signature_key, credential, capabilities,
// leaf_node_source, conditional(lifetime|parent_hash), extensions.
func (ln *LeafNode) marshalTBS() []byte {
	buf := tls.NewWriter()

	buf.WriteVLBytes(ln.EncryptionKey)

	// Serialize signature public key, VL-prefixed (RFC 9420 §7.2).
	if len(ln.SignatureKeyBytes) > 0 {
		buf.WriteVLBytes(ln.SignatureKeyBytes)
	} else {
		buf.WriteVLBytes(marshalP256PublicKey(ln.SignatureKey))
	}

	buf.WriteRaw(ln.Credential.Marshal())

	if ln.Capabilities != nil {
		ln.Capabilities.Marshal(buf)
	} else {
		buf.WriteUint8(0)
	}

	// RFC 9420 §7.2: leaf_node_source comes BEFORE the conditional data and extensions.
	buf.WriteUint8(ln.LeafNodeSource)

	switch ln.LeafNodeSource {
	case 1: // key_package: Lifetime { not_before, not_after }
		if ln.Lifetime != nil {
			buf.WriteUint64(ln.Lifetime.NotBefore)
			buf.WriteUint64(ln.Lifetime.NotAfter)
		} else {
			buf.WriteUint64(0)
			buf.WriteUint64(0)
		}
	case 2: // update: nothing
	case 3: // commit: parent_hash<V>
		buf.WriteVLBytes(ln.ParentHash)
	default: // treat as key_package
		if ln.Lifetime != nil {
			buf.WriteUint64(ln.Lifetime.NotBefore)
			buf.WriteUint64(ln.Lifetime.NotAfter)
		} else {
			buf.WriteUint64(0)
			buf.WriteUint64(0)
		}
	}

	// Extensions come AFTER the conditional source data.
	extBuf := tls.NewWriter()
	for _, ext := range ln.Extensions {
		extBuf.WriteUint16(uint16(ext.Type))
		extBuf.WriteVLBytes(ext.Data)
	}
	buf.WriteVLBytes(extBuf.Bytes())

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
		credBuf.WriteUint16(c)
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
	var exts []Extension
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
			exts = append(exts, Extension{Type: mlsext.ExtensionType(extType), Data: extData})
		}
	}

	signature, err := buf.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading signature: %w", err)
	}

	return &KeyPackage{
		ProtocolVersion: ProtocolVersion(protocolVersion),
		CipherSuite:     CipherSuite(cipherSuite),
		InitKey:         initKey,
		LeafNode:        leafNode,
		Extensions:      exts,
		Signature:       signature,
		Raw:             append([]byte(nil), data...),
	}, nil
}

// UnmarshalLeafNode parses a LeafNode from TLS format.
func UnmarshalLeafNode(data []byte) (*LeafNode, error) {
	buf := tls.NewReader(data)
	return unmarshalLeafNodeFromReader(buf)
}

// UnmarshalLeafNodeFromReader parses a LeafNode inline from r, advancing r's position.
func UnmarshalLeafNodeFromReader(r *tls.Reader) (*LeafNode, error) {
	return unmarshalLeafNodeFromReader(r)
}

// UnmarshalKeyPackageFromReader parses a KeyPackage inline from r, advancing r's position.
func UnmarshalKeyPackageFromReader(r *tls.Reader) (*KeyPackage, error) {
	startPos := r.Position()

	protocolVersion, err := r.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("reading protocol_version: %w", err)
	}
	cipherSuite, err := r.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("reading cipher_suite: %w", err)
	}
	initKey, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading init_key: %w", err)
	}
	leafNode, err := unmarshalLeafNodeFromReader(r)
	if err != nil {
		return nil, fmt.Errorf("parsing LeafNode: %w", err)
	}
	extBytes, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading extensions: %w", err)
	}
	var exts []Extension
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
			exts = append(exts, Extension{Type: mlsext.ExtensionType(extType), Data: extData})
		}
	}
	signature, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("reading signature: %w", err)
	}

	endPos := r.Position()
	// Re-read the parsed bytes to store as Raw.
	r.SetPosition(startPos)
	rawBytes, _ := r.ReadBytes(endPos - startPos)

	return &KeyPackage{
		ProtocolVersion: ProtocolVersion(protocolVersion),
		CipherSuite:     CipherSuite(cipherSuite),
		InitKey:         initKey,
		LeafNode:        leafNode,
		Extensions:      exts,
		Signature:       signature,
		Raw:             rawBytes,
	}, nil
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
	// Detect ECDSA P-256 keys by wire format: uncompressed SEC 1 point
	// 0x04 || X || Y = 65 bytes (ciphersuite.P256UncompressedKeySize, RFC 5480 §2.2).
	// Ed25519 keys are 32 bytes and never start with 0x04.
	if len(sigKeyBytes) == ciphersuite.P256UncompressedKeySize && sigKeyBytes[0] == 0x04 {
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
				Type: mlsext.ExtensionType(extType),
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
	verBytes, verReadErr := buf.ReadVLBytes()
	if verReadErr != nil {
		return nil, verReadErr
	}
	verReader := tls.NewReader(verBytes)
	for verReader.Remaining() > 0 {
		v, verErr := verReader.ReadUint16()
		if verErr != nil {
			break
		}
		caps.ProtocolVersions = append(caps.ProtocolVersions, ProtocolVersion(v))
	}

	// cipher_suites<V>
	csBytes, csReadErr := buf.ReadVLBytes()
	if csReadErr != nil {
		return nil, csReadErr
	}
	csReader := tls.NewReader(csBytes)
	for csReader.Remaining() > 0 {
		cs, csErr := csReader.ReadUint16()
		if csErr != nil {
			break
		}
		caps.CipherSuites = append(caps.CipherSuites, CipherSuite(cs))
	}

	// extensions<V>
	extBytes, extReadErr := buf.ReadVLBytes()
	if extReadErr != nil {
		return nil, extReadErr
	}
	extReader := tls.NewReader(extBytes)
	for extReader.Remaining() > 0 {
		e, extLoopErr := extReader.ReadUint16()
		if extLoopErr != nil {
			break
		}
		caps.Extensions = append(caps.Extensions, e)
	}

	// proposals<V>
	propBytes, propReadErr := buf.ReadVLBytes()
	if propReadErr != nil {
		return nil, propReadErr
	}
	propReader := tls.NewReader(propBytes)
	for propReader.Remaining() > 0 {
		p, propErr := propReader.ReadUint16()
		if propErr != nil {
			break
		}
		caps.Proposals = append(caps.Proposals, p)
	}

	// credentials<V>
	credBytes, credErr := buf.ReadVLBytes()
	if credErr != nil {
		return nil, credErr
	}
	credReader := tls.NewReader(credBytes)
	for credReader.Remaining() > 0 {
		c, readErr := credReader.ReadUint16()
		if readErr != nil {
			break
		}
		caps.Credentials = append(caps.Credentials, c)
	}

	//nolint:nilerr // False positive: credErr was already handled above
	return caps, nil
}

// Validate validates a KeyPackage according to MLS rules.
func (kp *KeyPackage) Validate() error {
	if kp.ProtocolVersion != MLS10 {
		return fmt.Errorf("unsupported protocol version: %d", kp.ProtocolVersion)
	}

	if !kp.CipherSuite.IsSupported() {
		return fmt.Errorf("unsupported cipher suite: %d", kp.CipherSuite)
	}

	if len(kp.InitKey) == 0 {
		return errors.New("init_key is empty")
	}

	if kp.LeafNode == nil {
		return errors.New("LeafNode is nil")
	}

	// RFC §10.1: leaf_node_source MUST be key_package (1) in a KeyPackage
	if kp.LeafNode.LeafNodeSource != 1 {
		return fmt.Errorf("leaf_node_source is %d, must be 1 (key_package) in a KeyPackage",
			kp.LeafNode.LeafNodeSource)
	}

	// RFC §10.1: init_key and encryption_key MUST be different (prevents key reuse)
	if bytes.Equal(kp.InitKey, kp.LeafNode.EncryptionKey) {
		return errors.New("init_key and encryption_key must be different (RFC §10.1)")
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

	if ln.SignatureKey == nil && len(ln.SignatureKeyBytes) == 0 {
		return errors.New("signature_key is nil")
	}

	if ln.Credential == nil {
		return errors.New("credential is nil")
	}

	if err := ln.Credential.Validate(); err != nil {
		return fmt.Errorf("credential validation failed: %w", err)
	}

	// RFC §7.3: every extension in LeafNode.extensions MUST be declared in capabilities.extensions
	if ln.Capabilities != nil {
		for _, ext := range ln.Extensions {
			declared := false
			for _, capExt := range ln.Capabilities.Extensions {
				if uint16(ext.Type) == capExt {
					declared = true
					break
				}
			}
			if !declared {
				return fmt.Errorf("extension type 0x%04x not declared in capabilities.extensions (RFC §7.3)",
					ext.Type)
			}
		}
	}

	return nil
}

// MarshalTBS serializes the KeyPackage TBS (To Be Signed) - public version.
// RFC 9420 §10.1: KeyPackageTBS = (version, cipher_suite, init_key, leaf_node, extensions)
func (kp *KeyPackage) MarshalTBS() []byte {
	return kp.marshalTBS()
}

// Verify verifies the KeyPackage signature.
// RFC 9420 §10.1, §12.2: VerifyWithLabel(LeafNode.SignatureKey, "KeyPackageTBS", tbs, signature)
func (kp *KeyPackage) Verify(cs ciphersuite.CipherSuite) error {
	if kp.LeafNode == nil || (kp.LeafNode.SignatureKey == nil && len(kp.LeafNode.SignatureKeyBytes) == 0) {
		return errors.New("keypackage: missing leaf node or signature key")
	}

	// Serialize TBS
	tbs := kp.marshalTBS()

	// Get signature public key bytes
	var pubKeyBytes []byte
	if len(kp.LeafNode.SignatureKeyBytes) > 0 {
		pubKeyBytes = kp.LeafNode.SignatureKeyBytes
	} else {
		// Use treesync.MarshalSignatureKey to ensure correct padding to 32 bytes per coordinate.
		pubKeyBytes = treesync.MarshalSignatureKey(kp.LeafNode.SignatureKey)
	}

	// Create MLS public key
	pk := ciphersuite.NewMLSSignaturePublicKey(pubKeyBytes, cs.SignatureScheme())

	// Verify signature
	sig := ciphersuite.NewSignature(kp.Signature)
	if err := ciphersuite.VerifyWithLabel(pk, "KeyPackageTBS", tbs, sig); err != nil {
		return fmt.Errorf("keypackage: signature verification failed: %w", err)
	}

	return nil
}

// marshalP256PublicKey serializes a P-256 public key as an uncompressed point
// (0x04 || X || Y) with X and Y padded to 32 bytes each (RFC 9420 §7.2).
func marshalP256PublicKey(key *ecdsa.PublicKey) []byte {
	if key == nil {
		return nil
	}
	// Use crypto/ecdh for uncompressed 65-byte P-256 point (avoids deprecated .X/.Y access).
	ecdhKey, err := key.ECDH()
	if err != nil {
		return nil
	}
	return ecdhKey.Bytes()
}
