package framing

import (
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/internal/tls"
	"github.com/thomas-vilte/mls-go/secrettree"
)

// PrivateMessage implements RFC 9420 §6.3.
// The first four fields are transmitted in cleartext; only the last two are encrypted.
//
// Structure:
//
//	struct {
//	    opaque group_id<V>;
//	    uint64 epoch;
//	    ContentType content_type;
//	    opaque authenticated_data<V>;
//	    opaque encrypted_sender_data<V>;
//	    opaque ciphertext<V>;
//	} PrivateMessage;
type PrivateMessage struct {
	GroupID             []byte      // In cleartext
	Epoch               uint64      // In cleartext
	ContentType         ContentType // In cleartext
	AuthenticatedData   []byte      // In cleartext
	EncryptedSenderData []byte      // Encrypted MLSSenderData
	Ciphertext          []byte      // Encrypted PrivateMessageContent
}

// Marshal serializes the PrivateMessage for transmission.
func (pm *PrivateMessage) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteUint16(uint16(WireFormatPrivateMessage))
	w.WriteVLBytes(pm.GroupID)
	w.WriteUint64(pm.Epoch)
	w.WriteUint8(uint8(pm.ContentType))
	w.WriteVLBytes(pm.AuthenticatedData)
	w.WriteVLBytes(pm.EncryptedSenderData)
	w.WriteVLBytes(pm.Ciphertext)
	return w.Bytes()
}

// UnmarshalPrivateMessage parses a PrivateMessage from its wire representation.
// The initial wire_format uint16 must be included in the data.
func UnmarshalPrivateMessage(data []byte) (*PrivateMessage, error) {
	r := tls.NewReader(data)

	wf, err := r.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("framing: reading wire_format: %w", err)
	}
	if WireFormat(wf) != WireFormatPrivateMessage {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidWireFormat, wf)
	}

	groupID, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("framing: reading group_id: %w", err)
	}
	epoch, err := r.ReadUint64()
	if err != nil {
		return nil, fmt.Errorf("framing: reading epoch: %w", err)
	}
	ct, err := r.ReadUint8()
	if err != nil {
		return nil, fmt.Errorf("framing: reading content_type: %w", err)
	}
	authData, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("framing: reading authenticated_data: %w", err)
	}
	encSD, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("framing: reading encrypted_sender_data: %w", err)
	}
	ciphertext, err := r.ReadVLBytes()
	if err != nil {
		return nil, fmt.Errorf("framing: reading ciphertext: %w", err)
	}

	return &PrivateMessage{
		GroupID:             groupID,
		Epoch:               epoch,
		ContentType:         ContentType(ct),
		AuthenticatedData:   authData,
		EncryptedSenderData: encSD,
		Ciphertext:          ciphertext,
	}, nil
}

// MLSSenderData implements RFC 9420 §6.3.2.
// Encrypted to form EncryptedSenderData.
//
// Structure:
//
//	struct {
//	    uint32 leaf_index;
//	    uint32 generation;
//	    opaque reuse_guard[4];
//	} MLSSenderData;
type MLSSenderData struct {
	LeafIndex  uint32
	Generation uint32
	ReuseGuard [ciphersuite.ReuseGuardBytes]byte
}

// Marshal serializes MLSSenderData.
func (sd *MLSSenderData) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteUint32(sd.LeafIndex)
	w.WriteUint32(sd.Generation)
	w.WriteRaw(sd.ReuseGuard[:])
	return w.Bytes()
}

// EncryptParams contains the parameters required to encrypt a PrivateMessage.
type EncryptParams struct {
	AuthContent      *AuthenticatedContent // If provided, ignores Content, SigKey, GroupContext, and ConfirmationTag
	Content          FramedContent
	SenderLeafIndex  uint32
	CipherSuite      ciphersuite.CipherSuite // For deriving ciphertext_sample and sizes
	PaddingSize      int                     // Block size for padding (0 = no padding)
	SenderDataSecret *ciphersuite.Secret     // Encrypts MLSSenderData
	SecretTree       *secrettree.Tree        // Derives content key/nonce
	SigKey           *ciphersuite.SignaturePrivateKey
	GroupContext     []byte // Serialized GroupContext; included in FramedContentTBS
	// ConfirmationTag is required for commits (ContentTypeCommit).
	// RFC §6.1: The tag is included in encrypted PrivateMessageContent.
	ConfirmationTag []byte
}

// Encrypt implements RFC 9420 §6.3.1.
//
// Flow (RFC §6.3.2 requires encrypting content FIRST to obtain ciphertext_sample):
// Validate that sender is member (RFC §6.3)
// Sign FramedContent → FramedContentAuthData
// Generate random ReuseGuard
// Derive content key/nonce from SecretTree
// XOR nonce[:4] with ReuseGuard (§6.3.1)
// Encrypt PrivateMessageContent → ciphertext
// Extract ciphertext_sample = ciphertext[0..Nh-1]
// Derive sender_data key/nonce with KdfExpandLabel(sender_data_secret, "key"/"nonce", ciphertext_sample)
// Encrypt MLSSenderData with SenderDataAAD
func Encrypt(p EncryptParams) (*PrivateMessage, error) {
	var ac *AuthenticatedContent
	if p.AuthContent != nil {
		ac = p.AuthContent
		if ac.Content.Sender.Type != SenderTypeMember {
			return nil, fmt.Errorf("%w: PrivateMessage sender must be member", ErrInvalidMessage)
		}
	} else {
		if p.Content.Sender.Type != SenderTypeMember {
			return nil, fmt.Errorf("%w: PrivateMessage sender must be member", ErrInvalidMessage)
		}
		// RFC §6.1: GroupContext required for member senders
		if len(p.GroupContext) == 0 {
			return nil, fmt.Errorf("%w: required for member sender in PrivateMessage", ErrMissingGroupContext)
		}

		ac = &AuthenticatedContent{
			WireFormat:   WireFormatPrivateMessage,
			Content:      p.Content,
			GroupContext: p.GroupContext,
		}
		sig, err := ciphersuite.SignWithLabel(p.SigKey, "FramedContentTBS", ac.MarshalTBS())
		if err != nil {
			return nil, fmt.Errorf("framing: signing content: %w", err)
		}
		ac.Auth = FramedContentAuthData{Signature: sig, ConfirmationTag: p.ConfirmationTag}
	}

	// Generate random ReuseGuard
	rg, err := ciphersuite.NewReuseGuardRandom()
	if err != nil {
		return nil, fmt.Errorf("framing: generating reuse_guard: %w", err)
	}

	// Derive content key/nonce from SecretTree
	leaf, err := p.SecretTree.LeafForIndex(p.SenderLeafIndex)
	if err != nil {
		return nil, fmt.Errorf("framing: getting leaf secret: %w", err)
	}
	// RFC §15.2: refuse to send if the AEAD nonce counter is exhausted
	if leaf.IsSequenceExhausted() {
		return nil, fmt.Errorf("framing: AEAD sequence number exhausted — must advance epoch before sending")
	}
	seqNum := leaf.NextSequenceNumber()

	var contentKey []byte
	var contentNonce []byte
	if ac.Content.ContentType() == ContentTypeApplication {
		contentKey, err = leaf.ApplicationKey(uint32(seqNum))
		if err != nil {
			return nil, fmt.Errorf("framing: deriving application content key: %w", err)
		}
		contentNonce, err = leaf.ApplicationNonce(uint32(seqNum))
		if err != nil {
			return nil, fmt.Errorf("framing: deriving application content nonce: %w", err)
		}
	} else {
		contentKey, err = leaf.HandshakeKey(uint32(seqNum))
		if err != nil {
			return nil, fmt.Errorf("framing: deriving handshake content key: %w", err)
		}
		contentNonce, err = leaf.HandshakeNonce(uint32(seqNum))
		if err != nil {
			return nil, fmt.Errorf("framing: deriving handshake content nonce: %w", err)
		}
	}

	// XOR nonce[:4] with ReuseGuard (RFC §6.3.1)
	guard := rg.AsSlice()
	for i := 0; i < ciphersuite.ReuseGuardBytes; i++ {
		contentNonce[i] ^= guard[i]
	}

	// Encrypt PrivateMessageContent FIRST (we need ciphertext for step 7)
	aad := buildPrivateContentAAD(
		ac.Content.GroupID,
		ac.Content.Epoch,
		ac.Content.ContentType(),
		ac.Content.AuthenticatedData,
	)
	plaintext := marshalPrivateMessageContent(ac.Content.Body, ac.Auth, p.PaddingSize)
	ciphertext, err := ciphersuite.EncryptWithCipherSuite(contentKey, contentNonce, plaintext, aad, p.CipherSuite)
	if err != nil {
		return nil, fmt.Errorf("framing: encrypting content: %w", err)
	}

	// Extract ciphertext_sample = ciphertext[0..Nh-1] (RFC §6.3.2)
	nh := p.CipherSuite.HashLength()
	sample := ciphertext
	if len(sample) > nh {
		sample = sample[:nh]
	}

	// Derive sender_data key/nonce using KdfExpandLabel with ciphertext_sample (RFC §6.3.2)
	sdKey, err := p.SenderDataSecret.KdfExpandLabel("key", sample, p.CipherSuite.AeadKeyLength())
	if err != nil {
		return nil, fmt.Errorf("framing: deriving sender_data_key: %w", err)
	}
	defer sdKey.SecureZero()

	sdNonce, err := p.SenderDataSecret.KdfExpandLabel("nonce", sample, p.CipherSuite.AeadNonceLength())
	if err != nil {
		return nil, fmt.Errorf("framing: deriving sender_data_nonce: %w", err)
	}
	defer sdNonce.SecureZero()

	// Encrypt MLSSenderData with SenderDataAAD (RFC §6.3.2)
	senderData := &MLSSenderData{
		LeafIndex:  p.SenderLeafIndex,
		Generation: uint32(seqNum),
	}
	copy(senderData.ReuseGuard[:], guard)

	sdAAD := buildSenderDataAAD(ac.Content.GroupID, ac.Content.Epoch, ac.Content.ContentType())
	encryptedSD, err := ciphersuite.EncryptWithCipherSuite(
		sdKey.AsSlice(), sdNonce.AsSlice(),
		senderData.Marshal(), sdAAD, p.CipherSuite,
	)
	if err != nil {
		return nil, fmt.Errorf("framing: encrypting sender_data: %w", err)
	}

	return &PrivateMessage{
		GroupID:             ac.Content.GroupID,
		Epoch:               ac.Content.Epoch,
		ContentType:         ac.Content.ContentType(),
		AuthenticatedData:   ac.Content.AuthenticatedData,
		EncryptedSenderData: encryptedSD,
		Ciphertext:          ciphertext,
	}, nil
}

// DecryptParams holds the parameters required to decrypt a PrivateMessage.
type DecryptParams struct {
	CipherSuite      ciphersuite.CipherSuite
	SenderDataSecret *ciphersuite.Secret
	SecretTree       *secrettree.Tree
	// SigPubKey is used to verify the sender's signature after decryption.
	// If nil, verification is skipped (not recommended in production).
	SigPubKey    *ciphersuite.MLSSignaturePublicKey
	GroupContext []byte // Serialized GroupContext; required for TBS verification
}

// Decrypt decrypts a PrivateMessage and returns the AuthenticatedContent.
// Verifies the sender's signature if SigPubKey is present.
func Decrypt(pm *PrivateMessage, p DecryptParams) (*AuthenticatedContent, error) {
	// Extract ciphertext_sample = ciphertext[0..Nh-1] (RFC §6.3.2)
	// Needed to derive sender_data key/nonce BEFORE decrypting sender_data
	nh := p.CipherSuite.HashLength()
	sample := pm.Ciphertext
	if len(sample) > nh {
		sample = sample[:nh]
	}

	// Derive sender_data key/nonce with KdfExpandLabel (RFC §6.3.2)
	sdKey, err := p.SenderDataSecret.KdfExpandLabel("key", sample, p.CipherSuite.AeadKeyLength())
	if err != nil {
		return nil, fmt.Errorf("framing: deriving sender_data_key: %w", err)
	}
	defer sdKey.SecureZero()

	sdNonce, err := p.SenderDataSecret.KdfExpandLabel("nonce", sample, p.CipherSuite.AeadNonceLength())
	if err != nil {
		return nil, fmt.Errorf("framing: deriving sender_data_nonce: %w", err)
	}
	defer sdNonce.SecureZero()

	// Decrypt MLSSenderData
	sdAAD := buildSenderDataAAD(pm.GroupID, pm.Epoch, pm.ContentType)
	sdPlain, err := ciphersuite.DecryptWithCipherSuite(
		sdKey.AsSlice(), sdNonce.AsSlice(),
		pm.EncryptedSenderData, sdAAD, p.CipherSuite,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: sender_data: %v", ErrDecryptionFailed, err)
	}

	senderData, err := UnmarshalSenderData(sdPlain)
	if err != nil {
		return nil, fmt.Errorf("framing: parsing sender_data: %w", err)
	}

	// Derive content key/nonce from SecretTree
	leaf, err := p.SecretTree.LeafForIndex(senderData.LeafIndex)
	if err != nil {
		return nil, fmt.Errorf("framing: getting leaf secret: %w", err)
	}
	leaf.SetSequenceNumber(uint64(senderData.Generation))

	// Build PrivateContentAAD and decrypt content
	aad := buildPrivateContentAAD(pm.GroupID, pm.Epoch, pm.ContentType, pm.AuthenticatedData)

	decryptWithRatchet := func(handshake bool) ([]byte, error) {
		var key []byte
		var nonce []byte
		var err error
		if handshake {
			key, err = leaf.HandshakeKey(senderData.Generation)
			if err != nil {
				return nil, fmt.Errorf("framing: deriving handshake content key: %w", err)
			}
			nonce, err = leaf.HandshakeNonce(senderData.Generation)
			if err != nil {
				return nil, fmt.Errorf("framing: deriving handshake content nonce: %w", err)
			}
		} else {
			key, err = leaf.ApplicationKey(senderData.Generation)
			if err != nil {
				return nil, fmt.Errorf("framing: deriving application content key: %w", err)
			}
			nonce, err = leaf.ApplicationNonce(senderData.Generation)
			if err != nil {
				return nil, fmt.Errorf("framing: deriving application content nonce: %w", err)
			}
		}

		for i := 0; i < ciphersuite.ReuseGuardBytes; i++ {
			nonce[i] ^= senderData.ReuseGuard[i]
		}

		return ciphersuite.DecryptWithCipherSuite(key, nonce, pm.Ciphertext, aad, p.CipherSuite)
	}

	var plaintext []byte
	if pm.ContentType == ContentTypeApplication {
		plaintext, err = decryptWithRatchet(false)
	} else {
		var pt []byte
		pt, hsErr := decryptWithRatchet(true)
		if hsErr == nil {
			plaintext = pt
		} else {
			pt, appErr := decryptWithRatchet(false)
			if appErr == nil {
				plaintext = pt
			} else {
				err = hsErr
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%w: content: %v", ErrDecryptionFailed, err)
	}

	// Parse body + auth from PrivateMessageContent
	pmc, err := unmarshalPrivateMessageContent(plaintext, pm.ContentType)
	if err != nil {
		return nil, fmt.Errorf("framing: parsing message content: %w", err)
	}

	// Rebuild complete FramedContent from cleartext fields + decrypted body.
	// Sender is always Member in PrivateMessage (RFC §6.3).
	content := FramedContent{
		GroupID:           pm.GroupID,
		Epoch:             pm.Epoch,
		Sender:            Sender{Type: SenderTypeMember, LeafIndex: senderData.LeafIndex},
		AuthenticatedData: pm.AuthenticatedData,
		Body:              pmc.Body,
	}

	ac := &AuthenticatedContent{
		WireFormat:   WireFormatPrivateMessage,
		Content:      content,
		Auth:         pmc.Auth,
		GroupContext: p.GroupContext,
	}

	// Verify signature if public key is provided
	if p.SigPubKey != nil {
		tbs := ac.MarshalTBS()
		if err := ciphersuite.VerifyWithLabel(p.SigPubKey, "FramedContentTBS", tbs, pmc.Auth.Signature); err != nil {
			return nil, ErrVerificationFailed
		}
	}

	return ac, nil
}

// buildPrivateContentAAD builds the AAD for PrivateMessageContent AEAD (RFC §6.3.1).
//
// Structure:
//
//	struct {
//	    opaque group_id<V>;
//	    uint64 epoch;
//	    ContentType content_type;
//	    opaque authenticated_data<V>;
//	} PrivateContentAAD;
func buildPrivateContentAAD(groupID []byte, epoch uint64, ct ContentType, authData []byte) []byte {
	w := tls.NewWriter()
	w.WriteVLBytes(groupID)
	w.WriteUint64(epoch)
	w.WriteUint8(uint8(ct))
	w.WriteVLBytes(authData)
	return w.Bytes()
}

// buildSenderDataAAD builds the AAD for MLSSenderData AEAD (RFC §6.3.2).
//
// Structure:
//
//	struct {
//	    opaque group_id<V>;
//	    uint64 epoch;
//	    ContentType content_type;
//	} SenderDataAAD;
func buildSenderDataAAD(groupID []byte, epoch uint64, ct ContentType) []byte {
	w := tls.NewWriter()
	w.WriteVLBytes(groupID)
	w.WriteUint64(epoch)
	w.WriteUint8(uint8(ct))
	return w.Bytes()
}
