package framing

import (
	"fmt"

	"github.com/openmls/go/ciphersuite"
	"github.com/openmls/go/group"
	"github.com/openmls/go/internal/tls"
	secret_tree "github.com/openmls/go/secret_tree"
)

// PrivateMessage implementa RFC 9420 §6.3.
// Los primeros cuatro campos se transmiten en claro; únicamente los últimos dos están cifrados.
type PrivateMessage struct {
	GroupID             []byte      // in clear
	Epoch               uint64      // in clear
	ContentType         ContentType // in clear
	AuthenticatedData   []byte      // in clear
	EncryptedSenderData []byte      // encrypted MLSSenderData
	Ciphertext          []byte      // encrypted PrivateMessageContent
}

// Marshal serializa el PrivateMessage para transmisión.
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

// UnmarshalPrivateMessage parsea un PrivateMessage desde su representación wire.
// El wire_format uint16 inicial debe estar incluido en los datos.
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

// MLSSenderData implementa RFC 9420 §6.3.2.
// Se cifra para formar EncryptedSenderData.
type MLSSenderData struct {
	LeafIndex  uint32
	Generation uint32
	ReuseGuard [ciphersuite.ReuseGuardBytes]byte
}

// Marshal serializa MLSSenderData.
func (sd *MLSSenderData) Marshal() []byte {
	w := tls.NewWriter()
	w.WriteUint32(sd.LeafIndex)
	w.WriteUint32(sd.Generation)
	w.WriteRaw(sd.ReuseGuard[:])
	return w.Bytes()
}

// EncryptParams contiene los parámetros requeridos para cifrar un PrivateMessage.
type EncryptParams struct {
	Content          FramedContent
	SenderLeafIndex  uint32
	CipherSuite      ciphersuite.CipherSuite // para derivar ciphertext_sample y tamaños
	PaddingSize      int                     // tamaño de bloque para padding (0 = sin padding)
	SenderDataSecret *ciphersuite.Secret     // encripta MLSSenderData
	SecretTree       *secret_tree.Tree       // deriva content key/nonce
	SigKey           *ciphersuite.SignaturePrivateKey
	GroupContext     *group.GroupContext // incluido en FramedContentTBS
}

// Encrypt implementa RFC 9420 §6.3.1.
//
// Flujo (RFC §6.3.2 requiere encriptar contenido PRIMERO para obtener ciphertext_sample):
//  1. Validar que sender es member (RFC §6.3)
//  2. Firmar FramedContent → FramedContentAuthData
//  3. Generar ReuseGuard aleatorio
//  4. Derivar content key/nonce del SecretTree
//  5. XOR nonce[:4] con ReuseGuard (§6.3.1)
//  6. Encriptar PrivateMessageContent → ciphertext
//  7. Extraer ciphertext_sample = ciphertext[0..Nh-1]
//  8. Derivar sender_data key/nonce con KdfExpandLabel(sender_data_secret, "key"/"nonce", ciphertext_sample)
//  9. Encriptar MLSSenderData con SenderDataAAD
func Encrypt(p EncryptParams) (*PrivateMessage, error) {
	// 1. Validar sender type (RFC §6.3: PrivateMessage sender MUST be member)
	if p.Content.Sender.Type != SenderTypeMember {
		return nil, fmt.Errorf("%w: PrivateMessage sender must be member", ErrInvalidMessage)
	}

	// 2. Firmar FramedContent
	ac := &AuthenticatedContent{
		WireFormat:   WireFormatPrivateMessage,
		Content:      p.Content,
		GroupContext: p.GroupContext,
	}
	sig, err := ciphersuite.SignWithLabel(p.SigKey, "FramedContentTBS", ac.MarshalTBS())
	if err != nil {
		return nil, fmt.Errorf("framing: signing content: %w", err)
	}
	ac.Auth = FramedContentAuthData{Signature: sig}

	// 3. Generar ReuseGuard aleatorio
	rg, err := ciphersuite.NewReuseGuardRandom()
	if err != nil {
		return nil, fmt.Errorf("framing: generating reuse_guard: %w", err)
	}

	// 4. Derivar content key/nonce del SecretTree
	leaf, err := p.SecretTree.LeafForIndex(p.SenderLeafIndex)
	if err != nil {
		return nil, fmt.Errorf("framing: getting leaf secret: %w", err)
	}
	seqNum := leaf.NextSequenceNumber()

	contentKey, err := leaf.EncryptionKey(seqNum)
	if err != nil {
		return nil, fmt.Errorf("framing: deriving content key: %w", err)
	}
	contentNonce, err := leaf.Nonce(seqNum)
	if err != nil {
		return nil, fmt.Errorf("framing: deriving content nonce: %w", err)
	}

	// 5. XOR nonce[:4] con ReuseGuard (RFC §6.3.1)
	guard := rg.AsSlice()
	for i := 0; i < ciphersuite.ReuseGuardBytes; i++ {
		contentNonce[i] ^= guard[i]
	}

	// 6. Encriptar PrivateMessageContent PRIMERO (necesitamos el ciphertext para step 7)
	aad := buildPrivateContentAAD(
		p.Content.GroupID,
		p.Content.Epoch,
		p.Content.ContentType(),
		p.Content.AuthenticatedData,
	)
	plaintext := marshalPrivateMessageContent(p.Content.Body, ac.Auth, p.PaddingSize)
	ciphertext, err := ciphersuite.AESEncrypt(contentKey, contentNonce, plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("framing: encrypting content: %w", err)
	}

	// 7. Extraer ciphertext_sample = ciphertext[0..Nh-1] (RFC §6.3.2)
	nh := p.CipherSuite.HashLength()
	sample := ciphertext
	if len(sample) > nh {
		sample = sample[:nh]
	}

	// 8. Derivar sender_data key/nonce usando KdfExpandLabel con ciphertext_sample (RFC §6.3.2)
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

	// 9. Encriptar MLSSenderData con SenderDataAAD (RFC §6.3.2)
	senderData := &MLSSenderData{
		LeafIndex:  p.SenderLeafIndex,
		Generation: uint32(seqNum),
	}
	copy(senderData.ReuseGuard[:], guard)

	sdAAD := buildSenderDataAAD(p.Content.GroupID, p.Content.Epoch, p.Content.ContentType())
	encryptedSD, err := ciphersuite.AESEncrypt(
		sdKey.AsSlice(), sdNonce.AsSlice(),
		senderData.Marshal(), sdAAD,
	)
	if err != nil {
		return nil, fmt.Errorf("framing: encrypting sender_data: %w", err)
	}

	return &PrivateMessage{
		GroupID:             p.Content.GroupID,
		Epoch:               p.Content.Epoch,
		ContentType:         p.Content.ContentType(),
		AuthenticatedData:   p.Content.AuthenticatedData,
		EncryptedSenderData: encryptedSD,
		Ciphertext:          ciphertext,
	}, nil
}

// DecryptParams holds the parameters required to decrypt a PrivateMessage.
type DecryptParams struct {
	CipherSuite      ciphersuite.CipherSuite
	SenderDataSecret *ciphersuite.Secret
	SecretTree       *secret_tree.Tree
	// SigPubKey se utiliza para verificar la firma del remitente luego de descifrar.
	// Si es nil, se omite la verificación (no recomendado en producción).
	SigPubKey    *ciphersuite.OpenMlsSignaturePublicKey
	GroupContext *group.GroupContext // requerido para verificación TBS
}

// Decrypt descifra un PrivateMessage y retorna el AuthenticatedContent.
// Verifica la firma del remitente si SigPubKey está presente.
func Decrypt(pm *PrivateMessage, p DecryptParams) (*AuthenticatedContent, error) {
	// 1. Extraer ciphertext_sample = ciphertext[0..Nh-1] (RFC §6.3.2)
	// Necesario para derivar sender_data key/nonce ANTES de descifrar sender_data
	nh := p.CipherSuite.HashLength()
	sample := pm.Ciphertext
	if len(sample) > nh {
		sample = sample[:nh]
	}

	// 2. Derivar sender_data key/nonce con KdfExpandLabel (RFC §6.3.2)
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

	// 3. Descifrar MLSSenderData
	sdAAD := buildSenderDataAAD(pm.GroupID, pm.Epoch, pm.ContentType)
	sdPlain, err := ciphersuite.AESDecrypt(
		sdKey.AsSlice(), sdNonce.AsSlice(),
		pm.EncryptedSenderData, sdAAD,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: sender_data: %v", ErrDecryptionFailed, err)
	}

	senderData, err := UnmarshalSenderData(sdPlain)
	if err != nil {
		return nil, fmt.Errorf("framing: parsing sender_data: %w", err)
	}

	// 4. Derivar content key/nonce del SecretTree
	leaf, err := p.SecretTree.LeafForIndex(senderData.LeafIndex)
	if err != nil {
		return nil, fmt.Errorf("framing: getting leaf secret: %w", err)
	}
	leaf.SetSequenceNumber(uint64(senderData.Generation))

	contentKey, err := leaf.EncryptionKey(uint64(senderData.Generation))
	if err != nil {
		return nil, fmt.Errorf("framing: deriving content key: %w", err)
	}
	contentNonce, err := leaf.Nonce(uint64(senderData.Generation))
	if err != nil {
		return nil, fmt.Errorf("framing: deriving content nonce: %w", err)
	}

	// 5. XOR nonce[:4] con ReuseGuard (igual que en Encrypt)
	for i := 0; i < ciphersuite.ReuseGuardBytes; i++ {
		contentNonce[i] ^= senderData.ReuseGuard[i]
	}

	// 6. Reconstruir PrivateContentAAD y descifrar contenido
	aad := buildPrivateContentAAD(pm.GroupID, pm.Epoch, pm.ContentType, pm.AuthenticatedData)
	plaintext, err := ciphersuite.AESDecrypt(contentKey, contentNonce, pm.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: content: %v", ErrDecryptionFailed, err)
	}

	// 7. Parsear body + auth del PrivateMessageContent
	pmc, err := unmarshalPrivateMessageContent(plaintext, pm.ContentType)
	if err != nil {
		return nil, fmt.Errorf("framing: parsing message content: %w", err)
	}

	// 8. Reconstruir FramedContent completo desde campos en claro + body descifrado.
	// Sender siempre es Member en PrivateMessage (RFC §6.3).
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

	// 9. Verificar firma si se provee clave pública
	if p.SigPubKey != nil {
		tbs := ac.MarshalTBS()
		if err := ciphersuite.VerifyWithLabel(p.SigPubKey, "FramedContentTBS", tbs, pmc.Auth.Signature); err != nil {
			return nil, ErrVerificationFailed
		}
	}

	return ac, nil
}

// buildPrivateContentAAD construye el AAD para el AEAD de PrivateMessageContent (RFC §6.3.1).
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

// buildSenderDataAAD construye el AAD para el AEAD de MLSSenderData (RFC §6.3.2).
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
