import re

with open('framing/private_message.go', 'r') as f:
    content = f.read()

# Replace EncryptParams
old_params = """type EncryptParams struct {
	Content          FramedContent
	SenderLeafIndex  uint32
	CipherSuite      ciphersuite.CipherSuite // para derivar ciphertext_sample y tamaños
	PaddingSize      int                     // tamaño de bloque para padding (0 = sin padding)
	SenderDataSecret *ciphersuite.Secret     // encripta MLSSenderData
	SecretTree       *secret_tree.Tree       // deriva content key/nonce
	SigKey           *ciphersuite.SignaturePrivateKey
	GroupContext     []byte // serialized GroupContext; incluido en FramedContentTBS
	// ConfirmationTag es obligatorio para commits (ContentTypeCommit).
	// RFC §6.1: el tag se incluye en PrivateMessageContent cifrado.
	ConfirmationTag []byte
}"""

new_params = """type EncryptParams struct {
	AuthContent      *AuthenticatedContent   // Si se provee, ignora Content, SigKey, GroupContext y ConfirmationTag
	Content          FramedContent
	SenderLeafIndex  uint32
	CipherSuite      ciphersuite.CipherSuite // para derivar ciphertext_sample y tamaños
	PaddingSize      int                     // tamaño de bloque para padding (0 = sin padding)
	SenderDataSecret *ciphersuite.Secret     // encripta MLSSenderData
	SecretTree       *secret_tree.Tree       // deriva content key/nonce
	SigKey           *ciphersuite.SignaturePrivateKey
	GroupContext     []byte // serialized GroupContext; incluido en FramedContentTBS
	// ConfirmationTag es obligatorio para commits (ContentTypeCommit).
	// RFC §6.1: el tag se incluye en PrivateMessageContent cifrado.
	ConfirmationTag []byte
}"""

content = content.replace(old_params, new_params)

# Replace Encrypt beginning
old_encrypt = """func Encrypt(p EncryptParams) (*PrivateMessage, error) {
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
	ac.Auth = FramedContentAuthData{Signature: sig, ConfirmationTag: p.ConfirmationTag}"""

new_encrypt = """func Encrypt(p EncryptParams) (*PrivateMessage, error) {
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
	}"""

content = content.replace(old_encrypt, new_encrypt)

# Replace all p.Content with ac.Content in the rest of the function
# We must find the body of Encrypt up to the return
start_idx = content.find('// 3. Generar ReuseGuard aleatorio')
end_idx = content.find('// DecryptParams holds the parameters required to decrypt a PrivateMessage.')

func_body = content[start_idx:end_idx]
func_body = func_body.replace('p.Content.', 'ac.Content.')

content = content[:start_idx] + func_body + content[end_idx:]

with open('framing/private_message.go', 'w') as f:
    f.write(content)

