with open('group/group_test.go', 'r') as f:
    content = f.read()

# Replace Alice crea el commit en epoch 1
old_commit_call = """	// Alice crea el commit en epoch 1.
	sc, err := aliceGroup.Commit(alice.sigPriv, alice.sigPub, nil)"""

new_commit_call = """	// Alice crea el commit en epoch 1.
	sc, err := aliceGroup.CommitWithFormat(alice.sigPriv, alice.sigPub, nil, framing.WireFormatPrivateMessage)"""

content = content.replace(old_commit_call, new_commit_call)

old_encrypt_call = """	pm, err := framing.Encrypt(framing.EncryptParams{
		Content:          sc.AuthenticatedContent.Content,
		SenderLeafIndex:  uint32(aliceGroup.OwnLeafIndex),
		CipherSuite:      aliceGroup.CipherSuite,
		PaddingSize:      0,
		SenderDataSecret: aliceGroup.EpochSecrets.SenderDataSecret,
		SecretTree:       aliceGroup.SecretTree,
		SigKey:           alice.sigPriv,
		GroupContext:     aliceGroup.GroupContext.Marshal(),
		ConfirmationTag:  sc.AuthenticatedContent.Auth.ConfirmationTag,
	})"""

new_encrypt_call = """	pm, err := framing.Encrypt(framing.EncryptParams{
		AuthContent:      sc.AuthenticatedContent,
		SenderLeafIndex:  uint32(aliceGroup.OwnLeafIndex),
		CipherSuite:      aliceGroup.CipherSuite,
		PaddingSize:      0,
		SenderDataSecret: aliceGroup.EpochSecrets.SenderDataSecret,
		SecretTree:       aliceGroup.SecretTree,
	})"""

content = content.replace(old_encrypt_call, new_encrypt_call)

# also replace wrong epoch and invalid signature which might need it.

with open('group/group_test.go', 'w') as f:
    f.write(content)

