import re

with open('group/group.go', 'r') as f:
    content = f.read()

# Replace Commit signature
old_commit_sig = """func (g *Group) Commit(
	sigPrivKey *ciphersuite.SignaturePrivateKey,
	sigPubKey *ciphersuite.SignaturePublicKey,
	psks []schedule.Psk,
) (*StagedCommit, error) {"""

new_commit_sig = """// Commit applies all pending proposals and creates a new epoch, generating a PublicMessage.
//
// This is the main function to advance the group to a new epoch.
// RFC 9420 §12.4
func (g *Group) Commit(
	sigPrivKey *ciphersuite.SignaturePrivateKey,
	sigPubKey *ciphersuite.SignaturePublicKey,
	psks []schedule.Psk,
) (*StagedCommit, error) {
	return g.CommitWithFormat(sigPrivKey, sigPubKey, psks, framing.WireFormatPublicMessage)
}

// CommitWithFormat creates a new epoch using the specified WireFormat for the commit signature.
func (g *Group) CommitWithFormat(
	sigPrivKey *ciphersuite.SignaturePrivateKey,
	sigPubKey *ciphersuite.SignaturePublicKey,
	psks []schedule.Psk,
	wireFormat framing.WireFormat,
) (*StagedCommit, error) {"""

content = content.replace(old_commit_sig, new_commit_sig)

# Replace WireFormatPublicMessage inside CommitWithFormat
old_auth_content = """	ac := &framing.AuthenticatedContent{
		WireFormat:   framing.WireFormatPublicMessage,
		Content:      content,
		GroupContext: groupContextBytes,
	}"""

new_auth_content = """	ac := &framing.AuthenticatedContent{
		WireFormat:   wireFormat,
		Content:      content,
		GroupContext: groupContextBytes,
	}"""

content = content.replace(old_auth_content, new_auth_content)

with open('group/group.go', 'w') as f:
    f.write(content)

