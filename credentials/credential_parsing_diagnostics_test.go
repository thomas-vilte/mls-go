//go:build diagnostics

package credentials

import "testing"

// Additional diagnostics for the top-level Credential parser.

// TestCredentialTopLevelParserRejectsTrailingBytes checks that bytes after a BasicCredential are refused.
func TestCredentialTopLevelParserRejectsTrailingBytes(t *testing.T) {
	raw := NewBasicCredential([]byte("alice")).Marshal()
	if _, err := UnmarshalCredential(raw); err != nil {
		t.Fatalf("control: UnmarshalCredential(valid) = %v", err)
	}
	if _, err := UnmarshalCredential(append(append([]byte{}, raw...), 0xDE, 0xAD)); err == nil {
		t.Errorf("UnmarshalCredential accepted 2 trailing bytes after a BasicCredential")
	}
}
