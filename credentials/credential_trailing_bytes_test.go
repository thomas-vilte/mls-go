package credentials

import (
	"testing"

	"github.com/thomas-vilte/mls-go/internal/tls"
)

// TestUnmarshalCredentialRejectsTrailingBytes checks that UnmarshalCredential reads exactly one credential,
// while the reader variant leaves the remaining bytes to its caller.
func TestUnmarshalCredentialRejectsTrailingBytes(t *testing.T) {
	raw := NewBasicCredential([]byte("alice")).Marshal()
	if _, err := UnmarshalCredential(raw); err != nil {
		t.Fatalf("control: UnmarshalCredential(valid) = %v", err)
	}
	if _, err := UnmarshalCredential(append(append([]byte{}, raw...), 0xDE, 0xAD)); err == nil {
		t.Error("UnmarshalCredential accepted 2 trailing bytes after a BasicCredential")
	}

	r := tls.NewReader(append(append([]byte{}, raw...), 0xAA))
	if _, err := UnmarshalCredentialFromReader(r); err != nil {
		t.Fatalf("UnmarshalCredentialFromReader: %v", err)
	}
	if r.Remaining() != 1 {
		t.Errorf("reader left %d bytes after the credential, want 1", r.Remaining())
	}
}
