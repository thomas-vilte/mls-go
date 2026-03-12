package treesync

import (
	"testing"
)

func FuzzUnmarshalRatchetTree(f *testing.F) {
	f.Add([]byte{0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04})
	f.Add([]byte{})

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = UnmarshalTreeFromExtension(data)
	})
}
