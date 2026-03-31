package framing

import (
	"testing"
)

func FuzzUnmarshalPrivateMessage(f *testing.F) {
	// Seed with some valid data if we have any, or just empty
	f.Add([]byte{0x00, 0x02, 0x00, 0x01, 0x02, 0x03, 0x04})
	f.Add([]byte{})

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = UnmarshalPrivateMessage(data)
	})
}

func FuzzUnmarshalPublicMessage(f *testing.F) {
	f.Add([]byte{0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04})
	f.Add([]byte{})

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = UnmarshalPublicMessage(data)
	})
}

func FuzzUnmarshalAuthenticatedContent(f *testing.F) {
	f.Add([]byte{0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04})
	f.Add([]byte{})

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = UnmarshalAuthenticatedContent(data)
	})
}

func FuzzUnmarshalMLSMessage(f *testing.F) {
	f.Add([]byte{0x01, 0x00, 0x01, 0x02, 0x03})
	f.Add([]byte{})

	f.Fuzz(func(_ *testing.T, data []byte) {
		msg, err := UnmarshalMLSMessage(data)
		if err != nil || msg == nil {
			return
		}
		_, _ = UnmarshalMLSMessage(msg.Marshal())
	})
}
