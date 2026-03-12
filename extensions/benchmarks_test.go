package extensions_test

import (
	"testing"

	"github.com/mls-go/extensions"
)

// Benchmarks para ApplicationIDExtension

func BenchmarkApplicationIDExtension_New(b *testing.B) {
	appID := []byte("com.example.chat.application.identifier")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extensions.NewApplicationIDExtension(appID)
	}
}

func BenchmarkApplicationIDExtension_Marshal(b *testing.B) {
	ext := extensions.NewApplicationIDExtension([]byte("com.example.chat"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ext.Marshal()
	}
}

func BenchmarkApplicationIDExtension_Unmarshal(b *testing.B) {
	ext := extensions.NewApplicationIDExtension([]byte("com.example.chat"))
	data := ext.Marshal()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = extensions.UnmarshalApplicationIDExtension(data)
	}
}

func BenchmarkApplicationIDExtension_Validate(b *testing.B) {
	ext := extensions.NewApplicationIDExtension([]byte("test"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ext.Validate()
	}
}

func BenchmarkApplicationIDExtension_Equal(b *testing.B) {
	ext1 := extensions.NewApplicationIDExtension([]byte("test"))
	ext2 := extensions.NewApplicationIDExtension([]byte("test"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ext1.Equal(ext2)
	}
}

func BenchmarkApplicationIDExtension_ToExtension(b *testing.B) {
	ext := extensions.NewApplicationIDExtension([]byte("test"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ext.ToExtension()
	}
}

// Benchmarks para ExternalPubExtension

func BenchmarkExternalPubExtension_New_P256(b *testing.B) {
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extensions.NewExternalPubExtension(pubKey)
	}
}

func BenchmarkExternalPubExtension_New_X25519(b *testing.B) {
	pubKey := make([]byte, 32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extensions.NewExternalPubExtension(pubKey)
	}
}

func BenchmarkExternalPubExtension_Marshal(b *testing.B) {
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	ext := extensions.NewExternalPubExtension(pubKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ext.Marshal()
	}
}

func BenchmarkExternalPubExtension_Unmarshal(b *testing.B) {
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	ext := extensions.NewExternalPubExtension(pubKey)
	data := ext.Marshal()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = extensions.UnmarshalExternalPubExtension(data)
	}
}

func BenchmarkExternalPubExtension_Validate(b *testing.B) {
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	ext := extensions.NewExternalPubExtension(pubKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ext.Validate()
	}
}

func BenchmarkExternalPubExtension_IsP256(b *testing.B) {
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	ext := extensions.NewExternalPubExtension(pubKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ext.IsP256()
	}
}

func BenchmarkExternalPubExtension_IsX25519(b *testing.B) {
	pubKey := make([]byte, 32)
	ext := extensions.NewExternalPubExtension(pubKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ext.IsX25519()
	}
}

// Benchmarks para LastResortExtension

func BenchmarkLastResortExtension_New(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extensions.NewLastResortExtension()
	}
}

func BenchmarkLastResortExtension_Marshal(b *testing.B) {
	ext := extensions.NewLastResortExtension()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ext.Marshal()
	}
}

func BenchmarkLastResortExtension_Unmarshal(b *testing.B) {
	ext := extensions.NewLastResortExtension()
	data := ext.Marshal()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = extensions.UnmarshalLastResortExtension(data)
	}
}

func BenchmarkLastResortExtension_Validate(b *testing.B) {
	ext := extensions.NewLastResortExtension()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ext.Validate()
	}
}

func BenchmarkLastResortExtension_Equal(b *testing.B) {
	ext1 := extensions.NewLastResortExtension()
	ext2 := extensions.NewLastResortExtension()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ext1.Equal(ext2)
	}
}

func BenchmarkLastResortExtension_ToExtension(b *testing.B) {
	ext := extensions.NewLastResortExtension()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ext.ToExtension()
	}
}

// Benchmarks para RequiredCapabilitiesExtension

func BenchmarkRequiredCapabilitiesExtension_New(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extensions.NewRequiredCapabilities()
	}
}

func BenchmarkRequiredCapabilitiesExtension_AddProtocolVersion(b *testing.B) {
	req := extensions.NewRequiredCapabilities()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.AddProtocolVersion(0x01)
	}
}

func BenchmarkRequiredCapabilitiesExtension_AddCipherSuite(b *testing.B) {
	req := extensions.NewRequiredCapabilities()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.AddCipherSuite(0x0002)
	}
}

func BenchmarkRequiredCapabilitiesExtension_Marshal(b *testing.B) {
	req := extensions.NewRequiredCapabilities()
	req.AddProtocolVersion(0x01)
	req.AddCipherSuite(0x0002)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.Marshal()
	}
}

func BenchmarkRequiredCapabilitiesExtension_Validate(b *testing.B) {
	req := extensions.NewRequiredCapabilities()
	req.AddProtocolVersion(0x01)
	req.AddCipherSuite(0x0002)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = req.Validate()
	}
}

func BenchmarkRequiredCapabilitiesExtension_HasProtocolVersion(b *testing.B) {
	req := extensions.NewRequiredCapabilities()
	req.AddProtocolVersion(0x01)
	req.AddProtocolVersion(0x02)
	req.AddProtocolVersion(0x03)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.HasProtocolVersion(0x02)
	}
}

func BenchmarkRequiredCapabilitiesExtension_SupportsAll(b *testing.B) {
	req1 := extensions.NewRequiredCapabilities()
	req1.AddProtocolVersion(0x01)
	req1.AddCipherSuite(0x0002)

	req2 := extensions.NewRequiredCapabilities()
	req2.AddProtocolVersion(0x01)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req1.SupportsAll(req2)
	}
}

// Benchmarks para Extensions collection

func BenchmarkExtensions_New(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extensions.NewExtensions()
	}
}

func BenchmarkExtensions_Add(b *testing.B) {
	ext := extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exts := extensions.NewExtensions()
		_ = exts.Add(ext)
	}
}

func BenchmarkExtensions_Add_Multiple(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exts := extensions.NewExtensions()
		_ = exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test1")})
		_ = exts.Add(extensions.Extension{Type: extensions.ExtensionTypeExternalPub, Data: []byte{0x04}})
		_ = exts.Add(extensions.Extension{Type: extensions.ExtensionTypeRatchetTree, Data: []byte{0x01}})
	}
}

func BenchmarkExtensions_Get(b *testing.B) {
	exts := extensions.NewExtensions()
	_ = exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exts.Get(extensions.ExtensionTypeApplicationID)
	}
}

func BenchmarkExtensions_Has(b *testing.B) {
	exts := extensions.NewExtensions()
	_ = exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exts.Has(extensions.ExtensionTypeApplicationID)
	}
}

func BenchmarkExtensions_Remove(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exts := extensions.NewExtensions()
		_ = exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")})
		exts.Remove(extensions.ExtensionTypeApplicationID)
	}
}

func BenchmarkExtensions_All(b *testing.B) {
	exts := extensions.NewExtensions()
	_ = exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")})
	_ = exts.Add(extensions.Extension{Type: extensions.ExtensionTypeExternalPub, Data: []byte{0x04}})
	_ = exts.Add(extensions.Extension{Type: extensions.ExtensionTypeRatchetTree, Data: []byte{0x01}})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exts.All()
	}
}

func BenchmarkExtensions_Marshal(b *testing.B) {
	exts := extensions.NewExtensions()
	_ = exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")})
	_ = exts.Add(extensions.Extension{Type: extensions.ExtensionTypeExternalPub, Data: []byte{0x04}})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exts.Marshal()
	}
}

func BenchmarkExtensions_Clone(b *testing.B) {
	exts := extensions.NewExtensions()
	_ = exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")})
	_ = exts.Add(extensions.Extension{Type: extensions.ExtensionTypeExternalPub, Data: []byte{0x04}})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exts.Clone()
	}
}

func BenchmarkExtensions_Len(b *testing.B) {
	exts := extensions.NewExtensions()
	_ = exts.Add(extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")})
	_ = exts.Add(extensions.Extension{Type: extensions.ExtensionTypeExternalPub, Data: []byte{0x04}})
	_ = exts.Add(extensions.Extension{Type: extensions.ExtensionTypeRatchetTree, Data: []byte{0x01}})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exts.Len()
	}
}

// Benchmarks para Extension genérica

func BenchmarkExtension_Marshal(b *testing.B) {
	ext := extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test-data")}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ext.Marshal()
	}
}

func BenchmarkExtension_Unmarshal(b *testing.B) {
	ext := extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test-data")}
	data := ext.Marshal()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = extensions.UnmarshalExtension(data)
	}
}

func BenchmarkExtension_Validate(b *testing.B) {
	ext := extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ext.Validate()
	}
}

func BenchmarkExtension_Equal(b *testing.B) {
	ext1 := extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")}
	ext2 := extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ext1.Equal(&ext2)
	}
}
