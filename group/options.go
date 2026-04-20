package group

type groupConfig struct {
	extensions          []Extension
	paddingSize         int
	pskStore            PSKStore
	credentialValidator CredentialValidator
	extensionHandlers   *ExtensionHandlerRegistry
}

func cloneExtensions(exts []Extension) []Extension {
	if len(exts) == 0 {
		return nil
	}
	out := make([]Extension, len(exts))
	for i := range exts {
		out[i] = Extension{Type: exts[i].Type}
		if len(exts[i].Data) > 0 {
			out[i].Data = append([]byte(nil), exts[i].Data...)
		}
	}
	return out
}

// GroupOption configures optional behavior for a Group.
type GroupOption func(*groupConfig)

// WithExtensions sets the initial GroupContext extensions.
func WithExtensions(exts []Extension) GroupOption {
	return func(cfg *groupConfig) {
		cfg.extensions = cloneExtensions(exts)
	}
}

// WithPaddingSize sets the padding size for encrypted application messages.
func WithPaddingSize(size int) GroupOption {
	return func(cfg *groupConfig) {
		if size < 0 {
			size = 0
		}
		cfg.paddingSize = size
	}
}

// WithPSKStore sets the PSK store for the group.
func WithPSKStore(store PSKStore) GroupOption {
	return func(cfg *groupConfig) {
		cfg.pskStore = store
	}
}

// WithCredentialValidator sets the credential validator for the group.
func WithCredentialValidator(v CredentialValidator) GroupOption {
	return func(cfg *groupConfig) {
		cfg.credentialValidator = v
	}
}

// ExtensionHandlerRegistryOption registers custom extension handlers.
func ExtensionHandlerRegistryOption(r *ExtensionHandlerRegistry) GroupOption {
	return func(cfg *groupConfig) {
		cfg.extensionHandlers = r
	}
}
