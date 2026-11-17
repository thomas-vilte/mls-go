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

// WithExtensionHandler registers a custom extension handler.
func WithExtensionHandler(h ExtensionHandler) GroupOption {
	return func(cfg *groupConfig) {
		if h == nil {
			return
		}
		if cfg.extensionHandlers == nil {
			cfg.extensionHandlers = NewExtensionHandlerRegistry()
		}
		cfg.extensionHandlers.Register(h)
	}
}

// WithCredentialValidator sets the credential validator for the group.
//
// The group calls the validator for each credential it admits: the KeyPackage of an Add made with
// AddMember, the Add proposals of a commit made with Commit, and the Add proposals and the external
// joiner of a commit processed with ProcessReceivedCommit or ProcessPublicMessage. A rejected credential
// makes that call return an error that wraps the validator's error, and the group state does not change.
// An Add that is only received as a proposal is checked when a commit applies it, not when it arrives.
//
// The option applies to the Group that NewGroup or NewGroupFromReInit creates with it. JoinFromWelcome,
// ExternalCommit and UnmarshalGroupState take no GroupOption, so the groups they return have no validator.
// The Client applies its own validator (mls.WithCredentialValidator) and does not pass this option to group.
func WithCredentialValidator(v CredentialValidator) GroupOption {
	return func(cfg *groupConfig) {
		cfg.credentialValidator = v
	}
}
