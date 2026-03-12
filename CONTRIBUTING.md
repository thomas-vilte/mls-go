# Contributing to mls-go

Thank you for considering contributing to mls-go! We welcome contributions from the community.

## Development Setup

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/mls-go.git`
3. Install Go 1.23 or later
4. Run tests: `go test ./...`

## Code Style

We follow standard Go conventions:

- Use `gofmt` or `goimports` for formatting
- Follow the Go naming conventions
- Write tests for all new functionality
- Use meaningful variable and function names
- Add godoc comments for exported types and functions
- **All comments and error messages MUST be in English** — this is a public library

## Language Requirements

**Important:** This is an international open-source project. All code artifacts must be in English:

- ✅ `ErrInvalidKeyLength` (good)
- ❌ `ErrLongitudInvalida` (bad)
- ✅ `// Computes the epoch secret from commit` (good)
- ❌ `// Computa el epoch secret desde el commit` (bad)
- ✅ `return fmt.Errorf("failed to derive key: %w", err)` (good)
- ❌ `return fmt.Errorf("falló derivar key: %w", err)` (bad)

This applies to:
- Variable and function names
- Error messages
- Code comments
- Test names and messages
- Documentation

## Testing

All PRs must include tests. We base our tests on the OpenMLS Rust test suite:

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run with race detector (required before submitting)
go test -race ./...

# Run specific package tests
go test ./ciphersuite/...
go test ./group/...
```

## Pull Request Process

1. Create a branch for your feature/fix
2. Write tests and ensure they pass
3. Run `go fmt ./...` and `go vet ./...`
4. Update documentation as needed
5. Submit a PR with a clear description in English
6. Address review feedback

## What We're Working On

### High Priority

- Complete Commit/Proposal message handling
- TreeKEM implementation
- Full interoperability with OpenMLS Rust
- Production-ready API stability

### Areas We Need Help

- Implementing remaining MLS message types
- Additional cipher suites (MLS_256_DHKEMX25519_AES256GCM_SHA512_P256)
- External senders support
- Documentation and examples

## Questions?

Open an issue for any questions or discussions. Please use English for all public communications.

## Code of Conduct

Be respectful and inclusive. We welcome contributors from all backgrounds.
