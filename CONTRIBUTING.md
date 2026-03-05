# Contributing to OpenMLS Go

Thank you for considering contributing to OpenMLS Go! We welcome contributions from the community.

## Development Setup

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/go.git`
3. Install Go 1.23 or later
4. Run tests: `go test ./...`

## Code Style

We follow standard Go conventions:

- Use `gofmt` or `goimports` for formatting
- Follow the Go naming conventions
- Write tests for all new functionality
- Use meaningful variable and function names
- Add godoc comments for exported types and functions

## Testing

All PRs must include tests. We base our tests on the OpenMLS Rust test suite:

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package tests
go test ./messages/...
```

## Pull Request Process

1. Create a branch for your feature/fix
2. Write tests and ensure they pass
3. Update documentation as needed
4. Submit a PR with a clear description
5. Address review feedback

## Areas We Need Help

- Implementing remaining MLS message types (Commit, Proposal)
- TreeKEM implementation
- Key schedule implementation
- Interop tests with OpenMLS Rust
- DAVE (Discord Audio Voice Encryption) support

## Questions?

Open an issue for any questions or discussions.
