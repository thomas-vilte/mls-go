# Contributing to mls-go

Contributions are welcome. Here's everything you need to know.

## Setup

1. Fork and clone the repo
2. Install Go 1.26+
3. Run `go test ./...` to verify everything passes

## Code style

Standard Go conventions apply:

- `gofmt` / `goimports` for formatting
- `golangci-lint` for static analysis — config in `.golangci.yml`
- Godoc comments on all exported types and functions
- Meaningful names — avoid abbreviations unless the context is obvious

**All code artifacts must be in English** — this is a public library:

```
✅  ErrInvalidKeyLength
❌  ErrLongitudInvalida

✅  // Computes the epoch secret from the commit.
❌  // Computa el epoch secret desde el commit.

✅  return fmt.Errorf("failed to derive key: %w", err)
❌  return fmt.Errorf("falló derivar key: %w", err)
```

This applies to variable names, error messages, comments, test names, and docs.

## Before submitting

```bash
go mod tidy                         # keep go.mod and go.sum clean
go build ./...                      # must build
go test -race ./...                 # must pass with race detector
go vet ./...                        # must be clean
golangci-lint run --timeout=5m      # must be clean
```

The CI runs all of these automatically, but catching issues locally first saves time.

## Tests

All PRs need tests. The project uses RFC 9420 interop vectors as the ground truth — if your change touches the key schedule, TreeKEM, or framing, run the relevant interop test:

```bash
go test ./schedule/... -run TestKeyScheduleInteropVectors -v
go test ./group/... -run TestTreeKEMVectors -v
go test ./group/... -run TestPassiveClientCommitVectors -v
```

## Pull requests

1. Branch off `dev`, not `master`
2. Write tests
3. Update relevant docs if the behavior changes
4. PR description in English with a short explanation of what and why

## Architecture

Before diving into a big change, read the package-level godoc (especially `group/doc.go`, `doc.go`, and `INTEGRATION.md`) and the relevant RFC 9420 sections. They document the main invariants, testing expectations, and protocol details that are easy to get wrong.

## Questions

Open an issue. Please use English for public communication.
