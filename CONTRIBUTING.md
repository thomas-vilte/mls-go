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

Two things the commands above do not cover:

- Some tests live behind the `diagnostics` build tag. CI does not run them, so if your change touches the code they exercise, also run `go test -tags diagnostics ./...` and `go vet -tags diagnostics ./...`.
- `interop/server` and `interop/testrunner` are separate Go modules. If you change anything they use, run `go vet ./...` and `go test -race ./...` inside each of them.

The module requires Go 1.26. Do not use standard library APIs that were added in a later version.

## Tests

All PRs need tests. The project uses RFC 9420 interop vectors as the ground truth — if your change touches the key schedule, TreeKEM, or framing, run the relevant interop test:

```bash
go test ./schedule/... -run TestKeyScheduleInteropVectors -v
go test ./group/... -run TestTreeKEMVectors -v
go test ./group/... -run 'TestPassiveClient(HandlingCommit|Welcome|Random)Vectors' -v
```

Tests should be named after the behavior they check, and a fix should come with a test that fails without it.

## Pull requests

1. Branch off `main`
2. Write tests
3. Update relevant docs if the behavior changes
4. PR description in English with a short explanation of what and why. The PR template asks for the type of change and how you tested it
5. Keep PRs small and focused on one change, so each one is easy to review
6. Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages and PR titles, for example `fix(treesync): bound tree queries`, `fix(group): leave the group unchanged when a commit is rejected` or `test(group): run the passive-client-random interop vector`. Mark a change that breaks the exported API with `!`, as in `fix(extensions)!: remove ProtocolVersions from RequiredCapabilities`, and explain the break in the description

## Security issues

Do not open a public issue or PR for a vulnerability. Follow [SECURITY.md](SECURITY.md) instead.

## Architecture

Before diving into a big change, read the package-level godoc (especially `group/doc.go`, `doc.go`, and `INTEGRATION.md`) and the relevant RFC 9420 sections. They document the main invariants, testing expectations, and protocol details that are easy to get wrong.

## Questions

Open an issue. Please use English for public communication.
