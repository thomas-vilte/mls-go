# Interoperability Testing

Interop is Docker-first in this repository.

That is not just for convenience. It is the supported path.

Running everything in containers avoids the usual setup drift: different Go versions, missing system packages, different `mlspp` builds, or some stale binary sitting in a random directory. If you want reproducible results, use Docker.

## What is in here

- `interop/server/` contains the `mls-go` gRPC interop server
- `interop/testrunner/` contains the test runner source used to build the Docker image
- `docker/` contains the Compose file, Dockerfiles, and the helper script used to run the suite

## The supported way to run interop

### Self-interop

This runs `mls-go` against itself:

```bash
./docker/run-interop.sh self
```

### Cross-interop

This runs `mls-go` against `mlspp`:

```bash
./docker/run-interop.sh cross
```

If you want to run against OpenMLS instead:

```bash
CROSS_TARGET=openmls ./docker/run-interop.sh cross
```

When `CROSS_TARGET=openmls`, the helper runs the subset that currently passes against upstream OpenMLS by default:

- `welcome_join`
- `application`
- `external_join`
- `deep_random`

That set passes on suites `1`, `2`, and `3`.

### Everything

This runs self-interop first and then cross-interop:

```bash
./docker/run-interop.sh all
```

## Suites

The script supports these cipher suites:

- `1` - `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
- `2` - `MLS_128_DHKEMP256_AES128GCM_SHA256_P256`
- `3` - `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`

If you only want one suite:

```bash
SUITES=2 ./docker/run-interop.sh cross
```

## Configs

The standard config set is:

- `welcome_join`
- `application`
- `commit`
- `external_join`
- `external_proposals`
- `reinit`
- `branch`

Self-interop also runs `deep_random`.

Cross-interop skips `deep_random` by default because it is a stress case. If you want the heavier run, opt in explicitly.

```bash
RUN_STRESS=1 ./docker/run-interop.sh cross
```

That behavior is specific to the default `mlspp` target. OpenMLS uses its own default cross-config set, because upstream OpenMLS does not yet implement the full MLS WG interop scenario list.

You can also run a single config:

```bash
./docker/run-interop.sh cross external_proposals
SUITES=3 ./docker/run-interop.sh self reinit
```

## Output

The Docker helper prints progress in a plain `PASS` / `FAIL` format.

Examples:

- `PASS: [self] suite=2 config=external_proposals`
- `PASS: [cross] suite=3 config=branch`

If something fails, the script prints the captured log for that case and exits non-zero.

## Notes

- `docker/docker-compose.yml` starts `mlspp` with `-live 50051`, which is required for cross-interop.
- `docker/Dockerfile.openmls` builds the OpenMLS interop client binary during the image build and runs the compiled binary directly at container startup. That keeps OpenMLS startup predictable and avoids recompiling the Rust project every time the container starts.
- `interop/testrunner/main.go` is kept in this repository so the Docker runner image is built from local source, not from an external checkout.
- The old local shell wrappers were removed on purpose. If someone needs interop results, they should get them from the Docker flow.

## OpenMLS status

OpenMLS support in this repository is experimental.

After patching the upstream OpenMLS interop client to use mixed wire-format policies, the currently passing OpenMLS matrix in this repository is:

- suite `1`: `welcome_join`, `application`, `external_join`, `deep_random`
- suite `2`: `welcome_join`, `application`, `external_join`, `deep_random`
- suite `3`: `welcome_join`, `application`, `external_join`, `deep_random`

That is `12/12` passing for the scenarios OpenMLS currently supports here.

The Docker image applies a small patch to the upstream OpenMLS interop client so it uses OpenMLS' mixed wire-format policies instead of the pure policies. Without that patch, `deep_random` can fail with a wire-format policy error when `encrypt_handshake` is enabled and the scenario mixes public and private handshake messages.

That patch only addresses the wire-format mismatch. It does not add missing protocol features to OpenMLS.

At the moment, the upstream OpenMLS interop client still contains several `todo!()` or `unimplemented` handlers in `openmls/interop_client/src/main.rs`, including:

- `group_context_extensions_proposal`
- `re_init_proposal`
- `re_init_commit`
- `handle_pending_re_init_commit`
- `handle_re_init_commit`
- `re_init_welcome`
- `handle_re_init_welcome`
- `create_branch`
- `handle_branch`
- `new_member_add_proposal`
- `create_external_signer`
- `add_external_signer`
- `external_signer_proposal`

These gaps map directly to the failing OpenMLS configs:

- `commit` fails because `group_context_extensions_proposal` is still unimplemented.
- `external_proposals` fails because the external signer and new-member add handlers are still `todo!()`.
- `reinit` fails because the ReInit proposal and follow-up handlers are not implemented.
- `branch` fails because branch creation and branch handling are still `todo!()`.

This is not just an interop harness issue. The upstream OpenMLS library itself does not currently expose complete public APIs for these flows, especially around ReInit and branching, so implementing those handlers locally would mean carrying deeper changes in a third-party project rather than filling in a few thin wrappers.

In practice, that means OpenMLS is useful here for a limited cross-check on the flows it already supports, but it is not yet a full drop-in cross-interop target for the whole MLS WG scenario set.

## References

- [MLS WG interoperability repository](https://github.com/mlswg/mls-implementations)
- [RFC 9420 - The Messaging Layer Security (MLS) Protocol](https://www.rfc-editor.org/rfc/rfc9420)
