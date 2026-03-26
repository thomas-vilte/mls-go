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
- `interop/testrunner/main.go` is kept in this repository so the Docker runner image is built from local source, not from an external checkout.
- The old local shell wrappers were removed on purpose. If someone needs interop results, they should get them from the Docker flow.

## References

- [MLS WG interoperability repository](https://github.com/mlswg/mls-implementations)
- [RFC 9420 - The Messaging Layer Security (MLS) Protocol](https://www.rfc-editor.org/rfc/rfc9420)
