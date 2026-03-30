# Examples

This repository does not currently ship maintained runnable examples under `examples/`.

The public API is still stabilizing in the `v0.3.x` beta line, and several old example snippets drifted away from the real code. Until dedicated examples are added back, use these sources instead:

- `group/integration_test.go` for end-to-end group flows
- `group/group_process_commit_test.go` for add/commit/welcome flows
- `group/messaging_test.go` for application message protection
- `interop/testvectors.go` for multi-party and interop-oriented scenarios

Useful commands:

```bash
go test ./group/... -run TestWelcomeRoundTrip -v
go test ./group/... -run TestGroupCreation -v
go test ./group/... -run TestReceiveApplicationMessage_VerifiesSignature -v
```

Interop runs are Docker-first by design:

```bash
docker compose -f docker/docker-compose.yml build mls-go
SUITES="1" ./docker/run-interop.sh self
```
