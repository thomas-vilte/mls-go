# Examples

This repository ships maintained runnable examples under `examples/`.

Current entry points:

- `examples/basic_chat` shows the low-level `group` package flow
- `examples/basic_chat_v2` shows the recommended `mls.Client` flow

Useful supporting sources:

- `client_test.go` for end-to-end high-level usage
- `group/integration_test.go` for low-level multi-party flows
- `group/messaging_test.go` for application message protection
- `interop/testvectors.go` for multi-party and interop-oriented scenarios

Useful commands:

```bash
go run ./examples/basic_chat
go run ./examples/basic_chat_v2
go test ./group/... -run TestReceiveApplicationMessage_VerifiesSignature -v
```

Interop runs are Docker-first by design:

```bash
docker compose -f docker/docker-compose.yml build mls-go
SUITES="1" ./docker/run-interop.sh self
```
