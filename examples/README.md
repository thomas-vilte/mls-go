# Examples

This repository ships maintained runnable examples under `examples/`.

Current entry points:

- `examples/basic_chat` shows the low-level `group` package flow
- `examples/basic_chat_v2` shows the recommended `mls.Client` flow
- `examples/ds` shows a minimal Delivery Service (HTTP + SSE)

## Delivery Service Example

The `examples/ds/` package provides a minimal MLS Delivery Service reference
implementation. It demonstrates how to build a group messaging system with MLS.

### Running

```bash
go run ./examples/ds/
```

### API Endpoints

| Method | Path                         | Description                          |
|-------|-----------------------------|--------------------------------------|
| POST  | /groups                     | Create a new group                   |
| POST  | /groups/{id}/keypackages   | Register a KeyPackage for invitation |
| GET   | /groups/{id}/keypackages   | Get registered KeyPackages          |
| POST  | /groups/{id}/messages       | Submit a Commit, Proposal, or App message |
| GET   | /groups/{id}/events        | SSE stream for new messages           |

### Example Usage

```bash
# Start DS
go run ./examples/ds/ &

# Create group
curl -X POST http://localhost:8080/groups \
  -H "Content-Type: application/json" \
  -d '{"cipher_suite": 1}'

# Register more KeyPackages (for inviting members)
curl -X POST http://localhost:8080/groups/{group_id}/keypackages \
  -H "Content-Type: application/json" \
  -d '{"key_package": "..."}'

# Submit a message
curl -X POST http://localhost:8080/groups/{group_id}/messages \
  -H "Content-Type: application/json" \
  -d '{"message": "..."}'

# Subscribe to events (SSE)
curl http://localhost:8080/groups/{group_id}/events
```

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
