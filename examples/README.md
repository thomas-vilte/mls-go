# Examples

This repository ships maintained runnable examples under `examples/`.

Current entry points:

- `examples/basic_chat` shows the low-level `group` package flow
- `examples/basic_chat_v2` shows the recommended `mls.Client` flow
- `examples/ds` shows a minimal Delivery Service (HTTP + SSE)

## Delivery Service Example

The `examples/ds/` package provides a minimal Delivery Service using HTTP + SSE.
The companion CLI at `examples/ds/client/` shows how to register key packages,
invite members, and exchange MLS messages through the DS.

### Running

Terminal 1:

```bash
go run ./examples/ds
```

Terminal 2 (Alice creates the first group automatically):

```bash
go run ./examples/ds/client alice
```

Terminal 3 (Bob auto-discovers the single existing group):

```bash
go run ./examples/ds/client bob
```

In Alice's prompt, invite Bob:

```text
/invite bob
```

After Bob joins, both terminals can send plain text lines as application messages.

### API Endpoints

| Method | Path                               | Description |
|--------|------------------------------------|-------------|
| GET    | /groups                            | List groups |
| POST   | /groups                            | Create a group |
| POST   | /groups/{id}/keypackages           | Upload a user's KeyPackage |
| GET    | /groups/{id}/keypackages           | List users with uploaded KeyPackage |
| GET    | /groups/{id}/keypackages/{user}    | Fetch a specific user's KeyPackage |
| POST   | /groups/{id}/messages              | Publish commit/proposal/application/welcome |
| GET    | /groups/{id}/events                | SSE stream of group events |

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
