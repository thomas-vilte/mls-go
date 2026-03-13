# Interoperability Testing

Interoperability testing against other MLS implementations using standardized test vectors.

## Overview

Test vectors are JSON files containing deterministic test cases. Multiple implementations generate and validate the same vectors — matching output confirms interoperability.

This follows the [MLS Interoperability Test Vectors](https://github.com/mlswg/mls-implementations/blob/master/test-vectors/) format used by the MLS working group.

## Test Vector Format

```json
{
  "name": "MLS-Interop",
  "description": "Test vectors for interoperability testing",
  "vectors": [
    {
      "name": "one-to-one-join",
      "cipher_suite": 2,
      "group_id": "hex_encoded_group_id",
      "epoch": 0,
      "key_packages": [...],
      "commits": [...],
      "welcomes": [...],
      "expected_tree_hash": "...",
      "expected_epoch": 1,
      "expected_num_members": 2
    }
  ]
}
```

## Usage

### Running Interop Tests

```bash
# Run all interop tests
go test ./interop/... -v

# Run a specific test
go test ./interop/... -v -run TestOneToOneJoinScenario

# Cross-implementation testing (requires external test vectors)
export MLS_TEST_VECTORS=path/to/vectors.json
go test ./interop/... -v -run TestCrossImplementationRoundTrip
```

### Generating Test Vectors

```go
package main

import (
    "github.com/thomas-vilte/mls-go/interop"
)

func main() {
    tvs, err := interop.GenerateInteropTestVectors()
    if err != nil {
        panic(err)
    }

    err = tvs.ExportToFile("go_test_vectors.json")
    if err != nil {
        panic(err)
    }
}
```

## Test Scenarios

### One-to-One Join

Covers the basic group formation flow:

1. Alice creates a group (epoch 0)
2. Alice adds Bob via Add proposal + Commit
3. Bob processes Welcome and joins at epoch 1
4. Both verify matching group state and tree hash

This exercises RFC 9420 section 11.2.1 (Adding Members).

### Planned Scenarios

- Multi-party join (3+ members)
- Multiple concurrent additions
- Member removal (RFC 9420 section 11.2.3)
- Member updates / key rotation (RFC 9420 section 11.2.2)
- External commits (RFC 9420 section 11.3)
- Group reinitialization

## Implementation Status

| Feature | Status | Notes |
|---------|--------|-------|
| Test vector generation | Done | Basic scenarios |
| Test vector import/export | Done | JSON format |
| 1:1 join scenario | Done | RFC 9420 section 11.2.1 |
| Multi-party join | Planned | |
| External commits | Planned | RFC 9420 section 11.3 |
| All cipher suites | Partial | Only MLS128DHKEMP256 (0x0002) tested |

## References

- [MLS Interop Test Vectors](https://github.com/mlswg/mls-implementations/blob/master/test-vectors/)
- [RFC 9420 - The Messaging Layer Security (MLS) Protocol](https://www.rfc-editor.org/rfc/rfc9420)
- [RFC 9420 Section 11.2.1 - Adding Members](https://www.rfc-editor.org/rfc/rfc9420#section-11.2.1)
- [RFC 9420 Section 11.2.2 - Member Updates](https://www.rfc-editor.org/rfc/rfc9420#section-11.2.2)
- [RFC 9420 Section 11.2.3 - Member Removal](https://www.rfc-editor.org/rfc/rfc9420#section-11.2.3)
- [RFC 9420 Section 11.3 - External Commits](https://www.rfc-editor.org/rfc/rfc9420#section-11.3)
