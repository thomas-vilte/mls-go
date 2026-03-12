# Interoperability Testing with OpenMLS

This package provides interoperability testing between the Go MLS implementation and [OpenMLS](https://github.com/openmls/openmls) (the reference Rust implementation).

## Overview

Interoperability is achieved through **test vectors** - JSON files containing standardized test cases that both implementations can generate and validate.

## Test Vector Format

Test vectors follow the [MLS Interop Test Vectors](https://github.com/mlswg/mls-implementations/blob/master/test-vectors/) specification:

```json
{
  "name": "Go-OpenMLS Interop",
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

# Run specific test
go test ./interop/... -v -run TestOneToOneJoinScenario

# Enable cross-implementation testing (requires OpenMLS test vectors)
export OPENMLS_TEST_VECTORS=path/to/openmls_vectors.json
go test ./interop/... -v -run TestCrossImplementationRoundTrip
```

### Generating Test Vectors

```go
package main

import (
    "github.com/mls-go/interop"
)

func main() {
    // Generate test vectors
    tvs, err := interop.GenerateInteropTestVectors()
    if err != nil {
        panic(err)
    }
    
    // Export to JSON
    err = tvs.ExportToFile("go_test_vectors.json")
    if err != nil {
        panic(err)
    }
}
```

### Testing Against OpenMLS

1. **Generate test vectors in Go:**
   ```bash
   go run cmd/generate_vectors.go -output go_vectors.json
   ```

2. **Import in OpenMLS:**
   ```bash
   cd openmls/
   cargo run --bin test_vector_runner -- --input ../go_vectors.json
   ```

3. **Export from OpenMLS:**
   ```bash
   cargo run --bin test_vector_generator -- --output openmls_vectors.json
   ```

4. **Validate in Go:**
   ```bash
   export OPENMLS_TEST_VECTORS=openmls_vectors.json
   go test ./interop/... -v -run TestCrossImplementationRoundTrip
   ```

## Test Scenarios

### 1. One-to-One Join
- Alice creates a group
- Alice adds Bob
- Bob joins via Welcome
- Both verify group state

### Future Scenarios (TODO)
- Three-party join
- Multiple additions
- Member removal
- Member update
- External join
- Group reinitialization

## Implementation Status

| Feature | Status | Notes |
|---------|--------|-------|
| Test Vector Generation | ✅ | Basic scenarios working |
| Test Vector Import/Export | ✅ | JSON format compatible |
| 1:1 Join | ✅ | Implemented |
| Multi-party Join | 🚧 | Planned |
| External Commits | 🚧 | Planned |
| All Cipher Suites | 🚧 | Only MLS128DHKEMP256 tested |

## Troubleshooting

### "undefined: testvectors" error
Make sure you're importing the correct package:
```go
import "github.com/mls-go/interop"
```

### Empty Commits in Test Vectors
This is expected in the current simplified implementation. The Commit struct generation requires full UpdatePath implementation.

## References

- [MLS Interop Test Vectors Specification](https://github.com/mlswg/mls-implementations/blob/master/test-vectors/)
- [OpenMLS Test Framework](https://github.com/openmls/openmls/tree/main/openmls_test)
- [RFC 9420 - The Messaging Layer Security (MLS) Protocol](https://www.rfc-editor.org/rfc/rfc9420)
