# Examples for mls-go

Basic examples showing how to use mls-go.

**Note:** API may change until v1.0.0. These examples target the current `v0.3.x` API.

---

## Example 1: Basic Group Chat

Creates a group, adds a member, sends encrypted messages.

```go
package main

import (
    "crypto/rand"
    "fmt"
    "log"

    "github.com/thomas-vilte/mls-go/ciphersuite"
    "github.com/thomas-vilte/mls-go/credentials"
    "github.com/thomas-vilte/mls-go/group"
    "github.com/thomas-vilte/mls-go/keypackages"
)

func main() {
    cs := ciphersuite.MLS128DHKEMP256

    // Alice creates group
    aliceCred := credentials.NewBasicCredential("Alice")
    aliceKP, aliceKeys, err := keypackages.Generate(aliceCred, cs, rand.Reader)
    if err != nil {
        log.Fatal(err)
    }

    aliceGroup, err := group.New(cs, aliceKP, aliceKeys)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Alice created group")

    // Bob generates KeyPackage
    bobCred := credentials.NewBasicCredential("Bob")
    bobKP, bobKeys, err := keypackages.Generate(bobCred, cs, rand.Reader)
    if err != nil {
        log.Fatal(err)
    }

    // Alice adds Bob
    welcome, _, err := aliceGroup.AddMember(bobKP, aliceKeys.SignatureKey)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Alice added Bob")

    // Bob joins from Welcome
    bobGroup, err := group.JoinFromWelcome(welcome, bobKP, bobKeys)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Bob joined group")

    // Bob sends message
    bobMsg, err := bobGroup.SendMessage([]byte("Hi from Bob!"), bobKeys.SignatureKey)
    if err != nil {
        log.Fatal(err)
    }

    // Alice decrypts
    plaintext, err := aliceGroup.ReceiveMessage(bobMsg, bobGroup.OwnLeafIndex)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Alice receives: %s\n", plaintext)
}
```

**Run:**
```bash
go run examples/basic_chat/main.go
```

---

## Example 2: Multiple Cipher Suites

Shows how to use different cipher suites.

```go
package main

import (
    "crypto/rand"
    "fmt"
    "log"

    "github.com/thomas-vilte/mls-go/ciphersuite"
    "github.com/thomas-vilte/mls-go/credentials"
    "github.com/thomas-vilte/mls-go/keypackages"
)

func main() {
    suites := []ciphersuite.CipherSuite{
        ciphersuite.MLS128DHKEMX25519,
        ciphersuite.MLS128DHKEMP256,
        ciphersuite.MLS256DHKEMX25519ChaCha20,
    }

    for _, cs := range suites {
        if !cs.IsSupported() {
            fmt.Printf("%s: not supported\n", cs)
            continue
        }

        cred := credentials.NewBasicCredential("Test")
        kp, _, err := keypackages.Generate(cred, cs, rand.Reader)
        if err != nil {
            log.Fatal(err)
        }

        fmt.Printf("%s: KeyPackage generated\n", cs)
        fmt.Printf("  Identity: %x...\n", kp.Credential.Identity[:16])
    }
}
```

**Run:**
```bash
go run examples/cipher_suites/main.go
```

---

## Example 3: Export Secrets

Shows how to export group secrets for backup or external use.

```go
package main

import (
    "crypto/rand"
    "fmt"
    "log"

    "github.com/thomas-vilte/mls-go/ciphersuite"
    "github.com/thomas-vilte/mls-go/credentials"
    "github.com/thomas-vilte/mls-go/group"
    "github.com/thomas-vilte/mls-go/keypackages"
)

func main() {
    cs := ciphersuite.MLS128DHKEMP256

    cred := credentials.NewBasicCredential("Alice")
    kp, keys, err := keypackages.Generate(cred, cs, rand.Reader)
    if err != nil {
        log.Fatal(err)
    }

    grp, err := group.New(cs, kp, keys)
    if err != nil {
        log.Fatal(err)
    }

    // Export secrets
    exporter := grp.NewExporter()

    encSecret, err := exporter.ExportSecret("encryption", 32)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Encryption secret: %x\n", encSecret)

    expSecret, err := exporter.ExportSecret("exporter", 32)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Exporter secret: %x\n", expSecret)

    // Zero secrets after use
    for i := range encSecret {
        encSecret[i] = 0
    }
    for i := range expSecret {
        expSecret[i] = 0
    }
}
```

**Run:**
```bash
go run examples/export_secrets/main.go
```

---

## Example 4: Interoperability Test

Generates test vectors for interoperability with other implementation.

```go
package main

import (
    "fmt"
    "log"

    "github.com/thomas-vilte/mls-go/interop"
)

func main() {
    // Generate test vectors
    tvs, err := interop.GenerateInteropTestVectors()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Generated %d test vectors\n", len(tvs.Vectors))

    // Export to JSON
    err = tvs.ExportToFile("test_vectors.json")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Exported to test_vectors.json")

    // Validate
    for _, tv := range tvs.Vectors {
        err := interop.ValidateTestVector(&tv)
        if err != nil {
            log.Printf("Vector %s invalid: %v\n", tv.Name, err)
        } else {
            fmt.Printf("Vector %s: valid\n", tv.Name)
        }
    }
}
```

**Run:**
```bash
go run examples/interop_test/main.go
```

---

## Running examples

```bash
# All examples
cd examples
go run basic_chat/main.go
go run cipher_suites/main.go
go run export_secrets/main.go
go run interop_test/main.go
```

## Notes

- Examples use `crypto/rand` - ensure proper seeding on your system
- Secrets are printed for demonstration - don't do this in production
- API may change - check version compatibility

## More examples

Want more examples? Open an issue or contribute:
- Matrix integration
- Enterprise messaging
- IoT use cases
- Custom protocols

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.
