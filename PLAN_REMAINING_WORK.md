# Plan: Trabajo restante hacia RFC 9420 completo

Implementación Go de RFC 9420 (MLS). Estado actual: CS=2 completo con todos los
interop vectors pasando. Este documento cubre todo lo que queda para alcanzar
cumplimiento completo del RFC.

## Posicionamiento vs OpenMLS Rust

| Área | OpenMLS Rust | Esta implementación Go | Ventaja |
|------|-------------|------------------------|---------|
| Cipher suites activas | 3 (cs=1,2,3) | 1 (cs=2) → objetivo: 3 | Ellos por ahora |
| Dependencias externas | ~50 crates | 0 | ✅ Go |
| Tiempo de compilación | 5–10 min | <30 seg | ✅ Go |
| Tamaño de binario | ~10 MB | ~2 MB | ✅ Go |
| Curva de aprendizaje | Rust (alta) | Go (baja) | ✅ Go |
| Interop vectors cs=2 | Todos pasan | Todos pasan | Empate |

**Objetivo**: alcanzar 3 cipher suites activas (cs=1,2,3) manteniendo 0 dependencias
externas en stdlib. Para cs=3 la única excepción posible es `golang.org/x/crypto`
(módulo oficial de Go, pero fuera del stdlib estricto) — ver nota en Bloque 5.

**No implementar cs=4,5,6,7 en el corto plazo**: OpenMLS tampoco las tiene activas.
Son código muerto en la práctica. Priorizar cs=1 y cs=3 da paridad funcional.

---

## Prioridades

| Prioridad | Área | Impacto |
|-----------|------|---------|
| 🔴 CRÍTICO | Verificación de firmas en proposals (Add/Update) | Seguridad |
| 🔴 CRÍTICO | PrivateMessage commit processing | Funcionalidad core |
| 🟡 ALTO | CS=1 (X25519/Ed25519) | Interop con el mundo real |
| 🟡 ALTO | API pública: Exporter, Branch PSK | Completitud RFC |
| 🟢 MEDIO | CS=3 (X25519/ChaCha20Poly1305) | Interop adicional |
| 🟢 MEDIO | CS=5,7 (P521, P384) sin deps externas | Completitud RFC |
| ⚪ BAJO | CS=4,6 (X448/Ed448) con deps externas | Raramente usado |
| ⚪ BAJO | required_capabilities extension | Completitud RFC |
| ⚪ BAJO | Subgroup branching | Raramente usado |

---

## Bloque 1: Gaps de seguridad en proposals

### 1.1 — Verificación de firma del KeyPackage en Add proposals

**RFC §12.2, §10.1**: Al recibir (y al procesar) un Add proposal, el receptor
debe verificar la firma del KeyPackage: `VerifyWithLabel(sig_pub, "KeyPackageTBS", tbs, sig)`.

**Archivos afectados**: `group/proposal_filter.go`, `keypackages/key_packages.go`

**Qué hay que hacer**:
- Agregar `func (kp *KeyPackage) Verify(cs CipherSuite) error` en `keypackages/key_packages.go`
  - `tbs = MarshalTBS()` (version + cipher_suite + init_key + leaf_node + extensions)
  - `VerifyWithLabel(leaf_node.SignatureKey, "KeyPackageTBS", tbs, kp.Signature)`
- Llamar `kp.Verify(pf.cipherSuite)` en `validateSingleProposal` para `ProposalTypeAdd`
- Agregar `func (kp *KeyPackage) MarshalTBS() []byte` si no existe

**Test**: Verificar que Add con KeyPackage con firma inválida es rechazado.

---

### 1.2 — Verificación de firma del LeafNode en Update proposals

**RFC §12.2, §7.3**: Al recibir un Update proposal, verificar la firma del
nuevo LeafNode con `VerifyWithContext(cs, groupID, leafIndex)` (source=update).

**Archivos afectados**: `group/proposal_filter.go`

**Qué hay que hacer**:
- En `validateSingleProposal` para `ProposalTypeUpdate`:
  ```go
  if proposal.Update != nil && proposal.Update.LeafNode != nil {
      ln := keyPackageLeafToTreeSync(proposal.Update.LeafNode)
      if err := ln.VerifyWithContext(pf.cipherSuite,
          pf.groupContext.GroupID.AsSlice(),
          uint32(fp.Sender)); err != nil {
          return fmt.Errorf("update leaf node signature invalid: %w", err)
      }
  }
  ```
- Convertir `keypackages.LeafNode` → `treesync.LeafNodeData` (ya existe `keyPackageLeafToTreeSync`)

**Test**: Update proposal con LeafNode de firma inválida es rechazado.

---

## Bloque 2: PrivateMessage commit processing

### 2.1 — Procesar commits enviados como PrivateMessage

**RFC §6, §12.4**: Los commits pueden enviarse como `PrivateMessage` (wire_format=2).
El código actual solo procesa `PublicMessage` commits. En producción, muchos clientes
usan PrivateMessage por defecto.

**Problema actual** (`passive_client_commit_interop_test.go:131`):
```go
// Private proposals are skipped (can't decrypt without sender data key)
```

**Archivos afectados**: `group/group.go` (`ProcessPublicMessage`), `framing/`, `group/messaging.go`

**Qué hay que hacer**:

1. **Agregar `ProcessPrivateMessage(pm *framing.PrivateMessage) error`** en `group/group.go`:
   - Usar `group.EpochSecrets.SenderDataSecret` para descifrar el `EncryptedSenderData`
   - Obtener `sender_data.leaf_index` y `sender_data.generation`
   - Usar `SecretTree` para derivar la clave de content decryption
   - Llamar `framing.DecryptPrivateMessage(...)` para obtener `PrivateMessageContent`
   - Si `content_type == commit`, llamar `ProcessReceivedCommit(ac, senderLeafIdx, nil)`
   - Si `content_type == proposal`, almacenar en `ProposalStore`

2. **`framing.DecryptPrivateMessage`** ya existe (usado en `ReceiveMessage`), pero necesita
   adaptarse para devolver el `AuthenticatedContent` desenvuelto para commit/proposal

3. **`ProcessPublicMessage`** refactorizar para que el processing de commit/proposal sea
   código compartido, callable también desde `ProcessPrivateMessage`

**Nota**: El `SecretTree` debe mantenerse por epoch. Actualmente se crea
bajo demanda en `SendMessage`/`ReceiveMessage`. Hay que preservarlo en `Group`.

**Test**: Agregar test con commit enviado como PrivateMessage.

---

## Bloque 3: API pública completa

### 3.1 — MLS-Exporter (RFC §8.5)

**RFC §8.5**: `MLS-Exporter(label, context, length) → bytes`

El `ExporterSecret` ya existe en `EpochSecrets`. Falta el método público en `Group`.

**Archivos afectados**: `group/group.go`, `schedule/exporter.go`

**Qué hay que hacer**:
```go
// Export deriva material de clave de la sesión MLS actual.
// RFC 9420 §8.5: MLS-Exporter(Label, Context, Length)
func (g *Group) Export(label string, context []byte, length int) ([]byte, error) {
    return schedule.Exporter(
        g.EpochSecrets.ExporterSecret.AsSlice(),
        label, context, length, g.CipherSuite,
    )
}
```

Verificar que `schedule.Exporter` ya implementa:
```
MLS-Exporter(Label, Context, Length) =
  ExpandWithLabel(
    DeriveSecret(exporter_secret, Label),
    "exporter", Hash(Context), Length
  )
```

**Test**: Vector de exportación manual contra valor esperado.

---

### 3.2 — Branch PSK (tipo 3, RFC §8.4)

**RFC §8.4**: PSK type 3 = `branch`. Se usa en subgroup branching.
Actualmente `MergeCommit` maneja tipos 1 (external) y 2 (resumption), pero no 3.

**Archivos afectados**: `group/group.go` (`MergeCommit`)

**Qué hay que hacer**:
- En el loop de PSK resolution dentro de `MergeCommit`, agregar case 3 (branch):
  ```go
  case 3: // branch
      branchKey := resumptionPskCacheKey(pid.PskGroupID, pid.PskEpoch)
      pskBytes, ok = g.CachedPsks[branchKey]
      if !ok {
          return fmt.Errorf("missing branch PSK for group=%x epoch=%d", ...)
      }
  ```
- Agregar `StoreBranchPsk(groupID, epoch, psk)` helper en `Group`

---

## Bloque 4: CS=1 — MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

Este es el cambio más grande. P256 está hardcodeado en ~21 lugares.
La estrategia es hacer el código genérico por CipherSuite, **sin crear
abstracciones sobre-diseñadas** — usar switches por cs donde sea necesario.

### Análisis de primitivas necesarias para CS=1

| Componente | CS=2 (actual) | CS=1 (nuevo) |
|------------|---------------|--------------|
| KEM | DHKEM(P-256, HKDF-SHA256) | DHKEM(X25519, HKDF-SHA256) |
| KDF | HKDF-SHA256 | HKDF-SHA256 ✅ (mismo) |
| AEAD | AES-128-GCM | AES-128-GCM ✅ (mismo) |
| Hash | SHA-256 | SHA-256 ✅ (mismo) |
| Firma | ECDSA P-256 | Ed25519 |

Solo cambian **KEM** (X25519 vs P256) y **firma** (Ed25519 vs ECDSA).

### 4.1 — `ciphersuite/`: nuevas constantes y config

**Archivo**: `ciphersuite/ciphersuite.go`

```go
const (
    MLS128DHKEMX25519   CipherSuite = 0x0001  // ← nuevo
    MLS128DHKEMP256     CipherSuite = 0x0002  // ya existe
    MLS128X25519CHACHA  CipherSuite = 0x0003  // ← nuevo (CS=3)
)

// CS=1: DHKEM(X25519), HKDF-SHA256, AES-128-GCM, Ed25519
// CS=3: DHKEM(X25519), HKDF-SHA256, ChaCha20Poly1305, Ed25519

// Agregar en IsSupported():
case MLS128DHKEMX25519, MLS128X25519CHACHA:
    return true

// Agregar nuevas KEMAlgorithm y SignatureScheme:
const (
    DHKEM_X25519_HKDF_SHA256 KEMAlgorithm   = 0x0020
    ED25519                  SignatureScheme = 0x0807
    CHACHA20POLY1305         AeadAlgorithm  = 0x0003
)
```

**Agregar métodos a `CipherSuite`**:
```go
// KEMPrivKeyLen retorna la longitud de la clave privada KEM.
func (cs CipherSuite) KEMPrivKeyLen() int
// KEMPubKeyLen retorna la longitud de la clave pública KEM.
func (cs CipherSuite) KEMPubKeyLen() int
// IsEdDSA retorna true si la firma es Ed25519 o Ed448.
func (cs CipherSuite) IsEdDSA() bool
```

---

### 4.2 — `ciphersuite/hpke.go`: soporte X25519

**Cambio principal**: `dhkemEncap` / `dhkemDecap` / `DeriveKeyPair` hardcodean `ecdh.P256()`.
Necesitan un switch por KEM.

```go
func kemCurve(cs CipherSuite) ecdh.Curve {
    switch cs.HPKEConfig().KEM {
    case DHKEM_X25519_HKDF_SHA256:
        return ecdh.X25519()
    default: // DHKEM_P256
        return ecdh.P256()
    }
}
```

**Cambios en `dhkemEncap`**:
```go
func dhkemEncap(pkR []byte, cs CipherSuite) (sharedSecret, enc []byte, err error) {
    curve := kemCurve(cs)              // ← genérico
    skE, err := curve.GenerateKey(rand.Reader)
    pkRKey, err := curve.NewPublicKey(pkR)
    // ... resto igual
}
```

**Cambios en `DeriveKeyPair`**: El algoritmo Bitmask de P256 no aplica a X25519.
X25519 solo necesita `curve.NewPrivateKey(ikm[:32])` (scalar ya es válido por construcción).

```go
func DeriveKeyPair(cs CipherSuite, ikm []byte) (*ecdh.PrivateKey, error) {
    switch cs.HPKEConfig().KEM {
    case DHKEM_X25519_HKDF_SHA256:
        return deriveKeyPairX25519(cs, ikm)
    default:
        return deriveKeyPairP256(cs, ikm) // lógica actual
    }
}

func deriveKeyPairX25519(cs CipherSuite, ikm []byte) (*ecdh.PrivateKey, error) {
    kemID := kemSuiteID(cs)
    dkpPrk := hpkeLabeledExtract(nil, "dkp_prk", ikm, kemID)
    skBytes, err := hpkeLabeledExpand(dkpPrk, "sk", nil, 32, kemID)
    if err != nil {
        return nil, err
    }
    return ecdh.X25519().NewPrivateKey(skBytes)
}
```

**`dhkemExtractAndExpand`**: el `sharedSecret` length cambia (32 para X25519, 32 para P256 —
mismo en ambos casos). No necesita cambio.

**`hpkeKeyScheduleBase`**: el key/nonce length depende del AEAD, no del KEM. No cambia para CS=1.

---

### 4.3 — `ciphersuite/signature.go`: soporte Ed25519

Ed25519 y ECDSA tienen APIs muy distintas. La forma más limpia sin over-engineering:

**Agregar funciones para Ed25519**:
```go
// GenerateEd25519SignaturePrivateKey genera un par de claves Ed25519.
func GenerateEd25519SignaturePrivateKey() (*SignaturePrivateKey, error)

// NewEd25519SignaturePrivateKey crea una clave privada Ed25519 desde bytes.
func NewEd25519SignaturePrivateKey(priv []byte) (*SignaturePrivateKey, error)
```

**Cambiar `SignWithLabel` y `VerifyWithLabel`** para ramificar por scheme:
```go
func SignWithLabel(key *SignaturePrivateKey, label string, content []byte) (Signature, error) {
    tbs := marshalSignContent(label, content)
    switch key.scheme {
    case ED25519:
        return signEd25519(key.raw, tbs)
    default: // ECDSA_SECP256R1_SHA256
        return signECDSA(key.raw, tbs)
    }
}
```

**`SignaturePrivateKey` y `SignaturePublicKey`** necesitan almacenar el scheme:
- Ya tienen `scheme SignatureScheme` (verificar en `signature.go`)
- Si no, agregar `scheme` field

**`OpenMlsSignaturePublicKey`**: ajustar para Ed25519:
```go
func (pk *OpenMlsSignaturePublicKey) verify(tbs, sig []byte) error {
    switch pk.scheme {
    case ED25519:
        return verifyEd25519(pk.rawBytes, tbs, sig)
    default:
        return verifyECDSA(pk.rawBytes, tbs, sig)
    }
}
```

---

### 4.4 — `keypackages/key_packages.go`: generación para CS=1

**`Generate(cred, cs)`** actualmente hardcodea P256 para init key, encryption key y signature key.

```go
// Agregar switch en Generate():
var initPrivKey *ecdh.PrivateKey
switch cs {
case MLS128DHKEMX25519, MLS128X25519CHACHA:
    initPrivKey, err = ecdh.X25519().GenerateKey(rand.Reader)
default: // P256
    initPrivKey, err = ecdh.P256().GenerateKey(rand.Reader)
}

// Para signature key (Ed25519 vs ECDSA):
switch cs {
case MLS128DHKEMX25519, MLS128X25519CHACHA:
    // usar ed25519.GenerateKey(rand.Reader)
    // SignatureKey es ed25519.PublicKey ([]byte de 32 bytes)
default:
    // ECDSA P256 (actual)
}
```

**Problema**: `LeafNode.SignatureKey` es `*ecdsa.PublicKey`. Para Ed25519 necesitamos
un tipo diferente. Opciones:
- Agregar `SignatureKeyEd25519 ed25519.PublicKey` field (más simple, no over-engineering)
- O usar `SignatureKeyBytes []byte` que ya existe — usar solo los bytes raw

**Recomendación**: usar `SignatureKeyBytes []byte` (ya existe) como representación
primaria para CS=1, y solo popularlo. La firma en `keypackages` puede quedar como bytes.

---

### 4.5 — `treesync/serialization.go`: parseo genérico de enc keys

Líneas 113 y 200 hardcodean `ecdh.P256().NewPublicKey(encKeyBytes)`.

**Problema**: `treesync` no tiene acceso al CipherSuite. Hay que propagarlo o
hacer `UnmarshalTree` / `UnmarshalTreeFromExtension` CS-aware.

**Opción A** (simple): pasar `cs CipherSuite` a `UnmarshalTree(data, cs)`:
```go
func UnmarshalTree(data []byte, cs CipherSuite) (*RatchetTree, error)
```

Y dentro:
```go
var encKey *ecdh.PublicKey
if len(encKeyBytes) > 0 {
    switch cs.HPKEConfig().KEM {
    case DHKEM_X25519_HKDF_SHA256:
        encKey, err = ecdh.X25519().NewPublicKey(encKeyBytes)
    default:
        encKey, err = ecdh.P256().NewPublicKey(encKeyBytes)
    }
}
```

**Actualizar todos los call sites** de `UnmarshalTree` y `UnmarshalTreeFromExtension`
para pasar el cipher suite.

---

### 4.6 — `treesync/node.go`: parseo de signature keys

Línea 156: `l.SignatureKey = &ecdsa.PublicKey{Curve: elliptic.P256(), ...}`
Solo aplica si son 65 bytes (P256 uncompressed). Para Ed25519 son 32 bytes.

```go
if len(sigKeyBytes) == 65 && sigKeyBytes[0] == 0x04 {
    // P256 (actual)
    x := new(big.Int).SetBytes(sigKeyBytes[1:33])
    y := new(big.Int).SetBytes(sigKeyBytes[33:65])
    l.SignatureKey = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
} else if len(sigKeyBytes) == 32 {
    // Ed25519: guardar solo en SignatureKeyRaw
    // (SignatureKey *ecdsa.PublicKey queda nil)
}
```

La verificación en `VerifyWithContext` ya usa `marshalSignatureKey()` →
`NewOpenMlsSignaturePublicKey(pubKeyBytes, scheme)` → `VerifyWithLabel`.
Hay que asegurar que el scheme se pase correctamente.

---

### 4.7 — `group/group.go` y `group/external_commit.go`: reemplazar `ecdh.P256()`

21 ocurrencias hardcodeadas. Para cada una, reemplazar con `kemCurve(g.CipherSuite)`:

```go
// Antes:
tree.Nodes[nodeIdx].EncryptionKey, _ = ecdh.P256().NewPublicKey(pubKeys[m])

// Después:
curve := ciphersuite.KEMCurve(g.CipherSuite)
tree.Nodes[nodeIdx].EncryptionKey, _ = curve.NewPublicKey(pubKeys[m])
```

**Agregar en `ciphersuite`**:
```go
// KEMCurve retorna la curva ECDH para el KEM de este cipher suite.
func KEMCurve(cs CipherSuite) ecdh.Curve {
    switch cs.HPKEConfig().KEM {
    case DHKEM_X25519_HKDF_SHA256:
        return ecdh.X25519()
    default:
        return ecdh.P256()
    }
}
```

---

### 4.8 — `credentials/credentials.go`: generación de claves Ed25519

Línea 653: `ecdsa.GenerateKey(elliptic.P256(), rand.Reader)` hardcodeado.

`GenerateCredentialWithKey` debe aceptar un parámetro de scheme o cs:
```go
func GenerateCredentialWithKey(identity []byte) (*Credential, *SignaturePrivateKey, error)
// → para CS=1 debería generar Ed25519
// → para CS=2 sigue con P256
```

**Opción simple**: agregar variante:
```go
func GenerateCredentialWithKeyForCS(identity []byte, cs CipherSuite) (*Credential, *SignaturePrivateKey, error)
```

---

### 4.9 — `extensions/`: actualizar external_pub y external_senders

`external_pub_extension.go:265` y `external_senders.go:265` hardcodean P256.
Misma corrección: usar `KEMCurve(cs)` o `kemCurve`.

---

### 4.10 — Test de interop CS=1

Una vez implementado, correr los passive-client vectors con cs=1:
```go
if v.CipherSuite != 2 && v.CipherSuite != 1 {
    continue
}
```

Vectores en `passive-client-handling-commit.json` tienen cs=1, cs=2 y otros.
Goal: cs=1 vectors pasen.

---

## Bloque 5: CS=3 — MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519

Una vez CS=1 funciona, CS=3 solo agrega ChaCha20Poly1305.

### 5.1 — `ciphersuite/hpke.go` y `aead.go`: ChaCha20Poly1305

**`encryptWithLabelInternal`** / **`decryptWithLabelInternal`** tienen `aes.NewCipher` + `cipher.NewGCM` hardcodeados.

```go
func newAEAD(cs CipherSuite, key []byte) (cipher.AEAD, error) {
    switch cs.AeadAlgorithm() {
    case CHACHA20POLY1305:
        return chacha20poly1305.New(key)  // golang.org/x/crypto
    case AES256GCM:
        block, _ := aes.NewCipher(key)
        return cipher.NewGCM(block)
    default: // AES128GCM
        block, _ := aes.NewCipher(key)
        return cipher.NewGCM(block)
    }
}
```

**Nota**: `golang.org/x/crypto/chacha20poly1305` es stdlib-adyacente pero técnicamente
fuera de stdlib. El proyecto actualmente usa solo stdlib. Verificar si se acepta esta dependencia.
**Alternativa**: implementar ChaCha20Poly1305 manualmente usando `golang.org/x/crypto` —
que es un módulo estándar de Go pero separado de `crypto/`.

**`hpkeKeyScheduleBase`**: el key length para ChaCha20 es 32 bytes (vs 16 para AES-128).
Cambiar `hpkeLabeledExpand(secret, "key", ksContext, 16, suiteID)` para usar `cs.AeadKeyLength()`.

---

## Bloque 6: CS=4–7 (AES-256, P384, P521, X448)

Una vez la infraestructura genérica existe, agregar:

| CS (RFC §17.1) | KEM | Firma | AEAD | Hash |
|----------------|-----|-------|------|------|
| 0x0004 | X448 | Ed448 | AES-256-GCM | SHA-512 |
| 0x0005 | P521 | ECDSA P521 | AES-256-GCM | SHA-512 |
| 0x0006 | X448 | Ed448 | ChaCha20Poly1305 | SHA-512 |
| 0x0007 | P384 | ECDSA P384 | AES-256-GCM | SHA-384 |

**Notas**:
- Go stdlib NO tiene `ecdh.X448()` ni `ecdh.P521()` ni `ecdh.P384()` en `crypto/ecdh`
- Para X448: no está en `crypto/ecdh` — requiere `filippo.io/edwards25519` o implementación propia
- Ed448: no está en stdlib — requiere dependencia externa
- Para P384/P521: disponibles en `crypto/elliptic` (sí están) pero no en `crypto/ecdh`
- **Recomendación**: CS=4,6 (X448/Ed448) requieren deps externas. CS=5 (P521) y CS=7 (P384)
  se pueden hacer con `crypto/elliptic` + adaptadores, sin deps externas.

---

## Bloque 7: required_capabilities extension (RFC §7.2)

**RFC §7.2**: GroupContextExtensions puede incluir `required_capabilities`.
Cuando está presente, todos los nuevos miembros deben soportar esas capabilities.

**Archivos afectados**: `extensions/`, `group/proposal_filter.go`

**Qué hay que hacer**:
- En `validateSingleProposal` para Add, leer la extensión `required_capabilities`
  del GroupContext y verificar que el KeyPackage del Add la soporta
- Es una validación adicional en `validateCapabilitiesCompatible`

---

## Orden de implementación recomendado

```
Bloque 1: Gaps de seguridad (1.1, 1.2)
  → Rápidos, no requieren cambios arquitecturales
  → Directamente en proposal_filter.go

Bloque 2: PrivateMessage commits (2.1)
  → Moderado, requiere refactor de ProcessPublicMessage
  → Importante para producción

Bloque 3: API pública (3.1, 3.2)
  → Simples, bajo riesgo

Bloque 4: CS=1 — el cambio grande
  Sub-orden:
    4.1 Constantes y config en ciphersuite.go
    4.2 HPKE X25519 en hpke.go
    4.3 Ed25519 en signature.go
    4.4 keypackages generación CS=1
    4.5 treesync UnmarshalTree CS-aware
    4.6 treesync node.go Ed25519 parsing
    4.7 group.go / external_commit.go: KEMCurve()
    4.8 credentials Ed25519
    4.9 extensions actualizar
    4.10 tests interop CS=1

Bloque 5: CS=3 (ChaCha20Poly1305)
  → Depende de 4.x
  → Requiere decisión sobre golang.org/x/crypto

Bloque 6: CS=4-7
  → Depende de 4.x y 5.x
  → CS=5,7 más fáciles (P521/P384 en crypto/elliptic, sin deps externas)
  → CS=4,6 (X448/Ed448) requieren deps externas
  → CS=4,5 requieren deps externas (X448/Ed448)

Bloque 7: required_capabilities
  → Independiente, agregar al final
```

---

## Checklist de archivos a modificar por bloque

### Bloque 1 (firmas en proposals)
- [ ] `keypackages/key_packages.go` — agregar `KeyPackage.MarshalTBS()` y `KeyPackage.Verify(cs)`
- [ ] `group/proposal_filter.go` — llamar Verify en Add y Update proposals

### Bloque 2 (PrivateMessage commits)
- [ ] `group/group.go` — agregar `ProcessPrivateMessage()`
- [ ] `framing/auth.go` o `framing/private_message.go` — adaptar DecryptPrivateMessage
- [ ] `group/group.go` — refactorizar processing de commit a función compartida

### Bloque 3 (API pública)
- [ ] `group/group.go` — agregar `Export(label, context, length)`
- [ ] `group/group.go` — agregar case 3 en PSK resolution

### Bloque 4 (CS=1)
- [ ] `ciphersuite/ciphersuite.go` — constantes CS=1, KEMAlgorithm X25519, SignatureScheme Ed25519
- [ ] `ciphersuite/hpke.go` — `kemCurve()`, `DeriveKeyPair` X25519, `dhkemEncap/Decap` genérico
- [ ] `ciphersuite/signature.go` — Ed25519 sign/verify, `KEMCurve()` helper exportado
- [ ] `keypackages/key_packages.go` — `Generate()` CS-aware para X25519+Ed25519
- [ ] `treesync/serialization.go` — `UnmarshalTree(data, cs)` y `UnmarshalTreeFromExtension(data, cs)`
- [ ] `treesync/node.go` — parseo de Ed25519 signature keys (32 bytes)
- [ ] `group/group.go` — 8 ocurrencias de `ecdh.P256()` → `ciphersuite.KEMCurve(cs)`
- [ ] `group/external_commit.go` — 2 ocurrencias → `KEMCurve(cs)`
- [ ] `credentials/credentials.go` — `GenerateCredentialWithKeyForCS(identity, cs)`
- [ ] `extensions/external_pub_extension.go` — P256 → genérico
- [ ] `extensions/external_senders.go` — P256 → genérico

### Bloque 5 (CS=3)
- [ ] `ciphersuite/ciphersuite.go` — constante CS=3, CHACHA20POLY1305
- [ ] `ciphersuite/hpke.go` — `newAEAD(cs, key)` con ChaCha20Poly1305
- [ ] `ciphersuite/hpke.go` — `hpkeKeyScheduleBase` usar `cs.AeadKeyLength()` en lugar de 16

### Bloque 6 (CS=5 y CS=7 con stdlib — P521, P384)
- [ ] Similar a CS=2 pero con P521/P384 en `crypto/elliptic` (no `crypto/ecdh`)

### Bloque 7 (required_capabilities)
- [ ] `group/proposal_filter.go` — leer y validar extensión

---

## Notas técnicas importantes

### X25519 vs P256 — diferencias de API en Go

```go
// P256: bytes = 65 (04 || X || Y), uncompressed
ecdh.P256().GenerateKey(rand.Reader)  // private.Bytes() = 32, public.Bytes() = 65

// X25519: bytes = 32 (scalar), always valid
ecdh.X25519().GenerateKey(rand.Reader)  // private.Bytes() = 32, public.Bytes() = 32
```

El campo `EncryptionKey` en `treesync.Node` (tipo `*ecdh.PublicKey`) acepta ambos.
La serialización cambia solo el tamaño.

### Ed25519 en Go

```go
import "crypto/ed25519"

pub, priv, _ := ed25519.GenerateKey(rand.Reader)
sig := ed25519.Sign(priv, message)
ok := ed25519.Verify(pub, message, sig)
```

Ed25519 está en stdlib desde Go 1.13. No requiere dependencias externas.
La firma tiene 64 bytes; la clave pública 32 bytes.

### DeriveKeyPair para X25519 (RFC 9180 §4.1)

RFC 9180 Appendix A.1 define `DeriveKeyPair` para X25519:
```
def DeriveKeyPair(ikm):
  dkp_prk = LabeledExtract("", "dkp_prk", ikm)
  sk = LabeledExpand(dkp_prk, "sk", "", Nsk)  # Nsk = 32
  return (sk, sk_to_pk(sk))
```
Para X25519, cualquier 32-byte scalar es válido (clampear los bits 0,1,2,255 → lo hace
`ecdh.X25519().NewPrivateKey()` internamente).

### HKDF para CS=1

CS=1 usa HKDF-SHA256 (igual que CS=2). El `schedule/` package no necesita cambios.

### TreeHash para CS=1

El TreeHash usa SHA-256 para CS=2. Para CS=1 también usa SHA-256 (mismo hash).
Solo cambia si se agrega CS con SHA-512 (CS=4,5,6,7).
`treesync/hash.go` necesita revisión para CS=4+.
