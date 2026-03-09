# Base de Conocimiento - OpenMLS Go

## Visión General del Proyecto

OpenMLS Go es una implementación en Go del protocolo Messaging Layer Security (MLS), según lo especificado en [RFC 9420](https://datatracker.ietf.org/doc/html/rfc9420). MLS es un protocolo de encriptación end-to-end para mensajería grupal.

Esta implementación está basada en la [implementación OpenMLS en Rust](https://github.com/openmls/openmls) y se está desarrollando como una librería nativa en Go. El proyecto también incluye documentación y consideraciones para DAVE (Discord Audio/Video End-to-end Encryption), un protocolo que usa MLS para encriptación de comunicación en tiempo real.

## Tecnologías Clave

| Tecnología | Versión/Detalle |
|------------|-----------------|
| Lenguaje | Go 1.23+ (toolchain: go1.24.5) |
| Protocolo | MLS 1.0 (RFC 9420) |
| Cipher Suite | MLS_128_DHKEMP256_AES128GCM_SHA256_P256 (0x0002) |
| Licencia | MIT |

## Estructura del Repositorio

```
mls-go/
├── ciphersuite/          # Primitivas criptográficas (AEAD, HPKE, HKDF, firmas)
├── credentials/          # Credenciales MLS (Basic, X509) según RFC 9420 §5.3
├── extensions/           # Extensiones de grupo MLS
├── framing/              # Enmarcado de mensajes (PublicMessage, PrivateMessage)
├── group/                # Gestión de grupos (creación, propuestas, commits)
├── internal/tls/         # Codificación/decodificación TLS presentation language
├── key_packages/         # Generación y manejo de KeyPackage
├── messages/             # Mensajes MLS (Welcome, Commit, Proposal, GroupInfo)
├── schedule/             # Implementación del key schedule
├── secret_tree/          # Árbol de secretos para encriptación de mensajes
├── tree/                 # (Vacío - implementación de ratchet tree pendiente)
├── treesync/             # Sincronización de árbol
├── openmls/              # Implementación OpenMLS Rust de referencia (submódulo)
├── test_vectors/         # Vectores de test MLS
├── protocol.md           # Especificación del protocolo DAVE (Discord A/V E2EE)
├── rfc9420.txt           # Referencia de la especificación RFC 9420
└── doc.go                # Documentación del paquete con ejemplos de uso
```

## Construcción y Ejecución

### Prerrequisitos
- Go 1.23 o posterior (el proyecto usa toolchain go1.24.5)

### Comandos

```bash
# Correr todos los tests
go test ./...

# Correr tests con coverage
go test -cover ./...

# Correr tests de un paquete específico
go test ./ciphersuite/...
go test ./group/...
go test ./messages/...

# Build del proyecto
go build ./...

# Correr linter (si tenés golangci-lint instalado)
golangci-lint run

# Formatear código
go fmt ./...
```

## Arquitectura de Paquetes

### Paquetes Core

| Paquete | Descripción |
|---------|-------------|
| `ciphersuite` | Primitivas criptográficas: AES-GCM, ECDSA, HPKE, HKDF, SHA-256 |
| `credentials` | Tipos de credencial Basic y X509 para autenticación de miembros |
| `extensions` | Extensiones de grupo (external senders, ratchet tree, capabilities) |
| `framing` | Enmarcado de mensajes MLS (PublicMessage, PrivateMessage, MLSMessage) |
| `group` | Ciclo de vida del grupo: creación, gestión de miembros, transiciones de epoch |
| `key_packages` | Generación, serialización y validación de KeyPackage |
| `messages` | Tipos de mensaje Welcome, Commit, Proposal y GroupInfo |
| `schedule` | Key schedule para derivar keys de encriptación |
| `secret_tree` | Estructura de secret tree para keys de encriptación por sender |
| `treesync` | Protocolo de sincronización de árbol |

### Paquetes Internos

| Paquete | Descripción |
|---------|-------------|
| `internal/tls` | Encoder/decoder de TLS presentation language (RFC 8446) |

## Convenciones de Desarrollo

### Estilo de Código
- Seguir convenciones estándar de Go (`gofmt`/`goimports`)
- Usar nombres significativos para variables y funciones
- Agregar comentarios godoc para tipos y funciones exportados
- Los comentarios de paquete deben incluir overview y ejemplos de uso

### Prácticas de Testing
- Los tests están basados en el test suite de OpenMLS Rust
- Cada paquete tiene su(s) propio(s) archivo(s) de test
- Hay tests de integración para framing y extensions
- Usar table-driven tests donde sea apropiado

### Guías de Contribución
1. Forkear el repositorio
2. Crear una branch para features/fixes
3. Escribir tests para toda funcionalidad nueva
4. Asegurarse que todos los tests pasen: `go test ./...`
5. Formatear código: `go fmt ./...`
6. Submitir un PR con una descripción clara

## Estado de Implementación

### Completado ✅
- Implementación de cipher suite (AES-GCM, ECDSA, HPKE, HKDF)
- Tipos de credencial (Basic, X509)
- Enmarcado de mensajes (PublicMessage, PrivateMessage)
- Creación y parsing de mensajes Welcome
- Creación de grupos y gestión básica de miembros
- Framework de extensiones
- Key schedule
- Secret tree
- Sincronización de árbol

### En Progreso / TODO ⏳
- Implementación completa de mensajes Commit
- Implementación completa de mensajes Proposal
- Implementación de TreeKEM
- Integración completa del key schedule
- Tests de interoperabilidad con OpenMLS Rust
- Soporte para protocolo DAVE

## Ejemplo de Uso

```go
package main

import (
    "github.com/openmls/go/ciphersuite"
    "github.com/openmls/go/credentials"
    "github.com/openmls/go/group"
    "github.com/openmls/go/key_packages"
)

// Crear un nuevo grupo MLS
cs := ciphersuite.MLS128DHKEMP256
cred := credentials.NewBasicCredential("Alice")
kp, privKeys, err := key_packages.Generate(cred, cs)
if err != nil {
    log.Fatal(err)
}

grp, err := group.New(cs, kp, privKeys)
if err != nil {
    log.Fatal(err)
}

// Agregar un miembro
welcome, err := grp.AddMember("Bob")
if err != nil {
    log.Fatal(err)
}

// Encriptar/Desencriptar
ciphertext, err := grp.Encrypt([]byte("Hello, MLS!"))
plaintext, err := grp.Decrypt(ciphertext)
```

## Documentación Relacionada

- [RFC 9420](https://datatracker.ietf.org/doc/html/rfc9420) - Especificación del Protocolo MLS
- [protocol.md](./protocol.md) - Especificación del Protocolo DAVE (Discord A/V E2EE)
- [CONTRIBUTING.md](./CONTRIBUTING.md) - Guías de contribución
- [OpenMLS Rust](https://github.com/openmls/openmls) - Implementación de referencia

## Información del Módulo

| Campo | Valor |
|-------|-------|
| Module Path | `github.com/openmls/go` |
| Version | `0.1.0-dev` |
| Go Version | 1.23.0+ |

---

# 📝 Estilo de Mis Notas de Aprendizaje

Cuando te pida crear notas para Obsidian o apuntes de estudio, seguí estas instrucciones:

## 🗣️ Tono y Persona

- **Primera persona siempre**: "yo", "me di cuenta", "aca lo entendi asi", "lo que veo en el código es..."
- **Técnico pero conversacional**: Como explicarle a un compañero del laburo, no a un profesor
- **Acento argentino natural** (sin forzar):
  - Voseo solo si hablás directamente al lector: "si querés ver...", "fijate que..." (usar poco)
  - Primera persona: "tengo", "veo", "entiendo", "vi", "lei", "me cerró", "no me cierra"
  - Palabras cotidianas: "che", "bueno", "dale", "obvio", "re" (como intensificador: "re importante")
  - Frases típicas: "lo veo así", "basicamente", "la verdad", "tipo"
- **Frases naturales** (usar con moderación, no forzar):
  - "aca" para señalar partes específicas: "aca en el `schedule/`...", "aca no me cerraba..."
  - "q e eto?" cuando introducís algo nuevo o confuso
  - "basicamente" para cerrar explicaciones densas
  - "aca no entendi un choto" solo cuando algo realmente confunde
- **Keywords técnicas en inglés**: middleware, promise, async/await, cipher, key_schedule, epoch, ratchet, struct, opaque, etc. (no traducir)
- **Sin emojis**: Texto limpio, solo Markdown y ASCII si ayuda
- **Prohibido sonar a IA**: Nada de "es importante destacar", "cabe mencionar", "en conclusión", "como modelo de lenguaje"
- **Falta de ortografía intencional**: Escribir como hablo, no como libro. Texto imperfecto, como nota real:
  - "q" en vez de "qué" (solo en "q e eto?", "lo q vi", "para q")
  - "aca" en vez de "acá"
  - "basicamente" sin tilde
  - "entendi" sin tilde
  - "tambien" sin tilde
  - "mas" sin tilde (cuando es cantidad)
  - "solo" sin tilde
  - Verbos conjugados informales: "tengo", "veo", "entiendo", "vi", "lei"
  - Apócopes: "pa" en vez de "para" (opcional, usar poco)
  - **Puntuación relajada**: comas y puntos opcionales, a veces no los pongo
  - **Palabras incompletas**: "basico", "implement", "valid" (cuando estoy apurado)
  - **Frases cortadas**: que parezca que escribo rápido, no que edito perfecto

---

## 🎨 Diagramas ASCII (Cuándo y Cómo Usarlos)

### Cuándo Incluir un Diagrama
- **Flujos de datos**: Mostrar cómo viaja la información entre componentes
- **Estructuras jerárquicas**: Árboles, nested structs, capas de abstracción
- **Secuencias temporales**: Epoch transitions, handshakes, state machines
- **Relaciones entre paquetes**: Dependencias, llamadas entre módulos

### Cuándo NO Incluir un Diagrama
- Si el concepto es simple y se explica en una frase
- Si el diagrama no agrega claridad real (solo decorativo)
- Si el código ya es suficientemente explícito

### Formato de Diagramas ASCII

```
# Flujo simple
[Entrada] --> [Proceso] --> [Salida]

# Con decisiones
[Request] --> [¿Valido?] --SÍ--> [Procesar]
                 |
                NO
                 |
                 v
            [Rechazar 400]

# Estructura jerárquica
[Group]
   |
   +-- [Members]
   |      +-- [KeyPackage]
   |      +-- [Credential]
   |
   +-- [SecretTree]
          +-- [Leaf]
          +-- [Parent]

# Secuencia temporal
Epoch N        Epoch N+1      Epoch N+2
   |              |              |
[Commit] -----> [Commit] -----> [Commit]
   |              |              |
[Keys]        [Keys]        [Keys]
```

### Reglas para Diagramas
1. **Mantenelos simples**: Máximo 15-20 líneas, si es más largo, dividilo
2. **Usá etiquetas claras**: `[Componente]`, `-->`, `--SÍ-->`, `--NO-->`
3. **Alineá verticalmente**: Que sea fácil seguir el flujo con la vista
4. **Incluí leyenda si es complejo**: Explicá qué significa cada símbolo

---

## 📚 Citas y Fuentes de Verdad

### Qué Siempre Citar
| Tipo | Formato | Ejemplo |
|------|---------|---------|
| **RFCs** | `RFC 9420 §11.2` + link | [RFC 9420 §11.2](https://datatracker.ietf.org/doc/html/rfc9420#section-11.2) |
| **Código del proyecto** | `ruta/archivo.go:Línea` | `schedule/derivation.go:L45` |
| **Docs externas** | Nombre + link | [OpenMLS Rust Docs](https://docs.openmls.io/) |
| **Issues/PRs** | `#Número` + link | [Issue #23](https://github.com/openmls/go/issues/23) |
| **Comentarios en código** | Citar el comentario literal | `// Derives epoch secret from commit` |

### Dónde Poner las Citas en la Nota

```markdown
## Fuentes consultadas
- RFC 9420 §11.2 (Key Schedule): https://datatracker.ietf.org/doc/html/rfc9420#section-11.2
- Código: `schedule/derivation.go` (líneas 40-60)
- OpenMLS Rust: `src/schedule/mod.rs` para comparación

## Referencias en el texto
- "Como dice el RFC 9420 §5.3, las credenciales..."
- "En el código (`group/create.go:L25`) se ve que..."
- "Esto difiere de la implementación Rust en..."
```

### Reglas para Citas
1. **Siempre linkeá al RFC** cuando menciones algo del protocolo
2. **Referenciá el archivo específico** del proyecto, no solo el paquete
3. **Si hay discrepancia entre RFC y código**, anotalo en "Dudas"
4. **Incluí la versión** si es relevante (RFC 9420 vs draft, Go 1.23 vs 1.24)

---

## 🔍 Explicación de Estructuras de Datos (RFC → Go)

### Cómo Traducir Estructuras del RFC a Go

Cuando encuentres una estructura del RFC (como `FramedContent`), explicala así:

#### Ejemplo: FramedContent del RFC 9420

**Estructura original (RFC):**
```
struct {
    opaque group_id<V>;
    uint64 epoch;
    Sender sender;
    opaque authenticated_data<V>;

    ContentType content_type;
    select (FramedContent.content_type) {
        case application:
          opaque application_data<V>;
        case proposal:
          Proposal proposal;
        case commit:
          Commit commit;
    };
} FramedContent;
```

**Mi traducción a Go (aca lo entendi asi):**

| RFC | Go | Notas |
|-----|-----|-------|
| `struct { ... }` | `type FramedContent struct { ... }` | Igual, es un struct |
| `opaque group_id<V>` | `GroupID []byte` | `opaque` = byte slice, `<V>` = variable length |
| `uint64 epoch` | `Epoch uint64` | Directo, mismo tipo |
| `Sender sender` | `Sender Sender` | Otro struct, hay que ver su definición |
| `opaque authenticated_data<V>` | `AuthenticatedData []byte` | Otro campo variable-length |
| `ContentType content_type` | `ContentType ContentType` | Enum/const en Go |
| `select (...) { case ... }` | `interface{}` + type switch | **Esto es clave**: el `select` es como un interface en Go |

### El `select` explicado

Aca lo entendi asi: el `select` del RFC es como tener un field que puede ser **distintos tipos** dependiendo del `content_type`. En Go, eso se resuelve con:

```go
type FramedContent struct {
    GroupID           []byte
    Epoch             uint64
    Sender            Sender
    AuthenticatedData []byte
    ContentType       ContentType
    Content           interface{} // <-- Esto es el `select`
}

// Después, al usarlo:
switch fc.ContentType {
case Application:
    data := fc.Content.([]byte)
case Proposal:
    proposal := fc.Content.(*Proposal)
case Commit:
    commit := fc.Content.(*Commit)
}
```

Otra opción (más type-safe):

```go
type FramedContent struct {
    GroupID           []byte
    Epoch             uint64
    Sender            Sender
    AuthenticatedData []byte
}

type FramedContentApplication struct {
    FramedContent
    ApplicationData []byte
}

type FramedContentProposal struct {
    FramedContent
    Proposal Proposal
}

type FramedContentCommit struct {
    FramedContent
    Commit Commit
}
```

**Q e eto?** del `opaque`: Básicamente es bytes sin interpretación. En Go, `[]byte`. El `<V>` significa que tiene un prefix de longitud (variable-length), tipo `uint32` + bytes.

### Plantilla para Explicar Estructuras

```markdown
## Estructura: {{Nombre}}

### Definición original (RFC / spec)
```
{{Pegar la estructura tal cual}}
```

### Traducción a Go (aca lo entendi asi)
| Campo RFC | Tipo Go | Notas |
|-----------|---------|-------|
| `opaque X<V>` | `X []byte` | Variable-length byte slice |
| `uint32 Y` | `Y uint32` | Directo |
| `select (...)` | `interface{}` o structs separados | Depende del caso |
| `Z<V>` | `Z []byte` | Variable-length |

### Cómo se usa en el código
```go
// Ejemplo mínimo de uso real
{{Snippet de Go del proyecto}}
```

### Dudas sobre la estructura
- [ ] q e eto? de {{campo específico}}
- [ ] Aca no entendi un choto por qué {{algo}}
```

### Reglas para Explicar Estructuras
1. **Mostrá la estructura original** del RFC/spec primero
2. **Traducí campo por campo** a Go, explicando cada tipo
3. **Incluí un snippet de uso real** del proyecto si existe
4. **Marcá las dudas** sobre campos que no entendés del todo
5. **Referenciá el archivo** donde está implementado: `framing/content.go`

---

## 📓 Formato de Nota (Completo)

```markdown
---
tags: [aprendizaje, {{topic_tag}}, {{project_tag}}]
fecha: {{date}}
estado: 🌱 confuso / 🔄 en-proceso / ✅ entendido / 📚 para-enseñar
relacionado: [[Nota A]], [[Nota B]]
---

# {{Título: pregunta o concepto}}

> TL;DR: Una frase que resume lo esencial, como si se lo contaras a vos mismo en una semana.

## Lo que entiendo hasta ahora
- Explicación en primera persona, técnica pero accesible
- Referenciar código real del proyecto cuando corresponda
- Si algo te confundió: "aca no entendi un choto por qué...", pero solo si es real
- "basicamente" para sintetizar después de una explicación densa

## Conceptos clave
| Concepto | Qué es | Por qué me importa | Ejemplo mínimo |
|----------|--------|-------------------|----------------|
| X | Explicación simple | Cómo lo voy a usar | snippet corto |

## Diagrama ASCII (solo si ayuda a visualizar)
```
[Entrada] --> [Proceso] --> [Salida]
|            |
v            v
[Error?]    [Log?]
```

## Estructuras de Datos (si aplica)
### Estructura: {{Nombre}}

**Definición original:**
```
{{Estructura del RFC}}
```

**Traducción a Go (aca lo entendi asi):**
| Campo RFC | Tipo Go | Notas |
|-----------|---------|-------|
| `opaque X<V>` | `X []byte` | Variable-length |
| `select (...)` | `interface{}` | Como un interface en Go |

**Uso en el código:**
```go
{{Snippet real del proyecto}}
```

## ❓ Lo que todavía no entendi (para revisar después)
- [ ] "q e eto?" de X: descripción breve de la duda
- [ ] "aca no entendi un choto" por qué Y hace Z
- [ ] Links a docs, RFCs o issues para investigar después

> Esta sección es clave: no borres las dudas, son el mapa de lo que tenés que aprender.

## 🔗 Conexiones con otras notas
- Relaciona con: [[Nota existente]] o crea [[Nueva nota para profundizar]]
- Usa backlinks naturalmente: "esto conecta con [[Key Schedule]] porque..."

## 📚 Fuentes consultadas
- RFC 9420 §11.2: https://datatracker.ietf.org/doc/html/rfc9420#section-11.2
- Código: `schedule/derivation.go` (líneas 40-60)
- OpenMLS Rust: `src/schedule/mod.rs`

## 📌 Para repasar / profundizar
- [ ] Probar este snippet en el proyecto
- [ ] Leer esta doc: [link]
- [ ] Explicárselo a alguien (rubber ducking)
- [ ] Revisar esta nota en 1 semana

## 🔄 Historial de entendimiento (opcional pero útil)
- 2026-03-06: Primera versión, entiendo lo básico pero me quedan dudas sobre X
- 2026-03-13: Actualicé después de leer el RFC, ahora entiendo Y
```

---

## ✍️ Reglas de Escritura

1. **Aprendizaje > Perfección**: Mejor una nota con dudas reales que una "perfecta" pero vacía
2. **Las dudas son features, no bugs**: La sección "Lo que todavía no entendi" es obligatoria si hay algo pendiente
3. **Conexiones explícitas**: Siempre preguntate "¿con qué otra nota se relaciona esto?" y linkealo
4. **Evolución visible**: Si actualizás la nota, agregá una entrada en "Historial de entendimiento"
5. **Código mínimo y ejecutable**: Si incluís código, que se pueda copiar y probar (`go test ./...`)
6. **ASCII solo si clarifica**: No hagas arte, hacé diagramas que ayuden a entender flujos
7. **Tags estratégicos**: Usá tags como `#aprendizaje`, `#openmls`, `#go`, `#por-revisar` para filtrar después
8. **Primero para vos, después para otros**: Escribí como si fueras tu propio lector futuro
9. **Citas siempre**: Si mencionás algo del RFC o del código, linkeá la fuente
10. **Traducí estructuras**: Cuando haya un struct del RFC, explicalo campo por campo en Go
11. **Escribí como hablás**: Sin emojis, sin formalismos, con acento argentino natural. Primera persona ("tengo", "veo", "entiendo"), palabras cotidianas ("che", "bueno", "obvio"), y faltas de ortografía naturales ("aca", "basicamente", "entendi", "q e eto?"). Voseo solo si hablás directo al lector ("fijate", "si querés ver"), usar poco. Texto imperfecto: puntuación relajada, palabras incompletas ("basico", "implement"), frases cortadas.

---

## 🎯 Para Este Proyecto (OpenMLS Go)

- Cuando explique conceptos de MLS, usá referencias al código real (`ciphersuite/`, `group/`, `schedule/`, `secret_tree/`, `framing/`)
- Si hay dudas, linkeá a RFC 9420 o al código específico del repositorio
- Incluí snippets de Go que pueda probar con `go test ./ciphersuite/...` o similar
- Mencioná el estado de implementación (✅ Completado / ⏳ En progreso) cuando corresponda
- Si algo está TODO o pendiente, anotalo en "Lo que todavía no entendi" o "Para repasar"
- **Para estructuras del RFC** (como `FramedContent`, `KeyPackage`, `Commit`), usá la plantilla de traducción RFC → Go
- **Para flujos** (como key schedule, epoch transitions), usá diagramas ASCII
- **Siempre citá el RFC** cuando menciones algo del protocolo MLS
- **Bitácora de problemas**: Cuando encuentres un bug o problema complejo, creá una nota en `problemas/YYYY-MM-DD-titulo.md` con:
  - Descripción del problema
  - Cómo lo descubriste
  - Solución aplicada (si la hay)
  - Fix pendiente (si corresponde)
  - Lecciones aprendidas
  - Archivos relacionados
- **Actualizá el índice** de `bitacora/README.md` cuando agregues una nueva entrada

---

## 🧪 Ejemplo de Output Esperado

```markdown
---
tags: [aprendizaje, openmls, framing, go]
fecha: 2026-03-06
estado: 🔄 en-proceso
relacionado: [[Messages]], [[RFC 9420]], [[ContentType]]
---

# FramedContent: q e eto?

> TL;DR: Basicamente, es el contenedor que envuelve cualquier contenido MLS (application, proposal, commit) antes de encriptar.

## Lo que entiendo hasta ahora

Aca en el código del `framing/` vi la estructura de FramedContent. Aca lo entendi asi: es como un envelope que tiene metadata (group_id, epoch, sender) y después el contenido real, que puede ser de distintos tipos.

Aca no entendi un choto al principio el `select` del RFC. Despues me cerró que es como un interface en Go: el tipo del contenido depende del `content_type`.

Basicamente, FramedContent = metadata + contenido polimórfico.

## Estructura: FramedContent

**Definición original (RFC 9420 §6.1):**
```
struct {
opaque group_id<V>;
uint64 epoch;
Sender sender;
opaque authenticated_data<V>;

    ContentType content_type;
    select (FramedContent.content_type) {
        case application:
          opaque application_data<V>;
        case proposal:
          Proposal proposal;
        case commit:
          Commit commit;
    };
} FramedContent;
```

**Traducción a Go (aca lo entendi asi):**

| Campo RFC | Tipo Go | Notas |
|-----------|---------|-------|
| `opaque group_id<V>` | `GroupID []byte` | Variable-length byte slice |
| `uint64 epoch` | `Epoch uint64` | Directo, mismo tipo |
| `Sender sender` | `Sender Sender` | Struct definido en `credentials/` |
| `opaque authenticated_data<V>` | `AuthenticatedData []byte` | Bytes opcionales para contexto |
| `ContentType content_type` | `ContentType uint8` | Enum: application=1, proposal=2, commit=3 |
| `select (...)` | `Content interface{}` | **Clave**: es polimórfico, depende del content_type |

**Uso en el código:**
```go
// framing/content.go
type FramedContent struct {
    GroupID           []byte
    Epoch             uint64
    Sender            Sender
    AuthenticatedData []byte
    ContentType       ContentType
    Content           interface{}
}

// Al usarlo:
switch fc.ContentType {
case ContentTypeApplication:
    data := fc.Content.([]byte)
case ContentTypeProposal:
    proposal := fc.Content.(*Proposal)
case ContentTypeCommit:
    commit := fc.Content.(*Commit)
}
```

## Diagrama ASCII

```
[FramedContent]
      |
      +-- group_id ([]byte)
      +-- epoch (uint64)
      +-- sender (Sender struct)
      +-- authenticated_data ([]byte)
      +-- content_type (uint8)
      |
      v
   [select]
      |
      +-- application --> []byte
      +-- proposal ----> Proposal struct
      +-- commit ------> Commit struct
```

## ❓ Lo que todavía no entendi

- [ ] q e eto? del encoding TLS: cómo se serializa el `select` en bytes?
- [ ] Aca no entendi un choto por qué `authenticated_data` es opcional, cuándo se usa?
- [ ] En el código de Go, están usando `interface{}` o structs separados para cada caso?

> Investigar: RFC 9420 §6.1, `framing/content.go`, `internal/tls/` para el encoding

## 🔗 Conexiones con otras notas

- Esto conecta con [[MLSMessage]] porque FramedContent se envuelve dentro de MLSMessage
- Relacionado con [[ContentType]] porque define los casos del select
- Crear [[TLS Encoding en MLS]] para profundizar en cómo se serializa

## 📚 Fuentes consultadas

- RFC 9420 §6.1 (FramedContent): https://datatracker.ietf.org/doc/html/rfc9420#section-6.1
- Código: `framing/content.go` (líneas 15-40)
- OpenMLS Rust: `src/framing/content.rs` para comparación

## 📌 Para repasar / profundizar

- [ ] Leer RFC 9420 §6.1 completo
- [ ] Ver cómo está implementado en `framing/content.go`
- [ ] Entender el encoding TLS del `select` en `internal/tls/`
- [ ] Revisar esta nota en 1 semana: ¿siguen vigentes las dudas?

## 🔄 Historial de entendimiento

- 2026-03-06: Primera versión. Entiendo la estructura general y la traducción a Go, pero me quedan dudas sobre el encoding TLS del select y cuándo se usa authenticated_data.
```

---

## 🚀 Cómo Usar Esto

Cuando quieras crear una nota de aprendizaje:

```
> /chat "Creá una nota de aprendizaje sobre el Secret Tree en MLS, usando el estilo de este QWEN.md"
```

O para estructuras específicas:

```
> /chat "q e eto? la estructura KeyPackage del RFC, explicala con traducción a Go y diagrama ASCII"
```

O para flujos:

```
> /chat "Creá una nota sobre el Key Schedule con diagrama ASCII del flujo de derivación"
```

El output debería:
- ✅ Usar primera persona ("aca en el `framing/` vi que...")
- ✅ Referenciar código real del proyecto
- ✅ Incluir sección de dudas pendientes
- ✅ Sin emojis, tono técnico pero natural
- ✅ Backlinks sugeridos a otras notas
- ✅ Tags estratégicos para filtrar en Obsidian después
- ✅ Citas a RFCs y archivos específicos
- ✅ Traducción RFC → Go para estructuras
- ✅ Diagrama ASCII si clarifica el flujo
- ✅ Acento argentino natural: primera persona ("tengo", "veo", "entiendo", "me cerró"), palabras cotidianas ("che", "bueno", "obvio"), y faltas de ortografía naturales ("aca", "basicamente", "entendi", "q e eto?", "lei", "tambien"). Voseo solo si hablás directo al lector ("fijate", "si querés ver"), usar poco. Texto imperfecto: puntuación relajada, palabras incompletas ("basico", "implement", "valid"), frases cortadas.