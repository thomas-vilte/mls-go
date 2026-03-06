// Package framing implementa el Message Framing de MLS según RFC 9420 §6.
//
// # ¿Qué es Message Framing?
//
// Message Framing es el proceso de empaquetar contenido MLS (aplicaciones,
// proposals, commits) en mensajes que pueden ser transmitidos por la red.
// El framing provee:
//
//   - Autenticación del remitente (firmas)
//   - Verificación de membresía (membership_tag)
//   - Cifrado para privacidad (PrivateMessage)
//   - Estructura uniforme para todos los mensajes
//
// # Estructuras Principales (RFC 9420 §6)
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                    MLS Message Hierarchy                        │
//	├─────────────────────────────────────────────────────────────────┤
//	│  MLSMessage (wrapper)                                           │
//	│  ├─ PublicMessage  (§6.2)  → Mensajes en claro, firmados       │
//	│  ├─ PrivateMessage (§6.3)  → Mensajes cifrados                 │
//	│  ├─ Welcome        (§11.2) → Mensajes de bienvenida            │
//	│  └─ GroupInfo      (§11.5) → Información del grupo             │
//	└─────────────────────────────────────────────────────────────────┘
//
// # PublicMessage (§6.2) - Mensajes en Claro
//
//	struct {
//	    FramedContent content;           // Contenido enmarcado
//	    FramedContentAuthData auth;      // Firma + confirmation
//	    select (sender.sender_type) {    // Tag condicional
//	        case member:  MAC membership_tag;
//	        case external:
//	        case new_member_commit:
//	        case new_member_proposal:  struct{};
//	    };
//	} PublicMessage;
//
// Wire format: [wire_format][content][auth][membership_tag?]
//
// # PrivateMessage (§6.3) - Mensajes Cifrados
//
//	struct {
//	    opaque group_id<V>;              // EN CLARO
//	    uint64 epoch;                    // EN CLARO
//	    ContentType content_type;        // EN CLARO
//	    opaque authenticated_data<V>;    // EN CLARO
//	    opaque encrypted_sender_data<V>; // CIFRADO
//	    opaque ciphertext<V>;            // CIFRADO
//	} PrivateMessage;
//
// Wire format: [group_id][epoch][type][auth_data][enc_sd][ct]
//
//	←─── EN CLARO ───→←──── CIFRADO ────→
//
// # SenderData (§6.3.2) - Datos del Remitente Cifrados
//
//	struct {
//	    uint32 leaf_index;       // Índice de hoja
//	    uint32 generation;       // Número de secuencia
//	    opaque reuse_guard[4];   // Protección nonce reuse
//	} MLSSenderData;
//
// Se cifra con sender_data_secret para formar encrypted_sender_data
//
// # FramedContent (§6.1) - Contenido Enmarcado
//
//	struct {
//	    opaque group_id<V>;            // ID del grupo
//	    uint64 epoch;                  // Época actual
//	    Sender sender;                 // Remitente
//	    opaque authenticated_data<V>;  // Datos extra
//	    ContentType content_type;      // Tipo de contenido
//	    select (content_type) {
//	        case application:  opaque application_data<V>;
//	        case proposal:     Proposal proposal;
//	        case commit:       Commit commit;
//	    };
//	} FramedContent;
//
// # Flujo de Cifrado (§6.3.1)
//
//  1. Firmar FramedContent → AuthenticatedContent
//  2. Generar ReuseGuard aleatorio (4 bytes)
//  3. Derivar key/nonce del SecretTree
//     └─ XOR nonce[:4] con ReuseGuard
//  4. Construir MLSSenderData
//     └─ Cifrar con sender_data_secret
//  5. Construir AAD completo
//     [group_id][epoch][content_type][auth_data][enc_sender]
//  6. Cifrar AuthenticatedContent
//     └─ key/nonce del SecretTree + AAD
//  7. Retornar PrivateMessage
//     [group_id][epoch][type][auth_data][enc_sd][ciphertext]
//
// # Membership Tag (§6.2)
//
//	membership_tag = MAC(membership_key, AuthenticatedContentTBM)
//
//	donde:
//	  - membership_key: derivada del key schedule
//	  - TBM = "ToBeMAC'd": contenido serializado para MAC
//	  - Solo para sender_type == member
//
// # Confirmation Tag (§6.1)
//
//	confirmation_tag = MAC(confirmation_key, confirmed_transcript)
//
//	donde:
//	  - confirmation_key: derivada del key schedule
//	  - confirmed_transcript: hash del transcript confirmado
//	  - Solo para ContentType == commit
//
// # Ejemplo de Uso
//
//	// Crear FramedContent
//	content := framing.FramedContent{
//	    GroupID:           []byte("my-group"),
//	    Epoch:             1,
//	    Sender:            framing.Sender{Type: framing.SenderTypeMember, LeafIndex: 0},
//	    AuthenticatedData: []byte("optional-data"),
//	    Body:              framing.ApplicationData{Data: []byte("Hello, MLS!")},
//	}
//
//	// Crear PublicMessage (en claro, firmado)
//	pubMsg, err := framing.NewPublicMessage(content, sigKey, membershipKey)
//	if err != nil {
//	    return err
//	}
//
//	// Serializar para enviar
//	data := pubMsg.Marshal()
//
//	// O crear PrivateMessage (cifrado)
//	privMsg, err := framing.Encrypt(framing.EncryptParams{
//	    Content:          content,
//	    SenderLeafIndex:  0,
//	    Generation:       0,
//	    SenderDataSecret: senderDataSecret,
//	    SecretTree:       secretTree,
//	    SigKey:           sigKey,
//	})
//
// # RFC Compliance
//
// Este package implementa:
//   - RFC 9420 §6.1: FramedContent y AuthenticatedContent
//   - RFC 9420 §6.2: PublicMessage y membership_tag
//   - RFC 9420 §6.3: PrivateMessage y cifrado
//   - RFC 9420 §6.3.1: Content encryption con ReuseGuard
//   - RFC 9420 §6.3.2: SenderData encryption
//
// # Seguridad
//
//   - ReuseGuard previene nonce reuse (§6.3.1)
//   - membership_tag verifica membresía (§6.2)
//   - confirmation_tag verifica commits (§6.1)
//   - Firmas ECDSA-SHA256 autentican remitente
//
// # Referencias
//
//   - RFC 9420 §6: https://www.rfc-editor.org/rfc/rfc9420.html#section-6
//   - RFC 9420 §6.1: FramedContent
//   - RFC 9420 §6.2: PublicMessage
//   - RFC 9420 §6.3: PrivateMessage
package framing

// Este archivo está vacío pero el package doc arriba provee
// documentación completa. Las implementaciones están en:
//   - framed_content.go: FramedContent y FramedContentBody
//   - auth.go: FramedContentAuthData y AuthenticatedContent
//   - public_message.go: PublicMessage
//   - private_message.go: PrivateMessage, Encrypt, Decrypt
//   - types.go: ContentType, WireFormat, Sender, SenderType
//   - helpers.go: Funciones helper
//   - errors.go: Errores del package
