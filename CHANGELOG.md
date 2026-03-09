# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]


## [v0.1.0] - 2026-03-09

[v0.1.0]: https://github.com/thomas-vilte/mls-go/compare/v0.0.0...v0.1.0

Presentamos la primera versión funcional de mls-go, estableciendo las bases del protocolo Messaging Layer Security (RFC 9420). En este lanzamiento, nos enfocamos en proporcionar una arquitectura sólida para la gestión de grupos, mensajería segura y cumplimiento estricto de los estándares criptográficos internacionales.

### 🚀 Protocolo Core y Mensajería

- Implementamos el flujo completo de mensajes MLS, incluyendo los protocolos de Welcome y Commit.
- Agregamos un sistema de mensajería robusto con soporte para el encuadrado (framing) de datos de aplicación y componentes de core.
- Introducimos pruebas de integración exhaustivas para validar la funcionalidad de mensajería de extremo a extremo.

### 👥 Gestión de Grupos y Membresía

- Introducimos componentes avanzados para la gestión de grupos y el seguimiento de propuestas de miembros.
- Mejoramos la actualización de miembros y la gestión del árbol de ratchets para garantizar una sincronización precisa entre participantes.
- Agregamos soporte para el referenciamiento de propuestas y actualizaciones dinámicas del árbol de estado.

### 🔒 Seguridad y Criptografía

- Incorporamos soporte para la encapsulación de claves HPKE y validación robusta mediante certificados X.509 y mecanismos GREASE.
- Refactorizamos la combinación de claves pre-compartidas (PSK) y el uso de HKDF para alinearnos con los estándares modernos de seguridad.
- Añadimos capacidades de comparación y validación de extensiones para fortalecer la integridad del protocolo.

### 📜 Estándares y Compatibilidad

- Alineamos el esquema de generación de claves (key schedule) con la especificación final del RFC 9420.
- Implementamos el soporte completo para extensiones críticas como RatchetTree, LastResort y Application ID.
- Mejoramos el procesamiento de mensajes de bienvenida para asegurar el cumplimiento estricto del estándar MLS.

### 🛠️ Correcciones y Estabilidad

- Corregimos errores en la serialización de credenciales y mejoramos el acceso a los datos de aplicación dentro del framing.
- Solucionamos un problema en la aplicación de propuestas que afectaba la integridad de las hojas del remitente en el árbol.
- Optimizamos la inicialización de grupos y el procesamiento de mensajes Welcome para evitar estados inconsistentes.

### ⚠️ Breaking Changes

- Renombramos varios paquetes internos y actualizamos la serialización de mensajes para mejorar la estructura del proyecto.
- Adoptamos una representación de árbol entrelazado (interleaved tree) que modifica la forma en que se gestionan los nodos del grupo.

