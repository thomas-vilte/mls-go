# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]


## [v0.2.0] - 2026-03-09

[v0.2.0]: https://github.com/thomas-vilte/mls-go/compare/v0.1.0...v0.2.0

En esta versión, nos enfocamos en alcanzar la plena conformidad con el estándar RFC 9420 (Messaging Layer Security). Implementamos operaciones críticas de árbol, mejoramos la interoperabilidad con vectores de prueba oficiales y refinamos la gestión de claves para garantizar una seguridad robusta en las comunicaciones grupales.

### 🔐 Protocolo y Estándares RFC 9420

- Alineamos los componentes DHKEM, KeySchedule y PSK con los estándares RFC 9180 y RFC 9420 para asegurar una compatibilidad total.
- Integramos funciones hash dinámicas que dependen del ciphersuite seleccionado para una mayor flexibilidad criptográfica.
- Implementamos el etiquetado de firmas y el filtrado de propuestas siguiendo estrictamente las especificaciones del protocolo.

### 🌳 Operaciones de Árbol y Seguridad

- Añadimos soporte completo para operaciones de árbol, incluyendo hashing de nodos y gestión eficiente de miembros.
- Implementamos ratchets de árbol de secretos para fortalecer la derivación de claves dentro del grupo.
- Mejoramos la sincronización del árbol y la validación de datos para mantener la integridad de la estructura jerárquica.

### 📦 Mensajería y Serialización

- Habilitamos el procesamiento y la verificación de mensajes públicos, garantizando la autenticidad de la comunicación.
- Refactorizamos el sistema de unmarshaling para extensiones y credenciales, optimizando la lectura de datos desde diversos orígenes.
- Unificamos el manejo de etiquetas de membresía en el framing para simplificar la estructura de los mensajes.

### 🔄 Gestión de Grupos

- Agregamos la capacidad de re-inicializar grupos a partir de una ReInitProposal, facilitando la actualización de parámetros del grupo.
- Mejoramos la gestión de LeafNode y KeyPackage para alinearlos con el orden de campos requerido por el estándar.

### 🧪 Interoperabilidad y Estabilidad

- Incorporamos una suite extensa de tests de interoperabilidad y vectores de prueba para validar la compatibilidad con implementaciones como OpenMLS.
- Corregimos errores críticos en la derivación de claves privadas y en la serialización de datos.
- Aseguramos la generación de claves privadas válidas durante los procesos de derivación.

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

