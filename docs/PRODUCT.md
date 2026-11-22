# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

- **Administradores de TI y desarrolladores**: Gestionan aplicaciones cliente (tenants), credenciales OAuth/M2M, políticas de acceso y seguridad (MFA, contraseñas, sesiones, registro), asignación de roles RBAC (ROOT, OWNER, ADMIN, USER) y auditoría de eventos de seguridad.
- **Usuarios finales**: Empleados o usuarios de las aplicaciones integradas que se autentican de forma centralizada mediante SSO (`peak_session`), completan desafíos de segundo factor (TOTP, WebAuthn/Passkeys, códigos de recuperación), vinculan proveedores federados (Google, GitHub) y gestionan sus sesiones activas y seguridad de perfil.

## Product Purpose

Proveer una solución empresarial de identidad centralizada y Single Sign-On (SSO) en Go basada rigurosamente en estándares abiertos (OAuth 2.0 con PKCE, M2M Client Credentials, JWT RS256 con JWKS y OIDC Discovery). El éxito significa que las aplicaciones integradas delegan su autenticación y autorización de forma confiable, sin fricción para los usuarios y con control granular total para los administradores.

## Positioning

Un proveedor de identidad (IdP) autónomo (self-hostable), liviano y de alto rendimiento en Go, sin sobrecargas de abstracción empresarial obsoletas, con soporte nativo de MFA multimodal (TOTP y Passkeys/FIDO2), rotación criptográfica multi-clave con JWKS, SDKs oficiales desacoplados y una interfaz web construida 100% en CSS Vanilla semántico sin dependencias de Tailwind CSS.

## Operating Context

- Microservicios, APIs y aplicaciones web/móviles integradas en arquitecturas modernas.
- Navegadores web de escritorio y móviles para flujos de login SSO, consentimientos y panel administrativo.
- Gateways, proxies y terminales consumiendo endpoints OAuth (`/oauth/token`, `/oauth/introspect`, `/.well-known/jwks.json`, `/.well-known/openid-configuration`).
- Infraestructura desplegable con base de datos PostgreSQL y almacenamiento de avatares desacoplado (disco local o S3/Cloudflare R2 sin costos de transferencia).

## Capabilities and Constraints

- **Capacidades**:
  - SSO con sesión compartida (`peak_session`).
  - OAuth 2.0 PKCE (RFC 7636) y Client Credentials (RFC 6749 §4.4).
  - JWT asimétrico RS256 con clave privada y verificación pública / JWKS.
  - MFA multimodal completo: TOTP (RFC 6238 con cifrado AES-GCM), WebAuthn/Passkeys y códigos de recuperación con hash bcrypt.
  - Políticas de seguridad por aplicación (`MFA_POLICY`, `PASSWORD_POLICY`, `SESSION_POLICY`, `REGISTRATION_POLICY`).
  - RBAC contextual granular por aplicación.
  - Auditoría de eventos y revocación remota de sesiones activas.
  - Identity brokering (Google y GitHub).
  - Almacenamiento desacoplado de avatares y branding de aplicación.
  - Páginas legales integradas (`/terms` y `/privacy`).
- **Restricciones técnicas**:
  - Backend en Go 1.27 + Gin + GORM + PostgreSQL.
  - Frontend exclusivamente con **CSS Vanilla** estructurado con variables semánticas (`web/static/css/variables.css`). Prohibido terminantemente el uso de clases de Tailwind CSS.
  - Redacción y UX writing: Español en **Sentence Case** (mayúscula solo en la letra inicial de cada frase o título, nunca Title Case).
  - Criptografía: Tokens firmados con clave RSA privada; passwords con bcrypt; refresh tokens rotativos con SHA-256; secretos TOTP cifrados con AES-GCM.
  - Tenant maestro inmutable: La app `peak-auth` (`util.AppIdPeakAuth`) es inmutable y sus reglas maestras no pueden eliminarse.

## Brand Commitments

- **Nombre**: Peak Auth.
- **Identidad visual**: Moderna, técnica, sobria y de alta confiabilidad. Soporte nativo para temas claro y oscuro mediante tokens CSS semánticos.
- **Assets**: Logo vectorial SVG (`web/static/img/logo.svg`) y favicon (`web/static/img/favicon.png`).

## Evidence on Hand

- Código fuente completo en Go para servidor y endpoints.
- Plantillas Go HTML existentes en `web/templates/` (`admin/`, `oauth/`, `components/`, `emails/`, `layouts/`, `partials/`).
- Sistema de estilos CSS Vanilla en `web/static/css/` (`variables.css`, `layout.css`, `components.css`, `modal.css`, `main.css`, `setup.css`).
- SDKs oficiales implementados en `sdk/go`, `sdk/typescript` y `sdk/kotlin`.

## Product Principles

1. **Seguridad rigurosa por diseño**: Cumplimiento estricto de especificaciones RFC sin compromisos criptográficos ni atajos en validación de identidad.
2. **Cero dependencias innecesarias en UI**: Interfaz 100% Vanilla CSS con tokens semánticos claros; mantenible, ligera y sin frameworks externos de utilidades.
3. **Consistencia gramatical y claridad**: Copy en español directo y conciso con formato Sentence Case consistente en botones, títulos y mensajes de error.
4. **Operabilidad sin sobrecarga**: Arquitectura de información en paneles administrativos orientada a minimizar el esfuerzo cognitivo en la configuración de políticas complejas.

## Accessibility & Inclusion

- Cumplimiento de WCAG 2.1 AA en ratios de contraste para temas claro y oscuro.
- Soporte completo para navegación por teclado en modales, desplegables y formularios.
- Mensajes de estado y validación visualmente perceptibles y accesibles para lectores de pantalla.
