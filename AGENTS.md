# Peak Auth - Sistema de Autenticación SSO & Proveedor de Identidad (IdP)

## Descripción General

**Peak Auth** es un proveedor de identidad (IdP) y autenticación Single Sign-On (SSO) empresarial desarrollado en **Go** que permite que múltiples aplicaciones se autentiquen de forma centralizada mediante el estándar **OAuth 2.0 con PKCE** y **JWT asimétrico (RSA-256)**. El sistema cuenta con autenticación multi-factor multi-modal (TOTP y WebAuthn/Passkeys), recuperación mediante recovery codes, roles contextuales por aplicación, reglas de autorización granulares, social login federado (Google & GitHub) y almacenamiento desacoplado de perfiles (Local y Cloudflare R2 / AWS S3).

### Características Principales

- ✅ **Autenticación centralizada (SSO)** mediante sesión compartida (`peak_session`)
- ✅ **OAuth 2.0 con PKCE (RFC 7636)**: Flujo `authorization_code` seguro con S256 para SPAs, apps móviles y web
- ✅ **OAuth 2.0 Client Credentials Grant (RFC 6749 §4.4)**: Autenticación Machine-to-Machine (M2M) para microservicios, daemons y APIs backend
- ✅ **Token Introspection (RFC 7662)**: Endpoint `/oauth/introspect` para gateways y validación de tokens
- ✅ **JWT Asimétrico (RSA-256)**: Firma con clave privada y verificación offline mediante clave pública o JWKS
- ✅ **MFA Multi-Modal**: TOTP (RFC 6238 con QR y secrets cifrados AES-GCM) + WebAuthn/Passkeys/FIDO2 + Códigos de Recuperación (bcrypt)
- ✅ **MFA Forzado por Política**: Regla `MFA_POLICY` (`NONE`, `OPTIONAL`, `REQUIRED`) por aplicación
- ✅ **Identity Brokering (Social Login)**: Integración con proveedores de identidad externos (Google y GitHub) con vinculación automática de cuentas (`UserIdentity`)
- ✅ **Gestión de roles y permisos** por aplicación (RBAC granular)
- ✅ **Gestión de sesiones activas y revocación remota**: Auditoría de dispositivos, cierre de sesión individual o masivo de otras sesiones
- ✅ **Almacenamiento de avatares desacoplado**: Soporte para disco local y Cloudflare R2 / AWS S3 S3-compatible sin egress fees
- ✅ **Contraseñas robustas** con hash criptográfico bcrypt y políticas personalizables
- ✅ **Interfaz administrativa moderna**: 100% **CSS Vanilla** con variables semánticas (`web/static/css/variables.css`), soporte Light/Dark y cero dependencias de Tailwind
- ✅ **Cumplimiento legal y normativo**: Páginas públicas y administrativas de Términos y condiciones (`/terms`) y Políticas de privacidad (`/privacy`)
- ✅ **Sistema multi-tenancy** (múltiples aplicaciones cliente con credenciales `client_id` y `client_secret`)
- ✅ **Verificación de email y recuperación de contraseña** vía Resend
- ✅ **Refresh tokens rotativos** almacenados con hash criptográfico SHA-256
- ✅ **Protección activa**: Rate limiting por IP, mitigación de timing attacks y CSRF double-submit cookies

---

## Arquitectura Técnica

### Stack Tecnológico

| Componente         | Tecnología                    | Versión   |
| ------------------ | ----------------------------- | --------- |
| **Lenguaje**       | Go                            | 1.27.0 (toolchain `go1.27.0`) |
| **Web Framework**  | Gin Web Framework             | v1.12.0   |
| **ORM**            | GORM                          | v1.31.2   |
| **Base de Datos**  | PostgreSQL (pgx driver)       | 16-alpine |
| **JWT**            | golang-jwt/jwt/v5             | v5.3.1    |
| **Criptografía**   | golang.org/x/crypto           | v0.55.0   |
| **MFA / FIDO2**    | go-webauthn/webauthn, otp     | v0.17.4   |
| **Email**          | Resend                        | v2.28.0   |
| **Almacenamiento** | AWS SDK Go v2 (S3 / R2), Local| v1.30+    |
| **Frontend**       | HTML5 + CSS Vanilla Semántico | Nativo    |
| **Env Management** | godotenv                      | v1.5.1    |

### Estructura de Directorios

```text
peak-auth/
├── main.go                       # Punto de entrada principal
├── routes.go                     # Definición y registro de rutas HTTP
├── go.mod                        # Dependencias del proyecto (Go 1.27.0 + toolchain)
├── Dockerfile                    # Configuración Docker multi-stage
├── jwt_private.pem               # Clave privada RSA para firmar JWTs
├── jwt_public.pem                # Clave pública RSA para verificar JWTs
│
├── internal/
│   ├── api/
│   │   ├── controller/           # Controladores HTTP (OAuth, User, Admin, Setup, MFA, Docs, Broker)
│   │   ├── middleware/           # Middlewares: Auth, Role, AppAuth, CSRF, RateLimit
│   │   ├── request/              # DTOs de entrada (request payloads)
│   │   └── response/             # DTOs de salida (response payloads)
│   │
│   ├── app/                      # Inicialización e inyección de dependencias
│   ├── audit/                    # Registro de auditoría y eventos de seguridad
│   ├── auth/                     # TokenManager: generación y validación RSA-256
│   ├── service/                  # Lógica de negocio (OAuth, User, App, MFA, Role, Rule, Broker)
│   ├── storage/                  # StorageService: adaptadores Local y Cloudflare R2 / AWS S3
│   ├── store/
│   │   ├── db/                   # Conexión y auto-migraciones GORM
│   │   ├── model/                # Modelos de base de datos
│   │   └── repo/                 # Repositorios de acceso a datos (DAL)
│   └── util/                     # Utilidades de seguridad, hashing, rendering y constantes
│
├── sdk/
│   ├── go/                       # SDK Go oficial (net/http y subpaquete gin/)
│   ├── kotlin/                   # SDK Kotlin / Android oficial (io.peakauth:peak-auth-kotlin)
│   └── typescript/               # SDK TypeScript/Node oficial (@brunotarditi/peak-auth)
│
└── web/
    ├── static/                   # Assets estáticos (CSS Vanilla, JS modular, imágenes)
    └── templates/                # Vistas HTML (Admin, OAuth, MFA, Emails, Legal)
```

---

## Flujos de Autenticación

### 1. **Flujo OAuth 2.0 con PKCE (Recomendado)**

```text
1. Cliente inicia flujo:
   GET /oauth/authorize?client_id=...&redirect_uri=...&response_type=code&code_challenge=...&state=...
2. Peak Auth verifica sesión SSO (peak_session):
   ├─ Si no existe sesión: muestra login público (/oauth/login)
   ├─ Valida credenciales + MFA (TOTP / WebAuthn)
   └─ Si MFA es requerido y no está configurado: redirige a /oauth/login/mfa/setup
3. Peak Auth genera Authorization Code y redirige:
   Location: https://tu-app.com/callback?code=...&state=...
4. Cliente intercambia código por token en backend:
   POST /oauth/token
   { client_id, client_secret, code, redirect_uri, code_verifier, grant_type: "authorization_code" }
5. Peak Auth responde con JWT asimétrico + Refresh token
```

### 2. **Login Directo por API (Headless / Móvil)**

```text
POST /api/v1/login (con header X-App-ID o body)
├─ Validar credenciales (email + password)
├─ Si tiene MFA o la app lo exige: retorna token temporal mfa_pending
├─ Desafío de segundo factor: POST /api/v1/login/mfa/totp o /webauthn/...
└─ Retornar access_token + refresh_token
```

### 3. **Flujo Client Credentials (M2M / Microservicios - RFC 6749 §4.4)**

```text
1. Microservicio o daemon solicita access token:
   POST /oauth/token
   Headers: Authorization: Basic <base64(client_id:client_secret)> (o body client_id + client_secret)
   Body: { grant_type: "client_credentials", scope: "service:read service:write" }
2. Peak Auth valida client_id y client_secret de la aplicación:
   ├─ Verifica existencia y estado activo de la aplicación
   └─ Verifica hash criptográfico del secreto
3. Peak Auth emite access token JWT asimétrico (RS256):
   {
     "access_token": "ey...",
     "token_type": "Bearer",
     "expires_in": 3600,
     "scope": "service:read service:write"
   }
   (Sin refresh token, conforme a RFC 6749 §4.4.3)
```

### 4. **Verificación de Token (en apps cliente)**

```text
Aplicación Cliente
├─ Recibe JWT emitido por Peak Auth
├─ Obtiene clave pública RSA (vía JWKS o archivo PEM)
├─ Verifica firma con clave pública (algoritmo RS256)
├─ Valida emisor (iss == "peak-auth") y audiencia (aud == client_id)
└─ Permite acceso si el token es válido
```

---

## Modelos de Base de Datos

### User (Usuario)

```go
type User struct {
    ID         uint
    Email      string
    Password   string
    FirstName  string
    LastName   string
    BirthDate  *time.Time
    AvatarURL  string
    IsActive   bool
    IsVerified bool
    MfaEnabled bool
    LastLogin  time.Time
    CreatedAt  time.Time
    UpdatedAt  time.Time
    DeletedAt  *time.Time
}
```

### UserIdentity (Social Login / Federation)

```go
type UserIdentity struct {
    ID         uint
    UserID     uint
    Provider   string // "google", "github"
    ProviderID string
    Email      string
    CreatedAt  time.Time
}
```

### MFA (Autenticación Multi-Factor)

```go
type UserMfaCredential struct {
    ID       uint
    UserID   uint
    Type     string // "TOTP" o "WEBAUTHN"
    Name     string
    Secret   string // Cifrado AES-GCM
    IsActive bool
}

type UserRecoveryCode struct {
    ID       uint
    UserID   uint
    CodeHash string // Hash bcrypt
    IsUsed   bool
}
```

### Application (Aplicación Registrada)

```go
type Application struct {
    ID            uint
    Name          string
    ClientID      string
    ClientSecret  string
    RedirectURI   string
    TermsURL      string
    PrivacyURL    string
    IsActive      bool
    OwnerID       *uint
    Owner         *User
}
```

### Role y Reglas

- **Role**: Define roles por aplicación (`OWNER`, `ADMIN`, `USER`, etc.).
  - A nivel plataforma: `ROOT` (1 usuario setup maestro del sistema).
  - A nivel aplicación: `OWNER` (1 propietario por app creada, con capacidad de transferir propiedad y gestión exclusiva de eliminación/secreto), acompañado de `ADMIN` y `USER`.
- **ApplicationRule**: Define políticas de acceso (`SESSION_POLICY`, `PASSWORD_POLICY`, `MFA_POLICY`, `REGISTRATION_POLICY`).

---

## Seguridad y Mejores Prácticas

✅ **JWT Asimétrico**: Solo Peak Auth puede firmar tokens con su clave privada.  
✅ **Verificación Estricta de Audiencia**: Cada token lleva `aud: [client_id]` para impedir que un token de una app sea reutilizado en otra.  
✅ **PKCE Obligatorio / Soportado**: Mitigación de interceptación de authorization codes.  
✅ **MFA Multi-Modal Completo**: TOTP + WebAuthn/Passkeys + Recovery codes.  
✅ **Gramática y UX Writing**: Textos, títulos, botones y modales deben redactarse en **Sentence Case** en español (mayúscula únicamente en la letra inicial de la frase o título, nunca Title Case anglosajón).  
✅ **Tailwind CSS Erradicado**: El frontend utiliza exclusivamente **CSS Vanilla** estructurado con variables semánticas en `web/static/css/variables.css`. **PROHIBIDO USAR CLASES DE TAILWIND**.  
✅ **Rotación de Refresh Tokens**: Tokens almacenados con hash SHA-256. Al renovarse, el token previo es destruido inmediatamente.  
✅ **Rotación Multi-Clave & Grace Period**: Tokens firmados con clave activa identificada por `kid`, resolución fail-closed, y exportación JWKS multi-key en `/.well-known/jwks.json`.  
✅ **OIDC Discovery**: Compatibilidad abierta con librerías estándar vía `/.well-known/openid-configuration` y JWKS con caching y CORS público.  
✅ **SDKs Oficiales Desacoplados**: Paquetes ultra-livianos (`@brunotarditi/peak-auth` en TS, `github.com/brunotarditi/peak-auth/sdk/go` en Go e `io.peakauth:peak-auth-kotlin` en Kotlin/Android) para verificación offline sin gestión manual de certificados ni dependencias innecesarias.  
✅ **Mitigación de Timing Attacks**: Endpoints de autenticación implementan dummy hash comparison para mantener tiempo constante frente a usuarios inexistentes.  
✅ **Rate Limiting In-Memory / Single-Instance**: Limitadores de tasa por IP en memoria (`sync.Mutex`) para mitigar fuerza bruta en endpoints de login, reset de password y token exchange en despliegues mono-instancia. Para despliegues horizontales multi-pod (Kubernetes/Cloud), se recomienda delegar el rate-limiting en el Ingress Controller (NGINX/Traefik) o CDN/WAF perimetral (Cloudflare, AWS WAF).  
✅ **Observabilidad y Health Probes**: Endpoints `/health` (Liveness) y `/ready` (Readiness con ping a PostgreSQL y comprobación de claves JWT) para orquestación e integración con balanceadores.  
✅ **Trazabilidad con Request ID**: Middleware de correlación que propaga `X-Request-ID` en respuestas HTTP y lo vincula al contexto de logs estructurados (`log/slog`).  
✅ **App Raíz Inmutable**: La app `peak-auth` (`util.AppIdPeakAuth`) es el tenant maestro del sistema; sus reglas maestras no pueden eliminarse.  
✅ **Páginas Legales Centralizadas**: `/terms` (Términos y condiciones) y `/privacy` (Políticas de privacidad) disponibles públicamente y vinculadas en el footer y flujos de autenticación.

---

## Licencia

MIT
