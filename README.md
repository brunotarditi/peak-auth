# 🏔️ Peak Auth - Sistema de Autenticación SSO & Proveedor de Identidad (IdP)

![Go Version](https://img.shields.io/badge/go-1.27.0-blue.svg)
![Gin Framework](https://img.shields.io/badge/gin-v1.12.0-blue.svg)
![PostgreSQL](https://img.shields.io/badge/postgresql-16--alpine-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Security](https://img.shields.io/badge/security-hardened-success.svg)

**Peak Auth** es un proveedor de identidad (IdP) y servidor de autenticación Single Sign-On (SSO) empresarial desarrollado en **Go**. Permite que múltiples aplicaciones web, móviles y microservicios se autentiquen de forma centralizada mediante el estándar **OAuth 2.0 con PKCE** y **JWT asimétricos (RSA-256)**, con verificación offline ultrarrápida vía JWKS y seguridad integral respaldada por **MFA multi-modal (TOTP + WebAuthn/Passkeys)**.

---

## ✨ Características Principales

- 🔐 **Autenticación Centralizada (SSO)**: Inicio de sesión único con cookie de sesión segura (`peak_session`) compartida entre tus aplicaciones cliente.
- ⚡ **OAuth 2.0 + PKCE (RFC 7636)**: Flujo de autorización estándar (`authorization_code`) con soporte estricto para Proof Key for Code Exchange (S256), protegiendo SPAs, apps móviles y clientes web contra intercepción de códigos.
- 🔑 **JWT Asimétricos (RSA-256) & OIDC Discovery**: 
  - Firma con clave privada RSA en el servidor y verificación offline con clave pública en clientes.
  - Endpoint de descubrimiento estándar `GET /.well-known/openid-configuration`.
  - Endpoint público de claves `GET /.well-known/jwks.json` con cache y CORS habilitado.
  - Validación estricta de audiencia (`aud`) para impedir que un token emitido para una app sea reutilizado en otra.
- 🛡️ **MFA Multi-Factor Multi-Modal**:
  - **TOTP (RFC 6238)**: Compatible con Google Authenticator, Authy, 1Password, etc. Códigos QR generados al vuelo y secretos cifrados en reposo con **AES-GCM**.
  - **WebAuthn / Passkeys / FIDO2**: Autenticación biométrica nativa (TouchID, FaceID, Windows Hello) y llaves de seguridad físicas (YubiKey). Errores centinela tipados que aíslan la validación de ceremonias.
  - **Recovery Codes**: Códigos de recuperación de respaldo de un solo uso protegidos con hash criptográfico `bcrypt`.
  - **MFA Enforcement por Aplicación**: Políticas configurables (`MFA_POLICY`: `NONE`, `OPTIONAL`, `REQUIRED`) que fuerzan al usuario a enrolarse en MFA durante el login si la app lo exige.
- 👥 **Control de Acceso Basado en Roles (RBAC) & Reglas por App**:
  - Roles contextuales por aplicación (`ADMIN`, `USER` o roles personalizados).
  - Políticas de seguridad granulares por aplicación:
    - `MFA_POLICY`: Nivel de obligatoriedad de MFA.
    - `PWD_POLICY`: Longitud mínima, mayúsculas, números y caracteres especiales.
    - `SESSION_POLICY`: Duración y expiración de tokens/sesiones.
    - `REGISTRATION_POLICY`: Habilitación o restricción del auto-registro de usuarios.
  - **App Raíz Inmutable**: El tenant maestro `peak-auth` (`util.AppIdPeakAuth`) está blindado contra eliminación accidental.
- 🏢 **Multi-Tenancy Real**: Gestión centralizada de múltiples aplicaciones cliente con credenciales independientes (`client_id` y `client_secret`).
- 🔄 **Refresh Tokens Rotativos**: Sesiones persistentes con rotación automática de refresh tokens; tokens previos son destruidos de inmediato y almacenados con hash criptográfico SHA-256.
- 🔄 **Rotación Multi-Clave & Período de Gracia (Grace Period)**: Compatibilidad multi-key fail-closed identificada por `kid`, permitiendo rotar claves RSA sin invalidar tokens activos.
- 📧 **Servicio de Correo Electrónico**: Verificación de cuentas de correo y recuperación de contraseñas mediante **Resend** (con fallback a proveedor en consola para desarrollo).
- 🛡️ **Seguridad Defensiva y Protección Activa**:
  - **Mitigación de Timing Attacks**: Hashes de relleno (dummy bcrypt) para mantener tiempo de respuesta constante ante usuarios inexistentes.
  - **Protección CSRF**: Tokens de doble submit cookie en formularios administrativos y flujos interactivos.
  - **Rate Limiting por IP**: Limitadores de tasa en memoria para endpoints sensibles (login, MFA, reset de contraseña, mutación de reglas).
  - **Sanitización de Errores**: Handlers con captura controlada (`internalErrorJSON`) que registran fallos en el servidor y responden mensajes genéricos, previniendo fuga de esquemas SQL o infraestructura.
  - **Prevención de Replay**: Consumo atómico de tokens temporales de MFA (`ConsumeApiMfaToken`).
  - **Límites de Memoria**: Decodificación acotada de payloads JSON respetando `MaxBytesReader`.
- 🎨 **Frontend 100% CSS Vanilla Semántico**: Interfaz moderna, responsiva, con temas Light/Dark nativos mediante tokens en `web/static/css/variables.css`. Cero dependencias de Tailwind CSS ni procesos pesados de compilación.

---

## 🛠️ Stack Tecnológico

| Componente | Tecnología | Versión |
| :--- | :--- | :--- |
| **Lenguaje** | Go | **1.27.0** (toolchain `go1.27.0`) |
| **Web Framework** | Gin Web Framework | `v1.12.0` |
| **ORM** | GORM | `v1.31.2` |
| **Base de Datos** | PostgreSQL (Driver pgx) | `16-alpine` |
| **JWT** | `golang-jwt/jwt/v5` (RSA-256) | `v5.3.1` |
| **Criptografía / MFA** | `go-webauthn/webauthn`, `pquerna/otp`, `golang.org/x/crypto` | Última |
| **Email Service** | Resend Go SDK | `v2.28.0` |
| **Frontend UI** | HTML5 + CSS Vanilla Semántico (Light/Dark) | Nativo |
| **Contenedor** | Docker Multi-Stage (Google Distroless nonroot) | Debian 12 |

---

## 🏗️ Arquitectura del Proyecto

El proyecto sigue una estructura limpia y desacoplada acorde a los estándares idiomáticos de Go:

```text
peak-auth/
├── main.go                       # Punto de entrada, configuración y arranque HTTP/TLS
├── routes.go                     # Definición y registro de rutas, middlewares y rate limits
├── go.mod                        # Módulo Go y dependencias
├── Dockerfile                    # Multi-stage build optimizado (Distroless nonroot)
├── jwt_private.pem               # Clave privada RSA (solo firma en Peak Auth)
├── jwt_public.pem                # Clave pública RSA (verificación en clientes)
│
├── internal/
│   ├── api/
│   │   ├── controller/           # Controladores HTTP (OAuth, Admin, Login, MFA, Setup, Discovery)
│   │   ├── middleware/           # Middlewares: Auth JWT, AppAuth, Role RBAC, CSRF, RateLimit
│   │   ├── request/              # DTOs y validación de entrada
│   │   └── response/             # DTOs estructurados de salida
│   ├── app/                      # Inicialización e inyección de dependencias
│   ├── audit/                    # Registro de auditoría y eventos de seguridad
│   ├── auth/                     # TokenManager (Firma RSA, Claims, JWKS, Validación)
│   ├── service/                  # Lógica de negocio (OAuth, User, MFA, WebAuthn, App, Rule, Role)
│   ├── store/
│   │   ├── db/                   # Conexión PostgreSQL y auto-migración GORM
│   │   ├── model/                # Modelos y entidades de base de datos
│   │   └── repo/                 # Repositorios de acceso a datos (DAL)
│   └── util/                     # Criptografía AES-GCM, hashing bcrypt/SHA-256 y constantes
│
├── sdk/
│   ├── go/                       # SDK Go oficial (net/http y subpaquete gin/)
│   └── typescript/               # SDK TypeScript/Node oficial (@brunotarditi/peak-auth)
│
└── web/
    ├── static/                   # Assets estáticos (CSS Vanilla, JS modular, imágenes)
    │   └── css/variables.css     # Tokens de diseño y soporte Dark/Light mode
    └── templates/                # Vistas HTML Gin (Admin, OAuth, MFA, Emails)
```

---

## 🚀 Instalación y Puesta en Marcha

### Requisitos Previos

- **Go 1.27.0+**
- **PostgreSQL 16+**
- **OpenSSL** (para la generación de claves RSA y clave AES de MFA)

---

### 1. Clonar el repositorio

```bash
git clone https://github.com/brunotarditi/peak-auth.git
cd peak-auth
```

---

### 2. Generar pares de claves criptográficas

#### A. Par de claves RSA para JWT (2048 bits)
```bash
openssl genpkey -algorithm RSA -out jwt_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem
```

> ⚠️ **Seguridad**: `jwt_private.pem` jamás debe exponerse ni compartirse con las aplicaciones cliente. Solo Peak Auth la requiere para firmar tokens.

#### B. Clave de cifrado AES-256 para secretos MFA
Genera una clave aleatoria de 32 bytes en formato Base64:
```bash
openssl rand -base64 32
```
Copia el resultado para la variable `MFA_ENCRYPTION_KEY`.

---

### 3. Configurar variables de entorno

Copia el archivo de ejemplo:
```bash
cp .env.example .env
```

Edita `.env` con los valores correspondientes:

```env
# === Base de datos PostgreSQL ===
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=tu_password
DB_NAME=peak_auth
DB_SSLMODE=disable              # disable en dev | require en prod

# === Servidor y URLs ===
ENV=development                 # development | production (habilita cookies Secure y HTTPS)
PORT=8080                       # Puerto de escucha del servidor
APP_BASE_URL=http://localhost:8080 # URL pública base de Peak Auth
FRONTEND_URL=http://localhost:3000 # Orígenes permitidos CORS para la API

# === Criptografía MFA (Obligatorio) ===
MFA_ENCRYPTION_KEY=tu_clave_base64_de_32_bytes_generada_con_openssl

# === Claves JWT Asimétricas ===
# Puedes usar los archivos locales (jwt_private.pem / jwt_public.pem)
# o inyectar el contenido PEM directamente:
# JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
JWT_ISSUER=peak-auth
JWT_KEY_ID=peak-auth-key-1

# === Proveedor de Correo ===
EMAIL_PROVIDER=CONSOLE          # CONSOLE para pruebas locales | RESEND para producción
RESEND_API_KEY=re_tu_api_key    # Requerido si EMAIL_PROVIDER=RESEND
EMAIL_FROM=Peak Auth <no-reply@tudominio.com>

# === Setup Inicial (Opcional) ===
# SETUP_TOKEN=token_secreto_personalizado # Si se omite, se genera uno aleatorio en consola
```

---

### 4. Ejecutar el servidor

```bash
go mod download
go run main.go
```

Al iniciar por primera vez:
1. GORM ejecutará automáticamente las migraciones necesarias en PostgreSQL.
2. Si no definiste `SETUP_TOKEN` en `.env`, el servidor imprimirá un token efímero en la consola.
3. Abre en tu navegador `http://localhost:8080/setup` e ingresa el token para crear el usuario **Administrador Inicial**.

---

## 🔐 Flujos de Autenticación

### 1. Flujo OAuth 2.0 Authorization Code con PKCE

Recomendado para SPAs (React, Next.js, Vue), aplicaciones móviles y backends.

```text
Usuario                     App Cliente                   Peak Auth (IdP)
   │                             │                              │
   │─── 1. Iniciar sesión ──────>│                              │
   │                             │─── 2. Redirigir con PKCE ───>│ (GET /oauth/authorize)
   │                             │    (?client_id, redirect_uri,│
   │                             │     code_challenge, state)   │
   │                             │                              │
   │<───────────── 3. Desafío de credenciales y MFA ───────────>│
   │               (Contraseña + TOTP / WebAuthn / Passkey)     │
   │                                                            │
   │<───────────── 4. Redirección con código ───────────────────│
   │               (redirect_uri?code=XYZ&state=ABC)            │
   │                             │                              │
   │─── 5. Entrega código ──────>│                              │
   │                             │─── 6. Canje de Código ──────>│ (POST /oauth/token)
   │                             │    (code, code_verifier,     │
   │                             │     client_id, client_secret)│
   │                             │                              │
   │                             │<── 7. Retorna JWT Asimétrico │
   │<── 8. Sesión iniciada ──────│
```

#### Paso A: Redirección al Autorizador
```text
GET /oauth/authorize?client_id=TU_CLIENT_ID&redirect_uri=https://tu-app.com/callback&response_type=code&state=xyz123&code_challenge=HASH_S256_VERIFIER&code_challenge_method=S256
```

#### Paso B: Canjear Código por Token en Backend
```bash
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&client_id=TU_CLIENT_ID
&client_secret=TU_CLIENT_SECRET
&code=CODIGO_RECIBIDO
&redirect_uri=https://tu-app.com/callback
&code_verifier=VERIFICADOR_ORIGINAL_PKCE
```

**Respuesta:**
```json
{
  "access_token": "<token_jwt_firmado>",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

---

### 2. Endpoints Estándar OIDC Discovery & JWKS

Cualquier librería OAuth/OIDC estándar (o los SDKs oficiales) puede autoconfigurarse mediante:

- **OIDC Discovery**: `GET /.well-known/openid-configuration`
- **Claves Públicas JWKS**: `GET /.well-known/jwks.json`

---

## 🔌 Integración con SDKs Oficiales

Peak Auth provee paquetes oficiales ultra-livianos con cero dependencias innecesarias para validar tokens de forma offline mediante JWKS con caché en memoria:

| Plataforma | Paquete / Módulo | Características |
| :--- | :--- | :--- |
| **Go / Gin / net/http** | [`github.com/brunotarditi/peak-auth/sdk/go`](sdk/go/README.md) | Cache JWKS thread-safe, generador PKCE, middlewares para `net/http` y subpaquete `gin/`. |
| **TypeScript / Node.js** | [`@brunotarditi/peak-auth`](sdk/typescript/README.md) | Basado en `jose` (sin binarios C++), generador PKCE nativo, middlewares para Express y Next.js. |

### Ejemplo en Go (con subpaquete Gin)

```go
package main

import (
    "github.com/gin-gonic/gin"
    peakauth "github.com/brunotarditi/peak-auth/sdk/go"
    peakauthgin "github.com/brunotarditi/peak-auth/sdk/go/gin"
)

func main() {
    client, _ := peakauth.New(peakauth.Config{
        IssuerURL: "https://auth.tuempresa.com",
        ClientID:  "mi-aplicacion",
    })

    r := gin.Default()
    r.GET("/api/protegido", peakauthgin.Middleware(client), func(c *gin.Context) {
        claims, _ := peakauthgin.ClaimsFromContext(c)
        c.JSON(200, gin.H{
            "user_id": claims.Subject,
            "roles":   claims.Roles,
        })
    })
    r.Run(":3000")
}
```

### Ejemplo en TypeScript (Express)

```typescript
import express from 'express';
import { PeakAuthClient } from '@brunotarditi/peak-auth';
import { peakAuthMiddleware } from '@brunotarditi/peak-auth/express';

const app = express();
const client = new PeakAuthClient({
  issuerUrl: 'https://auth.tuempresa.com',
  clientId: 'mi-aplicacion',
});

app.get('/api/protegido', peakAuthMiddleware(client), (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000);
```

---

## 🔄 Rotación Multi-Clave con Período de Gracia

Peak Auth soporta rotación de claves criptográficas en caliente sin desconectar a los usuarios ni interrumpir el servicio:

1. **Firma Activa**: Se firma con la clave especificada en `JWT_PRIVATE_KEY` y su identificador `JWT_KEY_ID`.
2. **JWKS Multi-Key**: `GET /.well-known/jwks.json` expone la clave activa y las claves históricas registradas en `JWT_PREVIOUS_KEYS`.
3. **Período de Gracia (`JWT_PREVIOUS_KEYS`)**: Permite conservar claves públicas previas mediante un JSON con formato:
   ```env
   JWT_KEY_ID="peak-auth-key-2"
   JWT_PREVIOUS_KEYS='[{"kid":"peak-auth-key-1","public_key":"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"}]'
   ```
4. **Flujo de Rotación**:
   - Generar el nuevo par de claves RSA.
   - Configurar la nueva clave como activa y pasar la anterior a `JWT_PREVIOUS_KEYS`.
   - Una vez transcurrido el TTL de los tokens de acceso antiguos (ej. 24h), retirar la clave anterior. Los clientes y SDKs actualizarán automáticamente su caché.

---

## 🐳 Despliegue con Docker

Peak Auth incluye un `Dockerfile` multi-stage ligero y seguro basado en **Google Distroless (`gcr.io/distroless/static-debian12:nonroot`)**: sin shell, sin paquetes innecesarios y ejecutándose con un usuario sin privilegios.

```bash
# Construir imagen
docker build -t peak-auth .

# Ejecutar contenedor
docker run -d -p 8080:8080 \
  --name peak-auth \
  -e DB_HOST="postgres-host" \
  -e DB_PORT="5432" \
  -e DB_USER="postgres" \
  -e DB_PASSWORD="tu_password" \
  -e DB_NAME="peak_auth" \
  -e DB_SSLMODE="disable" \
  -e MFA_ENCRYPTION_KEY="tu_clave_base64_de_32_bytes" \
  -e JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----" \
  -e JWT_ISSUER="peak-auth" \
  -e EMAIL_PROVIDER="RESEND" \
  -e RESEND_API_KEY="re_tu_resend_api_key" \
  peak-auth
```

---

## 🧪 Pruebas Automatizadas

El proyecto cuenta con una amplia suite de pruebas unitarias y de integración:

```bash
# Ejecutar todas las pruebas sin caché
go test -count=1 ./...

# Compilar binario de producción
go build -v .
```

---

## 📄 Licencia

Este proyecto se distribuye bajo los términos de la licencia **MIT**. Consulta el archivo [LICENSE](LICENSE) para más detalles.
