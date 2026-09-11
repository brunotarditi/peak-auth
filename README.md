# 🏔️ Peak Auth - Sistema de Autenticación SSO & Proveedor de Identidad (IdP)

![Go Version](https://img.shields.io/badge/go-1.27.0-blue.svg)
![Gin Framework](https://img.shields.io/badge/gin-v1.12.0-blue.svg)
![PostgreSQL](https://img.shields.io/badge/postgresql-16--alpine-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**Peak Auth** es un proveedor de identidad (IdP) y servidor de autenticación Single Sign-On (SSO) diseñado en **Go**. Permite que múltiples aplicaciones web, móviles y APIs se autentiquen de forma centralizada mediante el estándar **OAuth 2.0 con PKCE** y **JWT asimétricos (RSA-256)**, garantizando máxima seguridad con **MFA multi-modal (TOTP + WebAuthn/Passkeys)** y verificación offline de tokens vía JWKS.

---

## ✨ Características Principales

- 🔐 **Autenticación Centralizada (SSO)**: Inicio de sesión único con cookie de sesión segura (`peak_session`) compartida entre tus aplicaciones cliente.
- ⚡ **OAuth 2.0 + PKCE**: Flujo de autorización estándar (`authorization_code`) con soporte para Proof Key for Code Exchange (S256), protegiendo clientes públicos y SPAs contra intercepción de códigos.
- 🔑 **JWT Asimétricos (RSA-256) & OIDC Discovery**: Tokens firmados con clave privada RSA. Las aplicaciones cliente validan la firma de forma offline con la clave pública o mediante `GET /.well-known/jwks.json`, con validación estricta de audiencia (`aud`).
- 🛡️ **MFA Multi-Factor Robusto**:
  - **TOTP (RFC 6238)**: Códigos temporales compatibles con Google Authenticator, Authy, etc., con códigos QR y secretos cifrados en reposo (AES-GCM).
  - **WebAuthn / Passkeys / FIDO2**: Autenticación biométrica nativa (TouchID, FaceID, Windows Hello) y llaves de seguridad físicas (YubiKey).
  - **Recovery Codes**: Códigos de respaldo de un solo uso protegidos con hash `bcrypt`.
  - **MFA Enforcement por Aplicación**: Políticas configurables (`MFA_POLICY`: `NONE`, `OPTIONAL`, `REQUIRED`) que fuerzan el enrolamiento automático durante el login.
- 👥 **Control de Acceso Basado en Roles (RBAC) & Reglas**:
  - Roles específicos y contextuales por aplicación (`ADMIN`, `USER`, o roles personalizados).
  - Reglas granulares de autorización y políticas de complejidad de contraseñas por app.
- 🏢 **Multi-Tenancy**: Gestión centralizada de múltiples aplicaciones cliente con credenciales independientes (`client_id` y `client_secret`).
- 🔄 **Tokens de Renovación (Refresh Tokens)**: Sesiones persistentes con rotación automática de refresh tokens almacenados con hash criptográfico SHA-256.
- 📧 **Flujo de Correo Electrónico**: Verificación de emails y recuperación de contraseñas mediante **Resend**.
- 🛡️ **Seguridad Integral**:
  - Mitigación de timing attacks en endpoints de autenticación (dummy hashes).
  - Protección estricta contra CSRF (double-submit cookies) en formularios administrativos y flujos públicos.
  - Limitadores de tasa (Rate Limiting) en memoria por IP para mitigar ataques de fuerza bruta.
  - Headers de seguridad HTTP completos (HSTS, CSP, X-Frame-Options, etc.).
- 🎨 **Interfaz Administrativa Moderna sin Runtime**: 100% **CSS Vanilla** con variables semánticas (`web/static/css/variables.css`), soporte para temas Light/Dark y cero dependencias de compilación CSS (Tailwind erradicado).

---

## 🛠️ Stack Tecnológico

| Componente | Tecnología | Versión |
| :--- | :--- | :--- |
| **Lenguaje** | Go | **1.27.0** (toolchain `go1.27.0`) |
| **Web Framework** | Gin Web Framework | `v1.12.0` |
| **ORM** | GORM | `v1.31.2` |
| **Base de Datos** | PostgreSQL (Driver pgx) | `16-alpine` |
| **Criptografía / MFA** | `go-webauthn/webauthn`, `pquerna/otp`, `golang.org/x/crypto` | Última |
| **JWT** | `golang-jwt/jwt/v5` (RSA-256) | `v5.3.1` |
| **Email Service** | Resend Go SDK | `v2.28.0` |
| **Frontend UI** | HTML5 + CSS Vanilla (Variables Semánticas) | Nativo |

---

## 🏗️ Arquitectura del Proyecto

El código fuente sigue el estándar de diseño idiomático de Go (`internal/` para encapsulamiento y modularidad):

```text
peak-auth/
├── main.go                       # Punto de arranque y carga de configuración
├── routes.go                     # Registro y despacho de rutas HTTP
├── go.mod                        # Módulo Go (go 1.27.0 + toolchain)
├── Dockerfile                    # Multi-stage build optimizado (Alpine)
├── jwt_private.pem               # Clave privada RSA (solo firma en Peak Auth)
├── jwt_public.pem                # Clave pública RSA (para verificación de clientes)
│
├── internal/
│   ├── api/
│   │   ├── controller/           # Handlers HTTP (OAuth, Admin, Login, MFA, Setup)
│   │   ├── middleware/           # Auth JWT, AppAuth, Role RBAC, CSRF, RateLimit
│   │   ├── request/              # DTOs de validación de entrada
│   │   └── response/             # DTOs estructurados de salida
│   ├── app/                      # Inyección de dependencias e inicialización
│   ├── audit/                    # Registro de eventos y auditoría de seguridad
│   ├── auth/                     # TokenManager JWT (Firma RSA, Claims, Tokens MFA, JWKS)
│   ├── service/                  # Lógica de negocio (OAuth, User, MFA, App, Rule)
│   ├── store/
│   │   ├── db/                   # Inicialización y auto-migración GORM
│   │   ├── model/                # Entidades persistentes de base de datos
│   │   └── repo/                 # Capa de abstracción y acceso a datos (DAL)
│   └── util/                     # Utilidades criptográficas, hashing y parsing
│
└── web/
    ├── static/                   # Assets estáticos (CSS vanilla, JS modular, imágenes)
    │   └── css/variables.css     # Tokens de diseño y soporte Dark/Light mode
    └── templates/                # Plantillas HTML Gin (OAuth, Admin, MFA, Emails)
```

---

## 🚀 Instalación y Desarrollo Local

### Requisitos Previos

- **Go 1.27.0+**
- **PostgreSQL 16+**
- **OpenSSL** (para la generación de claves RSA asimétricas)

### 1. Clonar el repositorio

```bash
git clone https://github.com/brunotarditi/peak-auth.git
cd peak-auth
```

### 2. Configurar variables de entorno

Copia el archivo de ejemplo y completa los valores requeridos:

```bash
cp .env.example .env
```

Parámetros fundamentales en `.env`:

```env
# Base de Datos
DATABASE_URL=postgres://usuario:tu_password@localhost:5432/peak_auth?sslmode=disable
DB_HOST=localhost
DB_PORT=5432
DB_USER=usuario
DB_PASSWORD=tu_password
DB_NAME=peak_auth
DB_SSL_MODE=disable

# Servidor
PORT=8080
ENV=development                  # development | production (habilita cookies Secure)
FRONTEND_URL=http://localhost:3000
ADMIN_URL=http://localhost:8080

# JWT Asimétrico (Contenido PEM en variable de entorno con saltos de línea \n)
JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
JWT_ISSUER=peak-auth

# Proveedor de Email
RESEND_API_KEY=re_tu_api_key_aqui
```

### 3. Generar el par de claves RSA para JWT

```bash
openssl genpkey -algorithm RSA -out jwt_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem
```

> ⚠️ **Importante**: La clave privada (`jwt_private.pem`) jamás debe compartirse ni exponerse. Solo Peak Auth la requiere para firmar tokens.

### 4. Ejecutar el servidor

```bash
go mod download
go run main.go
```

En el primer arranque, dirígete a `http://localhost:8080/setup` para configurar la cuenta del Administrador Inicial (Root).

---

## 🔐 Flujos de Autenticación

### 1. Flujo OAuth 2.0 Authorization Code con PKCE

Es el mecanismo recomendado para aplicaciones web (Next.js, React, Vue), móviles y backends.

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
   │                             │─── 6. Intercambio S2S ──────>│ (POST /oauth/token)
   │                             │    (code, code_verifier,     │
   │                             │     client_id, client_secret)│
   │                             │                              │
   │                             │<── 7. Retorna JWT + Refresh ─│
   │<── 8. Sesión iniciada ──────│
```

#### Paso A: Redirección al Autorizador
Tu frontend o backend redirige al usuario a:

```text
GET /oauth/authorize?client_id=TU_CLIENT_ID&redirect_uri=https://tu-app.com/callback&response_type=code&state=xyz123_aleatorio&code_challenge=HASH_SHA256_CODE_VERIFIER&code_challenge_method=S256
```

#### Paso B: Canjear Código por Tokens
Al recibir el callback en tu servidor, realiza una petición Server-to-Server:

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

**Respuesta exitosa:**

```json
{
  "access_token": "<token_jwt_firmado>",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

---

### 2. Autenticación Multi-Factor (MFA)

Peak Auth ofrece flujos integrados tanto para usuarios del portal SSO como para la API:
- **TOTP**: Al registrarse, se genera un código QR y secreto compatible con aplicaciones estándar de autenticación.
- **WebAuthn / Passkeys**: Desafíos criptográficos nativos basados en la API Web Authentication del navegador, registrando credenciales públicas asociadas al usuario.
- **Códigos de Recuperación**: Códigos alfanuméricos de respaldo descargables en caso de pérdida del dispositivo MFA.
- **Enforcement**: Si una app tiene la regla `MFA_POLICY=REQUIRED`, un usuario sin segundo factor registrado es redirigido automáticamente a la interfaz de configuración forzada (`/oauth/login/mfa/setup`) antes de recibir autorización.

---

## 🔌 Cómo Integrar tus Aplicaciones

Gracias a los **JWT Asimétricos (RSA-256)** y a los endpoints estándar de descubrimiento OIDC/OAuth 2.0 (`GET /.well-known/openid-configuration` y `GET /.well-known/jwks.json`), cualquier aplicación cliente, framework o microservicio puede integrarse de forma automática, validando tokens **sin llamadas repetitivas** y con soporte automático para rotación de claves.

### Opción A: Validación automática vía JWKS / OIDC (Recomendado)

Peak Auth expone su conjunto de claves públicas en `/.well-known/jwks.json`. Librerías estándar como `jose` en Node/TypeScript pueden descargar y cachear las claves automáticamente:

```typescript
import { createRemoteJWKSet, jwtVerify } from "jose";

// Cachea automáticamente la clave pública usando el JWKS
const JWKS = createRemoteJWKSet(new URL("http://localhost:8080/.well-known/jwks.json"));

export async function verifyToken(token: string, clientId: string) {
  const { payload } = await jwtVerify(token, JWKS, {
    issuer: "peak-auth",
    audience: clientId,
  });
  return payload;
}
```

### Opción B: Validación con Clave Pública PEM en Node.js / Express

```javascript
import jwt from "jsonwebtoken";
import fs from "fs";

// Cargar la clave PÚBLICA descargada de Peak Auth
const publicKey = fs.readFileSync("./jwt_public.pem", "utf-8");

export function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Token no suministrado" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, publicKey, {
      algorithms: ["RS256"],
      issuer: "peak-auth",
      audience: "TU_CLIENT_ID",
    });

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: "Token inválido o expirado" });
  }
}
```

### Opción C: Validación en Go (Gin Framework)

```go
package middleware

import (
	"crypto/rsa"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var rsaPublicKey *rsa.PublicKey

func InitPublicKey(path string) error {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	rsaPublicKey, err = jwt.ParseRSAPublicKeyFromPEM(bytes)
	return err
}

func RequireAuth(clientID string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Bearer token requerido"})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return rsaPublicKey, nil
		},
			jwt.WithValidMethods([]string{"RS256"}),
			jwt.WithIssuer("peak-auth"),
			jwt.WithAudience(clientID),
		)

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token no válido"})
			return
		}

		c.Set("claims", token.Claims)
		c.Next()
	}
}
```

---

## 🐳 Despliegue con Docker

Peak Auth incluye un `Dockerfile` multi-stage ultra-seguro y ligero basado en **Google Distroless (`gcr.io/distroless/static-debian12:nonroot`)**: sin shell, sin gestores de paquetes y ejecutándose exclusivamente como usuario no privilegiado (`nonroot`):

```bash
# Construir la imagen
docker build -t peak-auth .

# Ejecutar el contenedor
docker run -d -p 8080:8080 \
  --name peak-auth \
  -e DATABASE_URL="postgres://user:pass@db:5432/peak_auth?sslmode=disable" \
  -e JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----" \
  -e RESEND_API_KEY="re_tu_resend_api_key" \
  peak-auth
```

---

## 🧪 Pruebas Automatizadas

Para ejecutar el conjunto de tests unitarios y de integración de la aplicación:

```bash
go test -v ./...
```

---

## 📄 Licencia

Este proyecto se distribuye bajo la licencia **MIT**. Consulta el archivo [LICENSE](LICENSE) para más información.
