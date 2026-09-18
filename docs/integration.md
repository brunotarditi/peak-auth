# Guía de Integración de Peak Auth

**Peak Auth** es un Proveedor de Identidad (IdP) y servidor Single Sign-On (SSO) basado en el estándar **OAuth 2.0 con PKCE** y **JWT Asimétricos (RSA-256)** con descubrimiento OIDC vía JWKS.

Esta guía explica cómo integrar aplicaciones frontend (Angular, React, Vue, móvil) y backend (Go, Node.js/Express, Next.js) de forma rápida y segura.

---

## 🎯 Arquitectura de Integración

```text
Usuario en Frontend (Angular, React, Web)
   │
   ├─ 1. Inicia login OAuth PKCE ──────────────────────► Peak Auth (/oauth/authorize)
   │                                                         │
   │                                                         ├─ Verifica sesión SSO o pide login + MFA
   │                                                         └─ Emite código de autorización
   │
   ├─ 2. Recibe Authorization Code en /callback ◄────────────┘
   │
   ├─ 3. Envía Code + Code Verifier a su Backend ──────► Backend de tu Aplicación
                                                             │
                                                             ├─ 4. Canjea Code por Token en Peak Auth (/oauth/token)
                                                             ├─ 5. Recibe Access Token (JWT) + Refresh Token
                                                             └─ 6. Valida firma offline vía JWKS (sin archivos PEM manuales)
```

---

## Paso 1: Registrar la Aplicación en Peak Auth

1. Inicia sesión en el panel administrativo de Peak Auth (`/admin`).
2. Ve a **Aplicaciones** ➔ **Nueva Aplicación**.
3. Configura:
   - **Nombre:** Ej. `Librería Mariela`
   - **App ID (Client ID):** Ej. `libreria-mariela`
   - **URI de Redirección:** Ej. `http://localhost:4200/callback` (donde vuelve tu frontend tras autenticarse).
4. El sistema generará el `client_id` y su `client_secret`.

---

## Paso 2: Flujo de Autorización Frontend (OAuth 2.0 + PKCE)

Para aplicaciones frontend (SPAs o móviles), se debe utilizar PKCE con método `S256` para evitar la interceptación de códigos de autorización.

### 1. Generar PKCE (`code_verifier` y `code_challenge`)
- `code_verifier`: Cadena aleatoria segura de 43 a 128 caracteres.
- `code_challenge`: Hash SHA-256 del verifier codificado en base64url (sin padding).

### 2. Redirigir al usuario al endpoint de autorización:
```text
GET https://<TU_DOMINIO_PEAK_AUTH>/oauth/authorize
    ?client_id=libreria-mariela
    &redirect_uri=https://tu-app.com/callback
    &response_type=code
    &state=<STATE_CSRF_ALEATORIO>
    &code_challenge=<CODE_CHALLENGE>
    &code_challenge_method=S256
```

### 3. Recibir el código en el callback:
Tras el login (y verificación MFA si está configurado), Peak Auth redirige a:
```text
https://tu-app.com/callback?code=<AUTHORIZATION_CODE>&state=<STATE>
```

---

## Paso 3: Validación y Consumo de Tokens en el Backend

El backend puede validar tokens de dos formas:

### 🔒 Validación Online (Recomendada para Revocación Inmediata)

Utiliza el endpoint `/api/v1/introspect` para verificar el estado actual del token en tiempo real, incluyendo si ha sido revocado. **Esta es la opción recomendada cuando se requiere que la revocación de acceso sea efectiva inmediatamente**, como en aplicaciones financieras, de salud o con requisitos de seguridad estrictos.

**Ventajas:**
- Detecta revocación inmediata (authz_version mismatch)
- Verifica estado actual del usuario y aplicación
- Cumple con RFC 7662 (OAuth 2.0 Token Introspection)

**Desventajas:**
- Requiere una llamada HTTP por cada validación
- Mayor latencia (~50-100ms adicionales)
- Requiere ClientSecret configurado

### ⚡ Validación Offline (Eventual Consistency)

Valida la firma RSA del JWT localmente utilizando el JWKS cacheado, verificando solo expiración, emisor y audiencia. **Esta opción es apropiada para aplicaciones con requisitos de latencia ultra-baja donde la revocación eventual (al expirar el token) es aceptable**.

**Ventajas:**
- Validación en microsegundos (sin llamadas HTTP)
- Escalabilidad horizontal sin límites
- Funciona incluso si Peak Auth está temporalmente inaccesible

**Desventajas:**
- **No detecta revocación inmediata**: tokens válidos seguirán siendo aceptados hasta su expiración natural
- Requiere tokens de corta duración (≤15 minutos) para minimizar ventana de exposición
- No apropiado para casos de uso que requieren revocación inmediata

---

### 🚀 Opción A: Backend en Go (SDK Oficial)

```bash
go get github.com/brunotarditi/peak-auth/sdk/go
# Si usas Gin:
go get github.com/brunotarditi/peak-auth/sdk/go/gin
```

#### Con Gin Framework:
```go
package main

import (
    "net/http"
    "github.com/gin-gonic/gin"
    peakauth "github.com/brunotarditi/peak-auth/sdk/go"
    peakauthgin "github.com/brunotarditi/peak-auth/sdk/go/gin"
)

func main() {
    client, err := peakauth.New(peakauth.Config{
        IssuerURL:    "https://auth.tuempresa.com",
        ClientID:     "tu-empresa",
        ClientSecret: "tu-client-secret", // Requerido para introspección
    })
    if err != nil {
        panic(err)
    }

    r := gin.Default()

    // Validación OFFLINE (eventual consistency): apropiada para APIs de lectura de baja latencia
    r.GET("/api/libros", peakauthgin.Middleware(client), func(c *gin.Context) {
        claims, _ := peakauthgin.ClaimsFromContext(c)
        c.JSON(http.StatusOK, gin.H{"usuario": claims.Username, "roles": claims.Roles})
    })

    // Validación ONLINE (revocación inmediata): recomendada para operaciones sensibles
    r.POST("/api/libros", peakauthgin.MiddlewareWithOptions(client, peakauthgin.MiddlewareOptions{
        RequiredRoles:    []string{"ADMIN"},
        UseIntrospection: true, // Verifica revocación en tiempo real
    }), func(c *gin.Context) {
        c.JSON(http.StatusCreated, gin.H{"mensaje": "Libro creado"})
    })

    r.Run(":3000")
}
```

#### Con `net/http` estándar o Chi:
```go
mux := http.NewServeMux()

// Validación offline
handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    claims, _ := peakauth.ClaimsFromContext(r.Context())
    w.Write([]byte("Hola " + claims.Username))
})
mux.Handle("/api/perfil", client.HTTPMiddleware()(handler))

// Validación online con revocación inmediata
adminHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Panel de administración"))
})
mux.Handle("/api/admin", client.HTTPMiddlewareWithOptions(peakauth.HTTPMiddlewareOptions{
    RequiredRoles:    []string{"ADMIN"},
    UseIntrospection: true,
})(adminHandler))
```

---

### 🚀 Opción B: Backend en Node.js / Express / Next.js (SDK Oficial)

```bash
npm install @brunotarditi/peak-auth
```

#### Con Express:
```typescript
import express from 'express';
import { PeakAuthClient } from '@brunotarditi/peak-auth';
import { peakAuthMiddleware } from '@brunotarditi/peak-auth/express';

const app = express();
const peakAuth = new PeakAuthClient({
  issuerUrl: 'https://auth.tuempresa.com',
  clientId: 'tu-empresa',
  clientSecret: 'tu-client-secret', // Requerido para introspección
});

// Validación OFFLINE (eventual consistency): apropiada para APIs de lectura
app.get('/api/perfil', peakAuthMiddleware(peakAuth), (req, res) => {
  res.json({ usuario: req.user });
});

// Validación ONLINE (revocación inmediata): recomendada para operaciones sensibles
app.post('/api/admin', peakAuthMiddleware(peakAuth, {
  requiredRoles: ['ADMIN'],
  useIntrospection: true, // Verifica revocación en tiempo real
}), (req, res) => {
  res.json({ mensaje: 'Bienvenido Admin', usuario: req.user });
});

app.listen(3000);
```

#### Con Next.js App Router (`app/api/profile/route.ts`):
```typescript
import { NextResponse } from 'next/server';
import { PeakAuthClient } from '@brunotarditi/peak-auth';
import { verifyNextRequest } from '@brunotarditi/peak-auth/nextjs';

const peakAuth = new PeakAuthClient({
  issuerUrl: process.env.PEAK_AUTH_URL!,
  clientId: process.env.PEAK_CLIENT_ID!,
  clientSecret: process.env.PEAK_CLIENT_SECRET, // Requerido para introspección
});

// Validación offline
export async function GET(request: Request) {
  try {
    const user = await verifyNextRequest(request, peakAuth);
    return NextResponse.json({ user });
  } catch (err) {
    return NextResponse.json({ error: (err as Error).message }, { status: 401 });
  }
}

// Validación online con revocación inmediata
export async function POST(request: Request) {
  try {
    const user = await verifyNextRequest(request, peakAuth, {
      requiredRoles: ['ADMIN'],
      useIntrospection: true, // Verifica revocación en tiempo real
    });
    return NextResponse.json({ success: true, user });
  } catch (err) {
    return NextResponse.json({ error: (err as Error).message }, { status: 401 });
  }
}
```

---

## 🔄 Rotación de Claves Cero-Downtime

1. Peak Auth publica todas las claves públicas válidas (la clave activa y las claves en período de gracia) en:
   ```text
   GET https://<TU_DOMINIO_PEAK_AUTH>/.well-known/jwks.json
   ```
2. Los SDKs oficiales cachean las claves en memoria y detectan automáticamente cuando un token llega firmado con un nuevo `kid`, recargando el JWKS de forma transparente.
3. No se requiere copiar archivos `.pem` a los servidores cliente ni reiniciar los backends cuando se rotan claves en Peak Auth.

---

## 🔐 Revocación de Acceso y Consideraciones de Seguridad

### Mecanismo de Revocación (authz_version)

Peak Auth implementa revocación inmediata mediante el campo `authz_version` en los tokens JWT. Cuando se revoca el acceso de un usuario a una aplicación:

1. Se incrementa el `authz_version` del usuario en la base de datos
2. Los tokens existentes contienen el `authz_version` anterior
3. El endpoint `/api/v1/introspect` compara el `authz_version` del token con el actual del usuario
4. Si no coinciden, el token se considera revocado (`active: false`)

### Cuándo Usar Validación Online (Introspección)

**Utiliza `useIntrospection: true` cuando:**
- La revocación de acceso debe ser efectiva inmediatamente (≤1 segundo)
- Manejas datos sensibles (financieros, médicos, PII)
- Cumples con regulaciones que exigen revocación inmediata (PCI-DSS, HIPAA, GDPR)
- Implementas funcionalidad de "cerrar todas las sesiones" o "revocar acceso de emergencia"
- El usuario cambia su contraseña y debe invalidar todas las sesiones activas

**Ejemplo de caso de uso crítico:**
```typescript
// Endpoint de transferencia bancaria - requiere revocación inmediata
app.post('/api/transferencias', peakAuthMiddleware(peakAuth, {
  requiredRoles: ['ACCOUNT_HOLDER'],
  useIntrospection: true, // ✅ Verifica que el usuario no haya sido revocado
}), async (req, res) => {
  // Procesar transferencia...
});
```

### Cuándo Usar Validación Offline (JWKS)

**Utiliza validación offline (por defecto) cuando:**
- La latencia es crítica (APIs de lectura de alta frecuencia)
- Los datos no son sensibles o tienen naturaleza pública
- La revocación eventual (al expirar el token) es aceptable
- Necesitas escalabilidad horizontal sin límites
- Quieres resiliencia ante indisponibilidad temporal del IdP

**Mitigaciones recomendadas para validación offline:**
- Configura tokens de corta duración (≤15 minutos) en la política de sesión
- Implementa refresh token rotation para minimizar ventana de exposición
- Combina con rate limiting y detección de anomalías
- Usa validación online para operaciones críticas específicas

### Configuración de Duración de Tokens

Para minimizar la ventana de exposición con validación offline, configura la política de sesión en Peak Auth:

1. Ve a **Aplicaciones** → **Tu Aplicación** → **Reglas**
2. Edita la regla `SESSION_POLICY`
3. Configura `tokenExpirationMinutes`:
   - **Validación offline**: 5-15 minutos (recomendado)
   - **Validación online**: 30-60 minutos (aceptable)

### Endpoint de Introspección

El endpoint `/api/v1/introspect` está disponible para validación manual:

```bash
curl -X POST https://auth.tuempresa.com/api/v1/introspect \
  -H "Content-Type: application/json" \
  -H "X-App-Id: tu-client-id" \
  -H "X-App-Secret: tu-client-secret" \
  -d '{"token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}'
```

Respuesta cuando el token es válido:
```json
{
  "active": true,
  "sub": "42",
  "username": "usuario@ejemplo.com",
  "aud": "libreria-mariela",
  "roles": ["USER", "ADMIN"],
  "mfa_verified": true,
  "exp": 1735689600,
  "iat": 1735686000
}
```

Respuesta cuando el token ha sido revocado:
```json
{
  "active": false
}
```

### Resumen de Recomendaciones

| Escenario | Validación | Duración Token | Justificación |
|-----------|-----------|----------------|---------------|
| API de lectura pública | Offline | 15 min | Latencia ultra-baja, datos no sensibles |
| Dashboard empresarial | Offline | 15 min | Balance latencia/seguridad |
| Operaciones financieras | **Online** | 30 min | Revocación inmediata crítica |
| Datos médicos (HIPAA) | **Online** | 30 min | Cumplimiento regulatorio |
| Admin panel (cambios críticos) | **Online** | 15 min | Seguridad máxima |
| APIs públicas de terceros | Offline | 5 min | Minimizar ventana de exposición |

**Regla general:** Si la pregunta "¿qué pasa si un usuario revocado accede durante los próximos 15 minutos?" tiene una respuesta inaceptable, usa validación online.
