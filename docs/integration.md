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

El backend puede validar tokens **de forma offline en microsegundos** utilizando los SDKs oficiales, los cuales descargan y cachean automáticamente las claves públicas desde `/.well-known/jwks.json`.

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
        IssuerURL: "https://auth.tuempresa.com",
        ClientID:  "libreria-mariela",
    })
    if err != nil {
        panic(err)
    }

    r := gin.Default()

    // Endpoint protegido (requiere token válido)
    r.GET("/api/libros", peakauthgin.Middleware(client), func(c *gin.Context) {
        claims, _ := peakauthgin.ClaimsFromContext(c)
        c.JSON(http.StatusOK, gin.H{"usuario": claims.Username, "roles": claims.Roles})
    })

    // Endpoint protegido que requiere rol ADMIN
    r.POST("/api/libros", peakauthgin.Middleware(client, "ADMIN"), func(c *gin.Context) {
        c.JSON(http.StatusCreated, gin.H{"mensaje": "Libro creado"})
    })

    r.Run(":3000")
}
```

#### Con `net/http` estándar o Chi:
```go
mux := http.NewServeMux()
handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    claims, _ := peakauth.ClaimsFromContext(r.Context())
    w.Write([]byte("Hola " + claims.Username))
})

mux.Handle("/api/admin", client.HTTPMiddleware("ADMIN")(handler))
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
  clientId: 'libreria-mariela',
});

// Ruta protegida para usuarios autenticados
app.get('/api/perfil', peakAuthMiddleware(peakAuth), (req, res) => {
  res.json({ usuario: req.user });
});

// Ruta que exige rol específico
app.get('/api/admin', peakAuthMiddleware(peakAuth, { requiredRoles: ['ADMIN'] }), (req, res) => {
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
});

export async function GET(request: Request) {
  try {
    const user = await verifyNextRequest(request, peakAuth);
    return NextResponse.json({ user });
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
