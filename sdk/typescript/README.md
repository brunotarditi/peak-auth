# @brunotarditi/peak-auth

SDK oficial, universal y ultra-liviano para integrar tus aplicaciones **Node.js, Express y Next.js** con **Peak Auth**.

Construido sobre la biblioteca estándar [`jose`](https://github.com/panva/jose) (sin dependencias binarias ni C++), compatible con Node.js 18+, Bun, y entornos Edge (Vercel Edge Runtime, Cloudflare Workers).

---

## 📦 Instalación

```bash
npm install @brunotarditi/peak-auth
# o
pnpm add @brunotarditi/peak-auth
# o
yarn add @brunotarditi/peak-auth
```

---

## ⚡ Inicio Rápido

### 1. Inicializar el cliente

```typescript
import { PeakAuthClient } from '@brunotarditi/peak-auth';

const peakAuth = new PeakAuthClient({
  issuerUrl: 'https://auth.tuempresa.com', // o http://localhost:8080
  clientId: 'tu_client_id',
  clientSecret: 'tu_client_secret', // Requerido para validación con revocación inmediata
  redirectUri: 'https://tu-app.com/api/auth/callback',
  // expectedIssuer: 'peak-auth', // Por defecto "peak-auth" (coincide con claim 'iss' del JWT)
});
```

> **⚠️ Importante - Validación de Revocación:**
> 
> - **Con `clientSecret` configurado (recomendado):** El middleware usa automáticamente validación online vía `/api/v1/introspect`, verificando revocación inmediata de tokens.
> - **Sin `clientSecret`:** El middleware usa validación offline (solo firma y expiración). Los tokens emitidos antes de revocar acceso seguirán siendo aceptados hasta su expiración natural.
> 
> Para aplicaciones en producción que requieren revocación inmediata de sesiones, configure siempre `clientSecret`.

---

## 🛡️ Uso en Express

### Proteger rutas con el Middleware

Puedes importar el middleware directamente desde el subpath `@brunotarditi/peak-auth/express`:

```typescript
import express from 'express';
import { PeakAuthClient } from '@brunotarditi/peak-auth';
import { peakAuthMiddleware } from '@brunotarditi/peak-auth/express';

const app = express();
const peakAuth = new PeakAuthClient({
  issuerUrl: 'https://auth.tuempresa.com',
  clientId: 'tu_client_id',
  clientSecret: 'tu_client_secret', // Requerido para detección de revocación
});

// Ruta pública
app.get('/api/public', (req, res) => {
  res.json({ status: 'ok' });
});

// Ruta protegida (cualquier usuario autenticado con token válido)
// Con clientSecret configurado, verifica automáticamente revocación
app.get('/api/protected', peakAuthMiddleware(peakAuth), (req, res) => {
  // El usuario decodificado está disponible en req.user
  res.json({
    message: 'Acceso autorizado',
    user: req.user,
  });
});

// Ruta que exige un rol específico (ej. "ADMIN")
app.get(
  '/api/admin',
  peakAuthMiddleware(peakAuth, { requiredRoles: ['ADMIN'] }),
  (req, res) => {
    res.json({ message: 'Bienvenido Administrador', user: req.user });
  }
);

app.listen(3000, () => console.log('Servidor corriendo en el puerto 3000'));
```

### Validación Offline vs Online

Por defecto, si el cliente tiene `clientSecret` configurado, el middleware usa **validación online** (introspección) que verifica revocación inmediata. Si no tiene `clientSecret`, usa **validación offline** (solo firma y expiración).

Para forzar un modo específico:

```typescript
// Forzar validación online (requiere clientSecret)
app.get('/api/secure', 
  peakAuthMiddleware(peakAuth, { useIntrospection: true }), 
  handler
);

// Forzar validación offline (NO verifica revocación - usar solo si comprende las implicaciones)
app.get('/api/fast', 
  peakAuthMiddleware(peakAuth, { useIntrospection: false }), 
  handler
);
```

---

## 🌐 Flujo OAuth 2.0 con PKCE

### Generar URL de login con PKCE

```typescript
// 1. Generar desafío PKCE
const pkce = await peakAuth.generatePKCE();

// Guardar pkce.codeVerifier en la sesión/cookie HttpOnly del usuario
// ...

// 2. Obtener URL de redirección
const authUrl = peakAuth.getAuthorizationUrl({
  state: 'estado_csrf_aleatorio',
  codeChallenge: pkce.codeChallenge,
});

// Redirigir al usuario
res.redirect(authUrl);
```

### Canjear código en el Callback (`/api/auth/callback`)

```typescript
app.get('/api/auth/callback', async (req, res) => {
  const { code, state } = req.query;

  // Recuperar codeVerifier almacenado previamente
  const codeVerifier = req.cookies.code_verifier;

  try {
    const tokens = await peakAuth.exchangeCode({
      code: String(code),
      codeVerifier,
    });

    // tokens.access_token contiene el JWT firmado
    // tokens.refresh_token (si aplica)
    res.json({ success: true, tokens });
  } catch (error) {
    res.status(400).json({ error: (error as Error).message });
  }
});
```

---

## ⚡ Uso en Next.js (App Router)

### Validar en Route Handlers (`app/api/profile/route.ts`)

```typescript
import { NextResponse } from 'next/server';
import { PeakAuthClient } from '@brunotarditi/peak-auth';
import { verifyNextRequest } from '@brunotarditi/peak-auth/nextjs';

const peakAuth = new PeakAuthClient({
  issuerUrl: process.env.PEAK_AUTH_URL!,
  clientId: process.env.PEAK_CLIENT_ID!,
  clientSecret: process.env.PEAK_CLIENT_SECRET!, // Requerido para detección de revocación
});

export async function GET(request: Request) {
  try {
    // Valida automáticamente desde el header Authorization o desde cookies
    // Con clientSecret configurado, verifica automáticamente revocación
    const user = await verifyNextRequest(request, peakAuth, {
      requiredRoles: ['USER'],
    });

    return NextResponse.json({ user });
  } catch (err) {
    return NextResponse.json(
      { error: (err as Error).message },
      { status: 401 }
    );
  }
}
```

---

## 📄 Licencia

MIT © Bruno Tarditi
