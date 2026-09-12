# Referencia de la API REST - Peak Auth

Peak Auth expone una API RESTFul modular con soporte para **OIDC Discovery**, **OAuth 2.0 con PKCE**, y endpoints administrativos bajo `/admin`.

---

## 🔍 1. Descubrimiento OIDC & JWKS (Público)

### 1.1 Configuración OpenID Connect
`GET /.well-known/openid-configuration`

Devuelve los metadatos estándar del servidor (endpoints de autorización, token y jwks).

**Response (200 OK):**
```json
{
  "issuer": "peak-auth",
  "authorization_endpoint": "https://auth.tuempresa.com/oauth/authorize",
  "token_endpoint": "https://auth.tuempresa.com/oauth/token",
  "jwks_uri": "https://auth.tuempresa.com/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"]
}
```

### 1.2 JSON Web Key Set (JWKS - RFC 7517)
`GET /.well-known/jwks.json`

Publica las claves públicas RSA activas y las que se encuentran en período de gracia para validación offline en clientes.

**Response (200 OK):**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "kid": "peak-auth-key-1",
      "n": "<MODULO_RSA_BASE64URL>",
      "e": "AQAB"
    }
  ]
}
```

---

## ⚡ 2. Endpoints OAuth 2.0 + PKCE

### 2.1 Autorización
`GET /oauth/authorize`

Inicia el flujo de autenticación. Si el usuario cuenta con sesión SSO (`peak_session`), emite un Authorization Code y redirige inmediatamente. De lo contrario, lo envía al login público.

**Parámetros Query:**
- `client_id` (requerido): Identificador de la aplicación cliente.
- `redirect_uri` (requerido): URI de retorno registrada exactamente en Peak Auth.
- `response_type` (requerido): Debe ser `code`.
- `state` (recomendado): Cadena aleatoria contra ataques CSRF.
- `code_challenge` (requerido para PKCE): SHA-256 base64url del `code_verifier`.
- `code_challenge_method` (requerido para PKCE): `S256`.

**Redirección exitosa:**
```text
302 Found
Location: https://tu-app.com/callback?code=<CODE>&state=<STATE>
```

### 2.2 Canje de Código por Tokens (Token Endpoint)
`POST /oauth/token`

Intercambia de forma atómica y de un solo uso el `code` por un Access Token firmado y un Refresh Token.

**Request Body (`application/x-www-form-urlencoded` o `application/json`):**
```text
grant_type=authorization_code
&client_id=<CLIENT_ID>
&client_secret=<CLIENT_SECRET>
&code=<CODE>
&redirect_uri=<REDIRECT_URI>
&code_verifier=<CODE_VERIFIER>
```

**Response (200 OK):**
```json
{
  "access_token": "<JWT_FIRMADO>",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

---

## 🛡️ 3. Endpoints Directos API v1

### 3.1 Iniciar Sesión Directo (Resource Owner)
`POST /api/v1/login`

**Request Body (JSON):**
```json
{
  "email": "usuario@ejemplo.com",
  "password": "<PASSWORD>",
  "client_id": "mi-app"
}
```

**Response (200 OK):**
```json
{
  "access_token": "<JWT>",
  "refresh_token": "<REFRESH_TOKEN>",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

**Response (MFA Requerido - 200 OK con mfa_pending):**
```json
{
  "mfa_required": true,
  "mfa_token": "<TEMPORAL_MFA_TOKEN>"
}
```

### 3.2 Verificar MFA TOTP
`POST /api/v1/login/mfa/totp`

**Request Body (JSON):**
```json
{
  "mfa_token": "<TEMPORAL_MFA_TOKEN>",
  "code": "123456",
  "client_id": "mi-app"
}
```

### 3.3 Renovar Token (Rotación Atómica)
`POST /api/v1/refresh`

Intercambia un refresh token válido por uno nuevo, invalidando el token anterior para prevenir ataques de replay.

**Request Body (JSON):**
```json
{
  "refresh_token": "<REFRESH_TOKEN>",
  "client_id": "mi-app"
}
```

**Response (200 OK):**
```json
{
  "access_token": "<NUEVO_JWT>",
  "refresh_token": "<NUEVO_REFRESH_TOKEN>",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

---

## ⚠️ Códigos de Error Comunes

- `400 Bad Request`: Parámetros incompletos, code_verifier erróneo (`invalid_grant`), o redirect_uri no registrada.
- `401 Unauthorized`: Credenciales inválidas o refresh token expirado/reutilizado.
- `403 Forbidden`: Permisos insuficientes o usuario desactivado.
- `429 Too Many Requests`: Límite de tasa excedido (Rate Limit por IP).
- `500 Internal Server Error`: Error inesperado del servidor.
