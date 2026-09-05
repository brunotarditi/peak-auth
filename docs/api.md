# Referencia de la API REST - Peak Auth

Peak Auth expone una API RESTFul bajo el prefijo `/api/v1` para la integración cliente a servidor, y rutas bajo `/admin` para la gestión interna.

## Autenticación y Autorización

Todas las rutas protegidas requieren un header HTTP:
`Authorization: Bearer <ACCESS_TOKEN>`

## 1. Endpoints Públicos (Autenticación)

### 1.1 Iniciar Sesión (Login)
`POST /api/v1/login`

Valida las credenciales de un usuario y retorna un Access Token y un Refresh Token.

**Request Body (JSON):**
```json
{
  "email": "usuario@email.com",
  "password": "MiPasswordSeguro123",
  "client_id": "app_client_id_opcional"
}
```

**Response (200 OK):**
```json
{
  "access_token": "<TU_TOKEN_JWT_AQUI>",
  "refresh_token": "rt_8f7d6a5b4c...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

**Response MFA Requerido (403 Forbidden):**
*(Si la cuenta tiene MFA activado)*
```json
{
  "error": "MFA_REQUIRED",
  "mfa_token": "temp_token_for_mfa_verification"
}
```

### 1.2 Verificar MFA
`POST /api/v1/mfa/verify`

**Headers:**
`Authorization: Bearer <mfa_token>`

**Request Body (JSON):**
```json
{
  "code": "123456",
  "client_id": "app_client_id_opcional"
}
```

### 1.3 Renovar Token (Refresh)
`POST /api/v1/refresh`

Genera un nuevo Access Token utilizando un Refresh Token válido.

**Request Body (JSON):**
```json
{
  "refresh_token": "rt_8f7d6a5b4c...",
  "client_id": "app_client_id_opcional"
}
```

### 1.4 Registro de Usuario
`POST /api/v1/register`

Crea una nueva cuenta de usuario (depende de la política de `ALLOW_REGISTRATION`).

**Request Body (JSON):**
```json
{
  "email": "nuevo@usuario.com",
  "password": "PasswordFuerte123"
}
```

## 2. Endpoints de Aplicaciones (Integración B2B)

Las aplicaciones cliente también pueden comunicarse de servidor a servidor (M2M) utilizando su `client_id` y `client_secret`.

### 2.1 Obtener Información del Usuario
`GET /api/v1/users/me`

**Headers:**
`Authorization: Bearer <ACCESS_TOKEN>`

Retorna la información del perfil y los roles asociados a la aplicación desde la cual se solicitó el token.

**Response (200 OK):**
```json
{
  "id": 105,
  "email": "usuario@email.com",
  "roles": ["ADMIN", "EDITOR"],
  "is_active": true
}
```

## 3. Códigos de Error Comunes

- `400 Bad Request`: Faltan campos obligatorios o el formato es inválido.
- `401 Unauthorized`: Credenciales inválidas, token expirado o firma RSA inválida.
- `403 Forbidden`: El usuario no tiene el rol necesario, la aplicación está desactivada o falta MFA.
- `404 Not Found`: El recurso solicitado (ej. una app por ID) no existe.
- `429 Too Many Requests`: Has superado el límite de intentos (Rate Limiting).
- `500 Internal Server Error`: Fallo interno del servidor Peak Auth.
