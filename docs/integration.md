# Guía de Integración de Peak Auth

Peak Auth es un sistema de SSO (Single Sign-On) basado en **JWT Asimétrico (RSA-256)**. Esta guía explica cómo integrar cualquier aplicación cliente (frontend o backend) con Peak Auth.

## Conceptos Básicos

1. **Peak Auth actúa como el Proveedor de Identidad (IdP).** No necesitas programar sistemas de login, registro, o recuperación de contraseña en tu aplicación.
2. **Aplicación Cliente:** Tu aplicación web, móvil o backend.
3. **Claves Asimétricas:** Peak Auth firma los tokens con su **Clave Privada**. Tu aplicación verifica los tokens usando la **Clave Pública** de Peak Auth.

## Flujo de Autenticación (OAuth 2.0 / OIDC inspirado)

1. El usuario intenta acceder a una ruta protegida en tu aplicación.
2. Tu aplicación verifica si el usuario tiene una sesión local válida (un JWT).
3. Si no la tiene, lo **rediriges** al portal de Peak Auth.
4. El usuario inicia sesión en Peak Auth (introduciendo sus credenciales, MFA, etc).
5. Tras un login exitoso, Peak Auth redirige al usuario de vuelta a tu aplicación (a la `RedirectURI` configurada) enviando un código o token.
6. Tu aplicación recibe el token y le da acceso al usuario.

## Paso 1: Configurar la Aplicación en Peak Auth

1. Inicia sesión en el panel de administrador de Peak Auth (`/admin`).
2. Haz clic en **Nueva Aplicación**.
3. Rellena los datos:
   - **Nombre:** Ej. `Librería Mariela`
   - **URI de Redirección:** Ej. `http://localhost:3000/auth/callback` (donde volverá el usuario).
4. Guarda los cambios. El sistema generará un **Client ID** y un **Client Secret**.

## Paso 2: Redirigir al Login

En tu aplicación cliente (ej. React, Vue, Next.js, o un backend en Go/Node), cuando un usuario pulse "Iniciar Sesión", envíalo a esta URL:

```text
GET https://<TU_DOMINIO_PEAK_AUTH>/login?client_id=<TU_CLIENT_ID>&redirect_uri=<TU_REDIRECT_URI>
```

> **Nota:** La URL pública de login actualmente se expone en `/login` o mediante la API si utilizas tu propia interfaz.

## Paso 3: Validar el JWT Asimétrico en tu Backend

Cuando recibas el **Access Token** de Peak Auth, tu aplicación cliente (específicamente tu backend o servidor) debe validarlo **sin hacer peticiones HTTP a Peak Auth**. Esto se logra usando la **Clave Pública**.

### Ejemplo en Node.js (Express)

```javascript
const jwt = require("jsonwebtoken");
const fs = require("fs");

// 1. Cargar la clave PÚBLICA (descargada previamente desde Peak Auth)
const publicKeyPEM = fs.readFileSync("./jwt_public.pem", "utf-8");

app.get("/api/protegido", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) return res.status(401).json({ error: "No token" });

  try {
    // 2. Verificar el JWT usando RSA-256
    const decoded = jwt.verify(token, publicKeyPEM, {
      algorithms: ["RS256"],
    });

    // 3. El token es válido, y fue emitido por Peak Auth.
    // 'decoded' contiene { sub: userID, roles: [...], email: "..." }
    res.json({ message: "Acceso permitido", user: decoded });

  } catch (err) {
    res.status(403).json({ error: "Token inválido o expirado" });
  }
});
```

### Ejemplo en Go (Gin Framework)

```go
package main

import (
    "crypto/rsa"
    "fmt"
    "os"
    "strings"
    "github.com/golang-jwt/jwt/v5"
)

var publicKey *rsa.PublicKey

func init() {
    // Cargar clave pública
    pubBytes, _ := os.ReadFile("jwt_public.pem")
    publicKey, _ = jwt.ParseRSAPublicKeyFromPEM(pubBytes)
}

func AuthMiddleware(tokenString string) error {
    token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
        if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("método de firma inesperado: %v", t.Header["alg"])
        }
        return publicKey, nil
    })

    if err != nil || !token.Valid {
        return fmt.Errorf("token inválido")
    }

    return nil
}
```

## Beneficios de este diseño

- **Cero latencia:** Tu aplicación no tiene que llamar a la API de Peak Auth en cada petición para saber si el usuario está autorizado. Todo se valida matemáticamente en tu servidor mediante RSA.
- **Microservicios:** Si tienes 5 APIs diferentes (Facturación, Inventario, Envíos), todas pueden compartir la misma clave pública y validar los tokens de Peak Auth sin comunicarse entre ellas.
- **Roles Centralizados:** Los claims del JWT incluyen los roles (`ADMIN`, `USER`) específicos para *tu aplicación*.
