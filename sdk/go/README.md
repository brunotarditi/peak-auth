# Peak Auth Go SDK

SDK oficial y liviano de **Peak Auth** para Go. Permite validar tokens JWT asimétricos (RSA-256) de forma offline utilizando el endpoint JWKS automático con cache en memoria, e incluye middlewares listos para usar en **Gin** y **`net/http`**.

---

## 📦 Instalación

```bash
go get github.com/brunotarditi/peak-auth/sdk/go
```

---

## ⚡ Inicio Rápido

### 1. Inicializar el cliente

```go
package main

import (
	"log"

	peakauth "github.com/brunotarditi/peak-auth/sdk/go"
)

func main() {
	client, err := peakauth.New(peakauth.Config{
		IssuerURL: "https://auth.tuempresa.com", // o http://localhost:8080
		ClientID:  "tu_client_id",
		ClientSecret: "tu_client_secret", // Requerido para validación con revocación inmediata
		RedirectURI:  "https://tu-app.com/callback",
	})
	if err != nil {
		log.Fatalf("Error inicializando Peak Auth: %v", err)
	}
}
```

> **⚠️ Importante - Validación de Revocación:**
> 
> - **Con `ClientSecret` configurado (recomendado):** El middleware usa automáticamente validación online vía `/api/v1/introspect`, verificando revocación inmediata de tokens.
> - **Sin `ClientSecret`:** El middleware usa validación offline (solo firma y expiración). Los tokens emitidos antes de revocar acceso seguirán siendo aceptados hasta su expiración natural.
> 
> Para aplicaciones en producción que requieren revocación inmediata de sesiones, configure siempre `ClientSecret`.

---

## 🛡️ Uso con Gin Framework

El middleware de Gin está disponible como un subpaquete independiente para que quienes solo usen `net/http` no arrastren Gin como dependencia obligatoria:

```go
package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	peakauth "github.com/brunotarditi/peak-auth/sdk/go"
	peakauthgin "github.com/brunotarditi/peak-auth/sdk/go/gin"
)

func main() {
	client, _ := peakauth.New(peakauth.Config{
		IssuerURL: "https://auth.tuempresa.com",
		ClientID:  "mi-aplicacion",
		ClientSecret: "mi-client-secret", // Requerido para detección de revocación
		// ExpectedIssuer: "peak-auth", // Por defecto es "peak-auth" (coincide con el claim 'iss' del JWT)
	})

	r := gin.Default()

	// Ruta pública
	r.GET("/api/public", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Ruta protegida (cualquier usuario con token válido)
	// Con ClientSecret configurado, verifica automáticamente revocación
	r.GET("/api/profile", peakauthgin.Middleware(client), func(c *gin.Context) {
		claims, _ := peakauthgin.ClaimsFromContext(c)
		c.JSON(http.StatusOK, gin.H{
			"user":   claims.Username,
			"roles":  claims.Roles,
			"app_id": claims.AppID,
		})
	})

	// Ruta que requiere rol ADMIN
	r.GET("/api/admin", peakauthgin.Middleware(client, "ADMIN"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Acceso de administrador concedido"})
	})

	r.Run(":3000")
}
```

### Validación Offline vs Online

Por defecto, si el cliente tiene `ClientSecret` configurado, el middleware usa **validación online** (introspección) que verifica revocación inmediata. Si no tiene `ClientSecret`, usa **validación offline** (solo firma y expiración).

Para forzar un modo específico:

```go
// Forzar validación online (requiere ClientSecret)
useIntrospection := true
r.GET("/api/secure", peakauthgin.MiddlewareWithOptions(client, peakauthgin.MiddlewareOptions{
	UseIntrospection: &useIntrospection,
}), handler)

// Forzar validación offline (NO verifica revocación - usar solo si comprende las implicaciones)
useOffline := false
r.GET("/api/fast", peakauthgin.MiddlewareWithOptions(client, peakauthgin.MiddlewareOptions{
	UseIntrospection: &useOffline,
}), handler)
```

---

## 🌐 Uso con `net/http` Estándar

```go
package main

import (
	"fmt"
	"net/http"

	peakauth "github.com/brunotarditi/peak-auth/sdk/go"
)

func main() {
	client, _ := peakauth.New(peakauth.Config{
		IssuerURL: "https://auth.tuempresa.com",
		ClientID:  "mi-aplicacion",
		ClientSecret: "mi-client-secret", // Requerido para detección de revocación
	})

	mux := http.NewServeMux()

	adminHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := peakauth.ClaimsFromContext(r.Context())
		fmt.Fprintf(w, "Bienvenido, %s! Roles: %v", claims.Username, claims.Roles)
	})

	// Proteger con el middleware estándar
	// Con ClientSecret configurado, verifica automáticamente revocación
	mux.Handle("/api/admin", client.HTTPMiddleware("ADMIN")(adminHandler))

	http.ListenAndServe(":3000", mux)
}
```

---

## 🔐 Flujo OAuth 2.0 con PKCE

```go
// 1. Generar PKCE
pkce, err := peakauth.GeneratePKCE()
if err != nil {
    // manejar error
}

// 2. Construir la URL de login
loginURL, err := client.GetAuthorizationURL("state-csrf", pkce.CodeChallenge)
// Redirigir al usuario a loginURL...

// 3. En el callback de tu app, canjear código por tokens:
tokens, err := client.ExchangeCode(ctx, code, pkce.CodeVerifier)
if err != nil {
    // manejar error
}
// tokens.AccessToken contiene el JWT
```

---

## 📄 Licencia

MIT © Bruno Tarditi
